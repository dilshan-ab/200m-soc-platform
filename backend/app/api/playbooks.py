from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit
from ..db import get_db
from ..deps import Principal, require, require_admin_step_up, scoped_get
from ..models import Alert, Case, Playbook, PlaybookRun, utcnow
from ..services import events, playbooks_engine
from .common import iso, page_out, paginate

router = APIRouter(prefix="/api/playbooks", tags=["playbooks"])


def playbook_out(pb: Playbook, detail: bool = False) -> dict[str, Any]:
    d = {
        "id": pb.id,
        "name": pb.name,
        "description": pb.description,
        "trigger": pb.trigger,
        "status": pb.status,
        "enabled": pb.enabled,
        "version": pb.version,
        "schedule_interval_minutes": pb.schedule_interval_minutes,
        "next_run_at": iso(pb.next_run_at),
        "last_run_at": iso(pb.last_run_at),
        "client_id": pb.client_id,
        "created_by": pb.created_by,
        "created_at": iso(pb.created_at),
        "updated_at": iso(pb.updated_at),
    }
    if detail:
        d["nodes"] = pb.nodes or []
        d["edges"] = pb.edges or []
        d["runs"] = [run_out(r) for r in sorted(pb.runs, key=lambda r: r.started_at, reverse=True)[:20]]
    return d


def run_out(r: PlaybookRun) -> dict[str, Any]:
    return {
        "id": r.id,
        "playbook_id": r.playbook_id,
        "trigger_ref": r.trigger_ref,
        "status": r.status,
        "current_node": r.current_node,
        "execution_log": r.execution_log or [],
        "error": r.error,
        "started_at": iso(r.started_at),
        "finished_at": iso(r.finished_at),
    }


@router.get("")
def list_playbooks(
    p: Principal = Depends(require("playbooks.read")),
    db: Session = Depends(get_db),
    status: str | None = None,
    q: str | None = Query(default=None, max_length=200),
    page: int = 1,
    limit: int = 50,
) -> dict[str, Any]:
    qy = select(Playbook).where(p.scope(Playbook.client_id))
    if status:
        qy = qy.where(Playbook.status == status)
    if q:
        qy = qy.where(Playbook.name.icontains(q, autoescape=True))
    rows, total = paginate(db, qy.order_by(Playbook.updated_at.desc(), Playbook.id), page, limit)
    return page_out([playbook_out(pb) for pb in rows], total, page, limit)


class PlaybookIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=2, max_length=200)
    description: str = Field(default="", max_length=5000)
    trigger: Literal["manual", "alert.created", "case.created", "scheduled"] = "manual"
    nodes: list[dict[str, Any]] = Field(default_factory=list)
    edges: list[dict[str, Any]] = Field(default_factory=list)
    schedule_interval_minutes: int | None = Field(default=None, ge=1, le=100000)
    client_id: str | None = None


@router.post("", status_code=201)
def create_playbook(body: PlaybookIn, p: Principal = Depends(require("playbooks.write")), db: Session = Depends(get_db)) -> dict[str, Any]:
    if p.client_ids is not None and not p.can_see_client(body.client_id):
        raise HTTPException(403, "client not permitted")
    pb = Playbook(
        name=body.name,
        description=body.description,
        trigger=body.trigger,
        nodes=body.nodes,
        edges=body.edges,
        schedule_interval_minutes=body.schedule_interval_minutes,
        client_id=body.client_id,
        created_by=p.label,
    )
    try:
        playbooks_engine.sync_schedule(pb, reset=True)
    except playbooks_engine.EngineError as e:
        raise HTTPException(400, str(e)) from e
    db.add(pb)
    db.flush()
    audit.record(db, "playbook.create", actor=p.label, actor_id=p.user.id, resource_type="playbook", resource_id=pb.id, client_id=pb.client_id, ip=p.ip)
    events.publish(db, "playbook.created", id=pb.id)
    return playbook_out(pb, True)


@router.get("/{playbook_id}")
def get_playbook(playbook_id: str, p: Principal = Depends(require("playbooks.read")), db: Session = Depends(get_db)) -> dict[str, Any]:
    pb = scoped_get(db, Playbook, playbook_id, p)
    return playbook_out(pb, True)


class PlaybookUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str | None = Field(default=None, min_length=2, max_length=200)
    description: str | None = Field(default=None, max_length=5000)
    trigger: Literal["manual", "alert.created", "case.created", "scheduled"] | None = None
    nodes: list[dict[str, Any]] | None = None
    edges: list[dict[str, Any]] | None = None
    status: Literal["draft", "published", "archived"] | None = None
    enabled: bool | None = None
    schedule_interval_minutes: int | None = Field(default=None, ge=1, le=100000)


@router.patch("/{playbook_id}")
def update_playbook(playbook_id: str, body: PlaybookUpdate, p: Principal = Depends(require("playbooks.write")), db: Session = Depends(get_db)) -> dict[str, Any]:
    pb = scoped_get(db, Playbook, playbook_id, p)
    if body.status == "published":
        try:
            playbooks_engine.validate_graph(body.nodes if body.nodes is not None else pb.nodes, body.edges if body.edges is not None else pb.edges)
        except playbooks_engine.EngineError as e:
            raise HTTPException(400, str(e)) from e
    old_sched = (pb.trigger, pb.schedule_interval_minutes, pb.enabled)
    for field in ("name", "description", "trigger", "nodes", "edges", "status", "enabled", "schedule_interval_minutes"):
        v = getattr(body, field)
        if v is not None:
            setattr(pb, field, v)
    try:
        # restart the countdown when the schedule or enabled state changes, so re-enabling never fires immediately
        playbooks_engine.sync_schedule(pb, reset=(pb.trigger, pb.schedule_interval_minutes, pb.enabled) != old_sched)
    except playbooks_engine.EngineError as e:
        raise HTTPException(400, str(e)) from e
    if body.nodes is not None or body.edges is not None:
        pb.version += 1
    pb.updated_at = utcnow()
    audit.record(db, "playbook.update", actor=p.label, actor_id=p.user.id, resource_type="playbook", resource_id=pb.id, client_id=pb.client_id, ip=p.ip)
    return playbook_out(pb, True)


@router.delete("/{playbook_id}", status_code=204)
def delete_playbook(playbook_id: str, p: Principal = Depends(require("playbooks.write")), db: Session = Depends(get_db)) -> None:
    pb = scoped_get(db, Playbook, playbook_id, p)
    audit.record(db, "playbook.delete", actor=p.label, actor_id=p.user.id, resource_type="playbook", resource_id=pb.id, client_id=pb.client_id, ip=p.ip)
    db.delete(pb)


class ExecuteIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    alert_id: str | None = None
    case_id: str | None = None


@router.post("/{playbook_id}/execute", status_code=201)
def execute_playbook(playbook_id: str, body: ExecuteIn = ExecuteIn(), p: Principal = Depends(require("playbooks.execute")), db: Session = Depends(get_db)) -> dict[str, Any]:
    pb = scoped_get(db, Playbook, playbook_id, p)
    if pb.status != "published":
        raise HTTPException(400, "only published playbooks can be executed")
    alert = db.get(Alert, body.alert_id) if body.alert_id else None
    case = db.get(Case, body.case_id) if body.case_id else None
    if (body.alert_id and alert is None) or (body.case_id and case is None):
        raise HTTPException(404, "alert or case not found")
    if alert is not None and not p.can_see_client(alert.client_id):
        raise HTTPException(404, "not found")
    if case is not None and not p.can_see_client(case.client_id):
        raise HTTPException(404, "not found")
    trigger_ref = f"alert:{alert.id}" if alert else (f"case:{case.id}" if case else f"manual:{p.label}")
    run = playbooks_engine.start_run(db, pb, trigger_ref, alert=alert, case=case)
    audit.record(db, "playbook.execute", actor=p.label, actor_id=p.user.id, resource_type="playbook", resource_id=pb.id, client_id=pb.client_id, ip=p.ip, meta={"run_id": run.id})
    events.publish(db, "playbook.executed", id=pb.id, run_id=run.id)
    return run_out(run)


class ResumeIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    approved: bool
    reason: str = Field(min_length=3, max_length=1000)


@router.post("/{playbook_id}/runs/{run_id}/resume")
def resume_run(playbook_id: str, run_id: str, body: ResumeIn, p: Principal = Depends(require_admin_step_up("playbooks.execute")), db: Session = Depends(get_db)) -> dict[str, Any]:
    pb = scoped_get(db, Playbook, playbook_id, p)
    run = db.get(PlaybookRun, run_id)
    if run is None or run.playbook_id != pb.id:
        raise HTTPException(404, "run not found")
    try:
        playbooks_engine.resume_run(db, run, approved=body.approved, actor_label=p.label)
    except playbooks_engine.EngineError as e:
        raise HTTPException(409, str(e)) from e
    audit.record(db, "playbook.resume", actor=p.label, actor_id=p.user.id, resource_type="playbook_run", resource_id=run.id, client_id=pb.client_id, ip=p.ip, meta={"approved": body.approved, "reason": body.reason})
    events.publish(db, "playbook.executed", id=pb.id, run_id=run.id)
    return run_out(run)


@router.get("/{playbook_id}/runs")
def list_runs(playbook_id: str, p: Principal = Depends(require("playbooks.read")), db: Session = Depends(get_db), page: int = 1, limit: int = 50) -> dict[str, Any]:
    pb = scoped_get(db, Playbook, playbook_id, p)
    qy = select(PlaybookRun).where(PlaybookRun.playbook_id == pb.id).order_by(PlaybookRun.started_at.desc())
    rows, total = paginate(db, qy, page, limit)
    return page_out([run_out(r) for r in rows], total, page, limit)
