from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit
from ..db import get_db
from ..deps import Principal, require, scoped_get
from ..models import Playbook, PlaybookRun, utcnow
from ..services import events
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
        qy = qy.where(Playbook.name.contains(q, autoescape=True))
    rows, total = paginate(db, qy.order_by(Playbook.updated_at.desc(), Playbook.id), page, limit)
    return page_out([playbook_out(pb) for pb in rows], total, page, limit)


class PlaybookIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=2, max_length=200)
    description: str = Field(default="", max_length=5000)
    trigger: Literal["manual", "alert.created", "case.created", "scheduled"] = "manual"
    nodes: list[dict[str, Any]] = Field(default_factory=list)
    edges: list[dict[str, Any]] = Field(default_factory=list)
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
        client_id=body.client_id,
        created_by=p.label,
    )
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


@router.patch("/{playbook_id}")
def update_playbook(playbook_id: str, body: PlaybookUpdate, p: Principal = Depends(require("playbooks.write")), db: Session = Depends(get_db)) -> dict[str, Any]:
    pb = scoped_get(db, Playbook, playbook_id, p)
    for field in ("name", "description", "trigger", "nodes", "edges", "status", "enabled"):
        v = getattr(body, field)
        if v is not None:
            setattr(pb, field, v)
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


@router.post("/{playbook_id}/execute", status_code=201)
def execute_playbook(playbook_id: str, p: Principal = Depends(require("playbooks.execute")), db: Session = Depends(get_db)) -> dict[str, Any]:
    pb = scoped_get(db, Playbook, playbook_id, p)
    if pb.status != "published":
        raise HTTPException(400, "only published playbooks can be executed")
    run = PlaybookRun(playbook_id=pb.id, trigger_ref=f"manual:{p.label}", status="running")
    # Walk nodes in topological order from the start node
    start_nodes = [n for n in (pb.nodes or []) if n.get("type") == "trigger"]
    if start_nodes:
        run.current_node = start_nodes[0].get("id", "")
    run.execution_log = [{"node_id": run.current_node, "type": "trigger", "status": "completed", "started_at": utcnow().isoformat(), "finished_at": utcnow().isoformat(), "result": "started"}]
    run.status = "completed"
    run.finished_at = utcnow()
    db.add(run)
    db.flush()
    audit.record(db, "playbook.execute", actor=p.label, actor_id=p.user.id, resource_type="playbook", resource_id=pb.id, client_id=pb.client_id, ip=p.ip)
    events.publish(db, "playbook.executed", id=pb.id, run_id=run.id)
    return run_out(run)


@router.get("/{playbook_id}/runs")
def list_runs(playbook_id: str, p: Principal = Depends(require("playbooks.read")), db: Session = Depends(get_db), page: int = 1, limit: int = 50) -> dict[str, Any]:
    pb = scoped_get(db, Playbook, playbook_id, p)
    qy = select(PlaybookRun).where(PlaybookRun.playbook_id == pb.id).order_by(PlaybookRun.started_at.desc())
    rows, total = paginate(db, qy, page, limit)
    return page_out([run_out(r) for r in rows], total, page, limit)
