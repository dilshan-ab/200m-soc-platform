from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit
from ..db import get_db
from ..deps import Principal, require, scoped_get
from ..models import Alert, Case, CaseEvidence, CaseObservable, CaseTask, CaseTemplate, CaseTicket, utcnow
from ..services import cases as svc
from ..services import events
from .alerts import alert_out
from .common import iso, page_out, paginate

router = APIRouter(prefix="/api/cases", tags=["cases"])


def case_out(c: Case, detail: bool = False) -> dict[str, Any]:
    d = {"id": c.id, "number": c.number, "title": c.title, "severity": c.severity, "status": c.status, "owner_id": c.owner_id, "client_id": c.client_id, "template": c.template,
         "tlp": c.tlp, "created_at": iso(c.created_at), "updated_at": iso(c.updated_at), "resolve_due": iso(c.resolve_due), "sync_status": c.sync_status, "version": c.version}
    if detail:
        d.update({"description": c.description, "pap": c.pap, "resolution": c.resolution, "lessons": c.lessons, "external_id": c.external_id, "sync_error": c.sync_error,
                  "tasks": [{"id": t.id, "title": t.title, "description": t.description, "required": t.required, "status": t.status, "assignee_id": t.assignee_id, "position": t.position} for t in sorted(c.tasks, key=lambda t: t.position)],
                  "observables": [{"id": o.id, "type": o.type, "value": o.value, "verdict": o.verdict, "tlp": o.tlp, "enrichment": o.enrichment} for o in c.observables],
                  "timeline": [{"id": e.id, "at": iso(e.at), "actor": e.actor, "kind": e.kind, "message": e.message, "meta": e.meta} for e in c.timeline]})
    return d


@router.get("")
def list_cases(p: Principal = Depends(require("cases.read")), db: Session = Depends(get_db), status: list[str] = Query(default=[]), severity: str | None = None,
               client_id: str | None = None, mine: bool = False, q: str | None = Query(default=None, max_length=200), page: int = 1, limit: int = 50) -> dict[str, Any]:
    qy = select(Case).where(p.scope(Case.client_id))
    if status:
        qy = qy.where(Case.status.in_(status))
    if severity:
        qy = qy.where(Case.severity == severity)
    if client_id:
        qy = qy.where(Case.client_id == client_id)
    if mine:
        qy = qy.where(Case.owner_id == p.user.id)
    if q:
        qy = qy.where(Case.title.contains(q, autoescape=True))
    rows, total = paginate(db, qy.order_by(Case.created_at.desc(), Case.id), page, limit)
    return page_out([case_out(c) for c in rows], total, page, limit)


class CaseIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: str = Field(min_length=3, max_length=300)
    description: str = Field(default="", max_length=20000)
    severity: Literal["low", "medium", "high", "critical"] = "medium"
    client_id: str | None = None
    template: str | None = Field(default=None, max_length=80)
    tlp: Literal["WHITE", "GREEN", "AMBER", "RED"] = "AMBER"


@router.post("", status_code=201)
def create_case(body: CaseIn, p: Principal = Depends(require("cases.write")), db: Session = Depends(get_db)) -> dict[str, Any]:
    if p.client_ids is not None and not p.can_see_client(body.client_id):
        raise HTTPException(403, "client not permitted")
    from ..sla import active_policy, due_dates

    c = Case(number=svc.next_number(db), title=body.title, description=body.description, severity=body.severity, client_id=body.client_id, owner_id=p.user.id, tlp=body.tlp)
    c.ack_due, c.resolve_due = due_dates(active_policy(db), c.severity, utcnow())
    db.add(c)
    db.flush()
    try:
        if body.template:
            svc.apply_template(db, c, body.template)
    except ValueError as e:
        raise HTTPException(400, str(e)) from e
    svc.add_event(db, c, p.label, "created", "Case created manually")
    audit.record(db, "case.create", actor=p.label, actor_id=p.user.id, resource_type="case", resource_id=c.id, client_id=c.client_id, ip=p.ip)
    events.publish(db, "case.created", id=c.id, severity=c.severity, client_id=c.client_id)
    events.enqueue(db, "case.sync", {"case_id": c.id})
    return case_out(c, True)


@router.get("/templates")
def templates(p: Principal = Depends(require("cases.read")), db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    return [{"id": t.id, "name": t.name, "description": t.description, "severity": t.severity, "tasks": t.tasks} for t in db.execute(select(CaseTemplate).order_by(CaseTemplate.name)).scalars()]


@router.get("/{cid}")
def get_case(cid: str, p: Principal = Depends(require("cases.read")), db: Session = Depends(get_db)) -> dict[str, Any]:
    c = scoped_get(db, Case, cid, p)
    d = case_out(c, True)
    d["alerts"] = [alert_out(a) for a in db.execute(select(Alert).where(Alert.case_id == c.id)).scalars()]
    d["tickets"] = [{"id": t.id, "provider": t.provider, "external_id": t.external_id, "url": t.url, "status": t.status} for t in db.execute(select(CaseTicket).where(CaseTicket.case_id == c.id)).scalars()]
    d["evidence"] = [_evidence_out(e) for e in db.execute(select(CaseEvidence).where(CaseEvidence.case_id == c.id).order_by(CaseEvidence.collected_at.desc())).scalars()]
    return d


class CasePatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: int
    title: str | None = Field(default=None, min_length=3, max_length=300)
    description: str | None = Field(default=None, max_length=20000)
    severity: Literal["low", "medium", "high", "critical"] | None = None
    status: Literal["open", "in_progress", "resolved", "closed"] | None = None
    resolution: str = Field(default="", max_length=40)
    lessons: str | None = Field(default=None, max_length=20000)
    owner_id: str | None = None


@router.patch("/{cid}")
def patch_case(cid: str, body: CasePatch, p: Principal = Depends(require("cases.write")), db: Session = Depends(get_db)) -> dict[str, Any]:
    c = scoped_get(db, Case, cid, p)
    if c.version != body.version:
        raise HTTPException(409, "case was modified by someone else; reload")
    if c.status == "closed":
        raise HTTPException(409, "case is closed")
    if body.status in ("resolved", "closed") and not p.can("cases.close"):
        raise HTTPException(403, "missing capability cases.close")
    try:
        if body.title:
            c.title = body.title
        if body.description is not None:
            c.description = body.description
        if body.severity:
            c.severity = body.severity
        if body.lessons is not None:
            c.lessons = body.lessons
        if body.owner_id:
            c.owner_id = body.owner_id
        if body.status:
            svc.change_status(db, c, body.status, p.label, body.resolution)
        else:
            c.version += 1
    except ValueError as e:
        raise HTTPException(400, str(e)) from e
    audit.record(db, "case.update", actor=p.label, actor_id=p.user.id, resource_type="case", resource_id=c.id, client_id=c.client_id, ip=p.ip, meta={"status": body.status})
    events.enqueue(db, "case.sync", {"case_id": c.id})
    return case_out(c, True)


class NoteIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    text: str = Field(min_length=1, max_length=10000)


@router.post("/{cid}/notes", status_code=201)
def add_note(cid: str, body: NoteIn, p: Principal = Depends(require("cases.write")), db: Session = Depends(get_db)) -> dict[str, bool]:
    c = scoped_get(db, Case, cid, p)
    svc.add_event(db, c, p.label, "note", body.text)
    return {"ok": True}


class TaskIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: str = Field(min_length=1, max_length=300)
    description: str = Field(default="", max_length=5000)
    required: bool = False


@router.post("/{cid}/tasks", status_code=201)
def add_task(cid: str, body: TaskIn, p: Principal = Depends(require("cases.write")), db: Session = Depends(get_db)) -> dict[str, str]:
    c = scoped_get(db, Case, cid, p)
    t = CaseTask(title=body.title, description=body.description, required=body.required, position=len(c.tasks))
    c.tasks.append(t)
    db.flush()
    return {"id": t.id}


class TaskPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Literal["todo", "in_progress", "done"]


@router.patch("/{cid}/tasks/{tid}")
def patch_task(cid: str, tid: str, body: TaskPatch, p: Principal = Depends(require("cases.write")), db: Session = Depends(get_db)) -> dict[str, str]:
    c = scoped_get(db, Case, cid, p)
    t = next((x for x in c.tasks if x.id == tid), None)
    if t is None:
        raise HTTPException(404, "not found")
    t.status = body.status
    t.completed_at = utcnow() if body.status == "done" else None
    svc.add_event(db, c, p.label, "task", f"Task '{t.title}' -> {body.status}")
    return {"status": t.status}


class ObsIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: Literal["ip", "domain", "hash", "url", "user", "email", "host"]
    value: str = Field(min_length=1, max_length=500)
    tlp: Literal["WHITE", "GREEN", "AMBER", "RED"] = "AMBER"


@router.post("/{cid}/observables", status_code=201)
def add_observable(cid: str, body: ObsIn, p: Principal = Depends(require("cases.write")), db: Session = Depends(get_db)) -> dict[str, str]:
    c = scoped_get(db, Case, cid, p)
    if any(o.type == body.type and o.value == body.value for o in c.observables):
        raise HTTPException(409, "observable already exists")
    o = CaseObservable(type=body.type, value=body.value.strip(), tlp=body.tlp)
    c.observables.append(o)
    db.flush()
    return {"id": o.id}


def _evidence_out(e: CaseEvidence) -> dict[str, Any]:
    return {"id": e.id, "name": e.name, "type": e.type, "description": e.description, "hash_sha256": e.hash_sha256,
            "file_size": e.file_size, "tags": e.tags, "collected_by": e.collected_by,
            "collected_at": iso(e.collected_at), "chain_of_custody": e.chain_of_custody,
            "observable_id": e.observable_id, "alert_id": e.alert_id, "created_at": iso(e.created_at)}


class EvidenceIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=300)
    type: Literal["file", "screenshot", "pcap", "log", "artifact", "note"] = "file"
    description: str = Field(default="", max_length=5000)
    hash_sha256: str = Field(default="", max_length=64)
    file_size: int = Field(default=0, ge=0)
    tags: list[str] = Field(default_factory=list, max_length=20)
    observable_id: str | None = None
    alert_id: str | None = None


@router.get("/{cid}/evidence")
def list_evidence(cid: str, p: Principal = Depends(require("evidence.read")), db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    c = scoped_get(db, Case, cid, p)
    rows = db.execute(select(CaseEvidence).where(CaseEvidence.case_id == c.id).order_by(CaseEvidence.collected_at.desc())).scalars()
    return [_evidence_out(e) for e in rows]


@router.post("/{cid}/evidence", status_code=201)
def add_evidence(cid: str, body: EvidenceIn, p: Principal = Depends(require("evidence.write")), db: Session = Depends(get_db)) -> dict[str, Any]:
    c = scoped_get(db, Case, cid, p)
    now = utcnow()
    e = CaseEvidence(
        case_id=c.id, name=body.name, type=body.type, description=body.description,
        hash_sha256=body.hash_sha256, file_size=body.file_size, tags=body.tags,
        collected_by=p.label, collected_at=now, observable_id=body.observable_id, alert_id=body.alert_id,
        client_id=c.client_id,
        chain_of_custody=[{"actor": p.label, "action": "collected", "at": now.isoformat(), "note": "Evidence collected"}],
    )
    db.add(e)
    db.flush()
    svc.add_event(db, c, p.label, "evidence", f"Evidence added: {body.name}")
    audit.record(db, "evidence.add", actor=p.label, actor_id=p.user.id, resource_type="evidence", resource_id=e.id, client_id=c.client_id, ip=p.ip)
    return _evidence_out(e)


class CustodyIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: str = Field(min_length=1, max_length=50)
    note: str = Field(default="", max_length=1000)


@router.post("/{cid}/evidence/{eid}/custody", status_code=201)
def add_custody_entry(cid: str, eid: str, body: CustodyIn, p: Principal = Depends(require("evidence.write")), db: Session = Depends(get_db)) -> dict[str, Any]:
    c = scoped_get(db, Case, cid, p)
    e = db.get(CaseEvidence, eid)
    if e is None or e.case_id != c.id:
        raise HTTPException(404, "not found")
    chain = list(e.chain_of_custody or [])
    chain.append({"actor": p.label, "action": body.action, "at": utcnow().isoformat(), "note": body.note})
    e.chain_of_custody = chain
    db.flush()
    return _evidence_out(e)
