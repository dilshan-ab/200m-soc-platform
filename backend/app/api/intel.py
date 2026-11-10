from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit
from ..config import get_settings
from ..connectors.base import get_connector_cls
from ..db import get_db
from ..deps import Principal, require, scoped_get
from ..models import Alert, Case, EnrichmentJob, Hunt, Tool, utcnow
from ..policy import ACTIONS
from ..ratelimit import limiter
from ..services import cases as cases_svc
from ..services import hunting
from ..services import intel as svc
from ..services import response as resp
from .common import iso

router = APIRouter(prefix="/api", tags=["intel"])


def job_out(j: EnrichmentJob) -> dict[str, Any]:
    return {"id": j.id, "indicator": j.indicator, "type": j.indicator_type, "status": j.status, "verdict": j.verdict, "results": j.results, "tlp": j.tlp, "created_at": iso(j.created_at), "alert_id": j.alert_id, "case_id": j.case_id}


class EnrichIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    indicator: str = Field(min_length=3, max_length=500)
    alert_id: str | None = None
    case_id: str | None = None


@router.post("/intel/enrich", status_code=202)
def enrich(body: EnrichIn, p: Principal = Depends(require("intel.enrich")), db: Session = Depends(get_db)) -> dict[str, Any]:
    if not limiter.allow(f"enrich:{p.user.id}", 30):
        raise HTTPException(429, "enrichment rate limit")
    try:
        itype = svc.detect_type(body.indicator)
    except ValueError as e:
        raise HTTPException(400, str(e)) from e
    client_id = None
    if body.alert_id:
        a = db.get(Alert, body.alert_id)
        if a is None or not p.can_see_client(a.client_id):
            raise HTTPException(404, "not found")
        client_id = a.client_id
    if body.case_id:
        c = db.get(Case, body.case_id)
        if c is None or not p.can_see_client(c.client_id):
            raise HTTPException(404, "not found")
        client_id = c.client_id
    if client_id is None and p.client_ids is not None:
        raise HTTPException(400, "alert_id or case_id is required for scoped users")
    j = svc.queue_enrichment(db, body.indicator, itype, p.user.id, alert_id=body.alert_id, case_id=body.case_id, client_id=client_id)
    audit.record(db, "intel.enrich", actor=p.label, actor_id=p.user.id, resource_type="enrichment", resource_id=j.id, client_id=client_id, ip=p.ip, meta={"type": itype})
    return job_out(j)


@router.get("/intel/jobs")
def jobs(p: Principal = Depends(require("intel.read")), db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    q = select(EnrichmentJob).where(p.scope(EnrichmentJob.client_id)).order_by(EnrichmentJob.created_at.desc()).limit(100)
    return [job_out(j) for j in db.execute(q).scalars()]


@router.get("/intel/jobs/{jid}")
def job(jid: str, p: Principal = Depends(require("intel.read")), db: Session = Depends(get_db)) -> dict[str, Any]:
    j = db.get(EnrichmentJob, jid)
    if j is None or not p.can_see_client(j.client_id):
        raise HTTPException(404, "not found")
    return job_out(j)


# ---------------------------------------------------------------- threat hunting workbench
# Two kinds of hunt share one record: "search" runs a hypothesis-driven query over alerts
# already in the platform (no connected tooling required); "collection" is the original
# approval-gated Velociraptor artifact pull.
VERDICTS = ("true_positive", "false_positive", "inconclusive")


def hunt_out(db: Session, h: Hunt, detail: bool = False) -> dict[str, Any]:
    status = h.status
    if h.kind == "collection" and h.request_id:
        from ..models import ActionRequest

        r = db.get(ActionRequest, h.request_id)
        if r is not None:
            status = r.status
    d: dict[str, Any] = {
        "id": h.id, "name": h.name, "kind": h.kind, "status": status, "hypothesis": h.hypothesis, "technique_ids": h.technique_ids,
        "query": h.query, "match_count": h.match_count, "verdict": h.verdict, "case_id": h.case_id, "requester_id": h.requester_id,
        "artifact": h.artifact, "targets": h.targets, "request_id": h.request_id, "created_at": iso(h.created_at), "concluded_at": iso(h.concluded_at),
    }
    if detail:
        d.update({"conclusion_note": h.conclusion_note, "results": h.results})
    return d


class HuntIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=3, max_length=200)
    artifact: str = Field(min_length=3, max_length=120)
    targets: list[str] = Field(min_length=1, max_length=50)
    case_id: str | None = None
    reason: str = Field(min_length=5, max_length=1000)


@router.post("/hunts", status_code=201)
def create_hunt(body: HuntIn, p: Principal = Depends(require("hunts.request")), db: Session = Depends(get_db)) -> dict[str, Any]:
    try:
        req = resp.create_request(db, requester=p.user, action_key="collect_artifact", targets=body.targets, params={"artifact": body.artifact}, reason=body.reason, case_id=body.case_id, scope=p)
    except resp.ResponseError as e:
        raise HTTPException(e.status, str(e)) from e
    h = Hunt(name=body.name, kind="collection", artifact=body.artifact, targets=req.targets, requester_id=p.user.id, request_id=req.id, case_id=body.case_id, client_id=req.client_id, status=req.status)
    db.add(h)
    db.flush()
    return {"id": h.id, "request_id": req.id, "status": req.status}


class HuntQuery(BaseModel):
    model_config = ConfigDict(extra="forbid")
    severities: list[str] = Field(default_factory=list, max_length=5)
    host: str = Field(default="", max_length=255)
    rule_id: str = Field(default="", max_length=80)
    q: str = Field(default="", max_length=200)
    days: int = Field(default=30, ge=1, le=365)
    technique_ids: list[str] = Field(default_factory=list, max_length=20)


class SearchHuntIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=3, max_length=200)
    hypothesis: str = Field(default="", max_length=2000)
    query: HuntQuery
    case_id: str | None = None


@router.post("/hunts/search", status_code=201)
def create_search_hunt(body: SearchHuntIn, p: Principal = Depends(require("hunts.request")), db: Session = Depends(get_db)) -> dict[str, Any]:
    if body.case_id:
        scoped_get(db, Case, body.case_id, p)
    client_id = next(iter(p.client_ids)) if p.client_ids and len(p.client_ids) == 1 else None
    h = Hunt(
        name=body.name, kind="search", hypothesis=body.hypothesis, technique_ids=body.query.technique_ids,
        query=body.query.model_dump(), case_id=body.case_id, requester_id=p.user.id, client_id=client_id, status="draft",
    )
    hunting.run_hunt(db, p, h)
    db.add(h)
    db.flush()
    audit.record(db, "hunt.create", actor=p.label, actor_id=p.user.id, resource_type="hunt", resource_id=h.id, ip=p.ip, meta={"matches": h.match_count})
    return hunt_out(db, h, detail=True)


@router.get("/hunts")
def list_hunts(p: Principal = Depends(require("hunts.read")), db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    rows = db.execute(select(Hunt).where(p.scope(Hunt.client_id)).order_by(Hunt.created_at.desc()).limit(100)).scalars()
    return [hunt_out(db, h) for h in rows]


@router.get("/hunts/artifacts")
def artifacts(p: Principal = Depends(require("hunts.read")), db: Session = Depends(get_db)) -> dict[str, Any]:
    allowed: set[str] = set()
    for t in db.execute(select(Tool).where(Tool.type == "velociraptor", Tool.enabled.is_(True))).scalars():
        allowed |= set(t.config.get("allowed_artifacts") or [])
    return {"artifacts": sorted(allowed), "spec": {k: ACTIONS["collect_artifact"].__dict__[k] for k in ("label", "risk")}, "env": get_settings().environment}


@router.get("/hunts/{hid}")
def get_hunt(hid: str, p: Principal = Depends(require("hunts.read")), db: Session = Depends(get_db)) -> dict[str, Any]:
    return hunt_out(db, scoped_get(db, Hunt, hid, p), detail=True)


@router.post("/hunts/{hid}/run")
def rerun_hunt(hid: str, p: Principal = Depends(require("hunts.request")), db: Session = Depends(get_db)) -> dict[str, Any]:
    h = scoped_get(db, Hunt, hid, p)
    if h.kind != "search":
        raise HTTPException(400, "only search hunts can be re-run")
    if h.status == "concluded":
        raise HTTPException(409, "hunt is concluded; reopen is not supported")
    hunting.run_hunt(db, p, h)
    db.flush()
    audit.record(db, "hunt.run", actor=p.label, actor_id=p.user.id, resource_type="hunt", resource_id=h.id, ip=p.ip, meta={"matches": h.match_count})
    return hunt_out(db, h, detail=True)


class ConcludeIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    verdict: str = Field(pattern="^(true_positive|false_positive|inconclusive)$")
    note: str = Field(default="", max_length=2000)


@router.post("/hunts/{hid}/conclude")
def conclude_hunt(hid: str, body: ConcludeIn, p: Principal = Depends(require("hunts.request")), db: Session = Depends(get_db)) -> dict[str, Any]:
    h = scoped_get(db, Hunt, hid, p)
    if h.status == "concluded":
        raise HTTPException(409, "already concluded")
    h.status, h.verdict, h.conclusion_note, h.concluded_at = "concluded", body.verdict, body.note, utcnow()
    db.flush()
    audit.record(db, "hunt.conclude", actor=p.label, actor_id=p.user.id, resource_type="hunt", resource_id=h.id, ip=p.ip, meta={"verdict": body.verdict})
    return hunt_out(db, h, detail=True)


class EscalateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    alert_ids: list[str] | None = None  # defaults to every alert currently in the hunt's snapshot
    title: str | None = None


@router.post("/hunts/{hid}/escalate", status_code=201)
def escalate_hunt(hid: str, body: EscalateIn, p: Principal = Depends(require("cases.write")), db: Session = Depends(get_db)) -> dict[str, Any]:
    h = scoped_get(db, Hunt, hid, p)
    wanted = set(body.alert_ids) if body.alert_ids else {r["id"] for r in h.results}
    if not wanted:
        raise HTTPException(400, "no matched alerts to escalate")
    alerts = []
    for aid in wanted:
        a = db.get(Alert, aid)
        if a is None or not p.can_see_client(a.client_id) or a.case_id:
            continue
        alerts.append(a)
    if not alerts:
        raise HTTPException(409, "none of the selected alerts can be escalated (already cased, or no longer visible)")
    try:
        c = cases_svc.create_case_from_alerts(db, alerts, actor=p.label, title=body.title or h.name, owner_id=p.user.id)
    except ValueError as e:
        raise HTTPException(400, str(e)) from e
    h.case_id = c.id
    audit.record(db, "hunt.escalate", actor=p.label, actor_id=p.user.id, resource_type="hunt", resource_id=h.id, client_id=c.client_id, ip=p.ip, meta={"case_id": c.id, "alerts": len(alerts)})
    return {"id": c.id, "number": c.number}


@router.get("/intel/sources")
def sources(p: Principal = Depends(require("intel.read")), db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    out = []
    for t in db.execute(select(Tool).where(Tool.type.in_(["misp", "cortex"]))).scalars():
        out.append({"id": t.id, "name": t.name, "type": t.type, "enabled": t.enabled, "capabilities": get_connector_cls(t.type).manifest.capabilities})
    return out
