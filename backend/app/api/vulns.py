from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import audit
from ..db import get_db
from ..deps import Principal, require, scoped_get
from ..models import ControlException, ControlResult, Finding, utcnow
from .common import iso, page_out, paginate

router = APIRouter(prefix="/api", tags=["vulnerabilities", "compliance"])
FINDING_STATUSES = ["open", "in_progress", "remediated", "accepted_risk", "false_positive"]


def finding_out(f: Finding) -> dict[str, Any]:
    return {"id": f.id, "asset_id": f.asset_id, "vuln_id": f.vuln_id, "component": f.component, "title": f.title, "severity": f.severity, "cvss": f.cvss, "status": f.status,
            "sources": f.sources, "owner": f.owner, "deadline": iso(f.deadline), "client_id": f.client_id, "first_seen": iso(f.first_seen), "last_seen": iso(f.last_seen)}


@router.get("/vulnerabilities")
def list_findings(p: Principal = Depends(require("vulns.read")), db: Session = Depends(get_db), severity: list[str] = Query(default=[]), status: list[str] = Query(default=[]),
                  asset_id: str | None = None, client_id: str | None = None, q: str | None = Query(default=None, max_length=200), page: int = 1, limit: int = 50) -> dict[str, Any]:
    qy = select(Finding).where(p.scope(Finding.client_id))
    if severity:
        qy = qy.where(Finding.severity.in_(severity))
    if status:
        qy = qy.where(Finding.status.in_(status))
    if asset_id:
        qy = qy.where(Finding.asset_id == asset_id)
    if client_id:
        qy = qy.where(Finding.client_id == client_id)
    if q:
        qy = qy.where(Finding.vuln_id.icontains(q, autoescape=True) | Finding.title.icontains(q, autoescape=True))
    rows, total = paginate(db, qy.order_by(Finding.cvss.desc().nulls_last(), Finding.id), page, limit)
    return page_out([finding_out(f) for f in rows], total, page, limit)


@router.get("/vulnerabilities/summary")
def vuln_summary(p: Principal = Depends(require("vulns.read")), db: Session = Depends(get_db)) -> dict[str, Any]:
    rows = db.execute(select(Finding.severity, Finding.status, func.count()).where(p.scope(Finding.client_id)).group_by(Finding.severity, Finding.status)).all()
    out: dict[str, dict[str, int]] = {}
    for sev, st, n in rows:
        out.setdefault(sev, {})[st] = n
    overdue = db.execute(select(func.count()).where(p.scope(Finding.client_id), Finding.status.in_(["open", "in_progress"]), Finding.deadline < utcnow())).scalar_one()
    return {"by_severity": out, "overdue": overdue}


class FindingPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Literal["open", "in_progress", "remediated", "accepted_risk", "false_positive"] | None = None
    owner: str | None = Field(default=None, max_length=120)
    deadline: datetime | None = None
    note: str = Field(default="", max_length=1000)


@router.patch("/vulnerabilities/{fid}")
def patch_finding(fid: str, body: FindingPatch, p: Principal = Depends(require("vulns.write")), db: Session = Depends(get_db)) -> dict[str, Any]:
    f = scoped_get(db, Finding, fid, p)
    if body.status in ("accepted_risk", "false_positive") and len(body.note.strip()) < 5:
        raise HTTPException(400, "a justification note is required")
    for k, v in body.model_dump(exclude_unset=True, exclude={"note"}).items():
        setattr(f, k, v)
    audit.record(db, "finding.update", actor=p.label, actor_id=p.user.id, resource_type="finding", resource_id=f.id, client_id=f.client_id, ip=p.ip, meta={"status": body.status, "note": body.note})
    return finding_out(f)


# ------------------------------------------------------------------ compliance
@router.get("/compliance/summary")
def compliance_summary(p: Principal = Depends(require("compliance.read")), db: Session = Depends(get_db), client_id: str | None = None) -> list[dict[str, Any]]:
    qy = select(ControlResult.framework, ControlResult.status, func.count()).where(p.scope(ControlResult.client_id))
    if client_id:
        qy = qy.where(ControlResult.client_id == client_id)
    agg: dict[str, dict[str, int]] = {}
    for fw, st, n in db.execute(qy.group_by(ControlResult.framework, ControlResult.status)):
        agg.setdefault(fw, {})[st] = n
    return [{"framework": fw, "pass": v.get("pass", 0), "fail": v.get("fail", 0), "unknown": v.get("unknown", 0),
             "score": round(100 * v.get("pass", 0) / max(1, v.get("pass", 0) + v.get("fail", 0)), 1)} for fw, v in sorted(agg.items())]


@router.get("/compliance/controls")
def controls(p: Principal = Depends(require("compliance.read")), db: Session = Depends(get_db), framework: str | None = None, status: str | None = None, page: int = 1, limit: int = 100) -> dict[str, Any]:
    qy = select(ControlResult).where(p.scope(ControlResult.client_id))
    if framework:
        qy = qy.where(ControlResult.framework == framework)
    if status:
        qy = qy.where(ControlResult.status == status)
    rows, total = paginate(db, qy.order_by(ControlResult.framework, ControlResult.control_id), page, limit)
    return page_out([{"id": r.id, "framework": r.framework, "control_id": r.control_id, "title": r.title, "asset_id": r.asset_id, "status": r.status, "source": r.source, "checked_at": iso(r.checked_at)} for r in rows], total, page, limit)


class ExceptionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    framework: str = Field(max_length=30)
    control_id: str = Field(max_length=60)
    asset_id: str | None = None
    reason: str = Field(min_length=10, max_length=2000)
    expires_at: datetime


@router.post("/compliance/exceptions", status_code=201)
def create_exception(body: ExceptionIn, p: Principal = Depends(require("compliance.write")), db: Session = Depends(get_db)) -> dict[str, str]:
    if body.expires_at <= utcnow():
        raise HTTPException(400, "expiry must be in the future")
    e = ControlException(**body.model_dump(), approved_by=p.label)
    db.add(e)
    db.flush()
    audit.record(db, "compliance.exception", actor=p.label, actor_id=p.user.id, resource_type="control_exception", resource_id=e.id, ip=p.ip, meta={"control": body.control_id})
    return {"id": e.id}


@router.get("/compliance/exceptions")
def list_exceptions(p: Principal = Depends(require("compliance.read")), db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    return [{"id": e.id, "framework": e.framework, "control_id": e.control_id, "asset_id": e.asset_id, "reason": e.reason, "approved_by": e.approved_by, "expires_at": iso(e.expires_at)} for e in db.execute(select(ControlException).order_by(ControlException.created_at.desc())).scalars()]
