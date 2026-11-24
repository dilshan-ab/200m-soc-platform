"""Sigma rule library: import, browse, and retire detection rules; feeds the MITRE coverage view."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit
from ..db import get_db
from ..deps import Principal, require
from ..models import SigmaRule
from ..services import sigma as svc
from .common import iso

router = APIRouter(prefix="/api/sigma", tags=["sigma"])


def rule_out(r: SigmaRule, detail: bool = False) -> dict[str, Any]:
    d: dict[str, Any] = {
        "id": r.id, "sigma_id": r.sigma_id, "title": r.title, "status": r.status, "level": r.level,
        "log_source": r.log_source, "technique_ids": r.technique_ids, "enabled": r.enabled,
        "created_at": iso(r.created_at), "updated_at": iso(r.updated_at),
    }
    if detail:
        d.update({"description": r.description, "tags": r.tags, "references": r.references, "false_positives": r.false_positives, "raw_yaml": r.raw_yaml})
    return d


class ImportIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    yaml: str = Field(min_length=10, max_length=200_000)


@router.post("/rules/import", status_code=201)
def import_rules(body: ImportIn, p: Principal = Depends(require("detections.write")), db: Session = Depends(get_db)) -> dict[str, Any]:
    result = svc.parse_yaml(body.yaml)
    imported: list[str] = []
    duplicates: list[str] = []
    for rule in result.parsed:
        if rule.sigma_id and db.execute(select(SigmaRule.id).where(SigmaRule.sigma_id == rule.sigma_id)).first():
            duplicates.append(rule.title)
            continue
        row = SigmaRule(
            sigma_id=rule.sigma_id, title=rule.title, description=rule.description, status=rule.status, level=rule.level,
            log_source=rule.log_source, technique_ids=rule.technique_ids, tags=rule.tags, references=rule.references,
            false_positives=rule.false_positives, raw_yaml=rule.raw_yaml, imported_by=p.user.id,
        )
        db.add(row)
        db.flush()
        imported.append(row.id)
    if imported:
        audit.record(db, "sigma.import", actor=p.label, actor_id=p.user.id, resource_type="sigma_rule", resource_id=",".join(imported[:20]), ip=p.ip, meta={"count": len(imported)})
    return {"imported": len(imported), "duplicates": duplicates, "skipped": result.skipped}


@router.get("/rules")
def list_rules(
    p: Principal = Depends(require("detections.read")), db: Session = Depends(get_db),
    status: str | None = None, level: str | None = None, technique_id: str | None = None,
    enabled: bool | None = None, q: str | None = Query(default=None, max_length=200),
    page: int = 1, limit: int = 50,
) -> dict[str, Any]:
    from .common import page_out, paginate

    qy = select(SigmaRule)
    if status:
        qy = qy.where(SigmaRule.status == status)
    if level:
        qy = qy.where(SigmaRule.level == level)
    if enabled is not None:
        qy = qy.where(SigmaRule.enabled.is_(enabled))
    if q:
        qy = qy.where(SigmaRule.title.icontains(q, autoescape=True) | SigmaRule.description.icontains(q, autoescape=True))
    qy = qy.order_by(SigmaRule.created_at.desc())
    rows, total = paginate(db, qy, page, limit)
    if technique_id:
        rows = [r for r in rows if technique_id in (r.technique_ids or [])]
        total = len(rows)
    return page_out([rule_out(r) for r in rows], total, page, limit)


@router.get("/rules/{rid}")
def get_rule(rid: str, p: Principal = Depends(require("detections.read")), db: Session = Depends(get_db)) -> dict[str, Any]:
    r = db.get(SigmaRule, rid)
    if r is None:
        raise HTTPException(404, "not found")
    return rule_out(r, detail=True)


class RuleUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool | None = None
    status: str | None = Field(default=None, pattern="^(stable|test|experimental|deprecated|unsupported)$")


@router.patch("/rules/{rid}")
def update_rule(rid: str, body: RuleUpdate, p: Principal = Depends(require("detections.write")), db: Session = Depends(get_db)) -> dict[str, Any]:
    r = db.get(SigmaRule, rid)
    if r is None:
        raise HTTPException(404, "not found")
    if body.enabled is not None:
        r.enabled = body.enabled
    if body.status is not None:
        r.status = body.status
    db.flush()
    audit.record(db, "sigma.update", actor=p.label, actor_id=p.user.id, resource_type="sigma_rule", resource_id=r.id, ip=p.ip, meta={"enabled": r.enabled, "status": r.status})
    return rule_out(r, detail=True)


@router.delete("/rules/{rid}", status_code=204)
def delete_rule(rid: str, p: Principal = Depends(require("detections.write")), db: Session = Depends(get_db)) -> None:
    r = db.get(SigmaRule, rid)
    if r is None:
        raise HTTPException(404, "not found")
    audit.record(db, "sigma.delete", actor=p.label, actor_id=p.user.id, resource_type="sigma_rule", resource_id=r.id, ip=p.ip, meta={"title": r.title})
    db.delete(r)
