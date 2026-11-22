"""Enrichment engine API: custom rules, local IOC lookup, reputation scoring."""
from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit
from ..db import get_db
from ..deps import Principal, require
from ..models import EnrichmentRule, utcnow
from ..services import enrichment_engine as engine
from .common import iso

router = APIRouter(prefix="/api/enrichment", tags=["enrichment"])


def rule_out(r: EnrichmentRule) -> dict[str, Any]:
    return {
        "id": r.id, "name": r.name, "description": r.description, "rule_type": r.rule_type,
        "indicator_type": r.indicator_type, "pattern": r.pattern, "verdict": r.verdict,
        "confidence": r.confidence, "tags": r.tags, "enabled": r.enabled,
        "hit_count": r.hit_count, "last_hit_at": iso(r.last_hit_at), "created_at": iso(r.created_at),
    }


@router.get("/rules")
def list_rules(p: Principal = Depends(require("intel.read")), db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    rows = db.execute(select(EnrichmentRule).order_by(EnrichmentRule.created_at.desc())).scalars()
    return [rule_out(r) for r in rows]


class RuleIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=2, max_length=200)
    description: str = Field(default="", max_length=2000)
    rule_type: Literal["cidr", "domain_pattern", "hash_list", "regex"]
    indicator_type: Literal["ip", "domain", "hash", "url", "any"]
    pattern: str = Field(min_length=1, max_length=10000)
    verdict: Literal["malicious", "suspicious", "benign"] = "suspicious"
    confidence: int = Field(default=70, ge=0, le=100)
    tags: list[str] = Field(default_factory=list, max_length=20)


@router.post("/rules", status_code=201)
def create_rule(body: RuleIn, p: Principal = Depends(require("intel.enrich")), db: Session = Depends(get_db)) -> dict[str, Any]:
    r = EnrichmentRule(
        name=body.name, description=body.description, rule_type=body.rule_type,
        indicator_type=body.indicator_type, pattern=body.pattern, verdict=body.verdict,
        confidence=body.confidence, tags=body.tags, created_by=p.user.id,
    )
    db.add(r)
    db.flush()
    audit.record(db, "enrichment.rule.create", actor=p.label, actor_id=p.user.id, resource_type="enrichment_rule", resource_id=r.id, ip=p.ip, meta={"name": r.name})
    return rule_out(r)


class RulePatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str | None = Field(default=None, min_length=2, max_length=200)
    description: str | None = None
    pattern: str | None = Field(default=None, min_length=1, max_length=10000)
    verdict: Literal["malicious", "suspicious", "benign"] | None = None
    confidence: int | None = Field(default=None, ge=0, le=100)
    tags: list[str] | None = None
    enabled: bool | None = None


@router.patch("/rules/{rid}")
def patch_rule(rid: str, body: RulePatch, p: Principal = Depends(require("intel.enrich")), db: Session = Depends(get_db)) -> dict[str, Any]:
    r = db.get(EnrichmentRule, rid)
    if r is None:
        raise HTTPException(404, "not found")
    for field in ("name", "description", "pattern", "verdict", "confidence", "tags", "enabled"):
        v = getattr(body, field)
        if v is not None:
            setattr(r, field, v)
    audit.record(db, "enrichment.rule.update", actor=p.label, actor_id=p.user.id, resource_type="enrichment_rule", resource_id=r.id, ip=p.ip)
    return rule_out(r)


@router.delete("/rules/{rid}", status_code=204)
def delete_rule(rid: str, p: Principal = Depends(require("intel.enrich")), db: Session = Depends(get_db)) -> None:
    r = db.get(EnrichmentRule, rid)
    if r is None:
        raise HTTPException(404, "not found")
    audit.record(db, "enrichment.rule.delete", actor=p.label, actor_id=p.user.id, resource_type="enrichment_rule", resource_id=r.id, ip=p.ip, meta={"name": r.name})
    db.delete(r)


class LookupIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    indicator: str = Field(min_length=1, max_length=500)
    type: Literal["ip", "domain", "hash", "url", "email"]


@router.post("/lookup")
def lookup(body: LookupIn, p: Principal = Depends(require("intel.read")), db: Session = Depends(get_db)) -> dict[str, Any]:
    local = engine.enrich_local(db, body.indicator.strip(), body.type)
    rep = engine.compute_reputation(
        local.get("local_intel", {}),
        local.get("rule_matches", []),
        {},
    )
    return {
        "indicator": body.indicator.strip(),
        "type": body.type,
        "local_intel": local["local_intel"],
        "rule_matches": local["rule_matches"],
        "tags": local["tags"],
        "reputation": rep,
    }


class BulkLookupIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    indicators: list[dict[str, str]] = Field(min_length=1, max_length=100)


@router.post("/bulk-lookup")
def bulk_lookup(body: BulkLookupIn, p: Principal = Depends(require("intel.read")), db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    return engine.bulk_lookup(db, body.indicators)


@router.get("/stats")
def enrichment_stats(p: Principal = Depends(require("intel.read")), db: Session = Depends(get_db)) -> dict[str, Any]:
    from sqlalchemy import func
    from ..models import ThreatIndicator, EnrichmentJob

    total_indicators = db.execute(select(func.count()).select_from(ThreatIndicator).where(ThreatIndicator.revoked.is_(False))).scalar_one()
    by_verdict = dict(db.execute(select(ThreatIndicator.verdict, func.count()).where(ThreatIndicator.revoked.is_(False)).group_by(ThreatIndicator.verdict)).all())
    by_source = dict(db.execute(select(func.substr(ThreatIndicator.source, 1, 10), func.count()).where(ThreatIndicator.revoked.is_(False)).group_by(func.substr(ThreatIndicator.source, 1, 10))).all())
    total_rules = db.execute(select(func.count()).select_from(EnrichmentRule)).scalar_one()
    enabled_rules = db.execute(select(func.count()).where(EnrichmentRule.enabled.is_(True))).scalar_one()
    total_rule_hits = db.execute(select(func.sum(EnrichmentRule.hit_count)).where(EnrichmentRule.enabled.is_(True))).scalar_one() or 0
    auto_learned = db.execute(select(func.count()).where(ThreatIndicator.source.startswith("case:"))).scalar_one()
    return {
        "indicators": {"total": total_indicators, "by_verdict": by_verdict, "by_source": by_source, "auto_learned": auto_learned},
        "rules": {"total": total_rules, "enabled": enabled_rules, "total_hits": total_rule_hits},
    }
