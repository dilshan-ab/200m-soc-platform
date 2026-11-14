from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit
from ..db import get_db
from ..deps import Principal, require, scoped_get
from ..models import CorrelationRule, Incident, utcnow
from ..services import events
from ..services.correlation import STRATEGIES, run_correlation
from .common import iso, page_out, paginate

router = APIRouter(prefix="/api/correlation", tags=["correlation"])


# ── correlation rules ──────────────────────────────────────────────

def rule_out(r: CorrelationRule) -> dict[str, Any]:
    return {
        "id": r.id,
        "name": r.name,
        "description": r.description,
        "strategy": r.strategy,
        "config": r.config or {},
        "severity_boost": r.severity_boost,
        "enabled": r.enabled,
        "client_id": r.client_id,
        "created_by": r.created_by,
        "created_at": iso(r.created_at),
        "updated_at": iso(r.updated_at),
    }


@router.get("/rules")
def list_rules(
    p: Principal = Depends(require("correlation.read")),
    db: Session = Depends(get_db),
    page: int = 1,
    limit: int = 50,
) -> dict[str, Any]:
    qy = select(CorrelationRule).where(p.scope(CorrelationRule.client_id))
    rows, total = paginate(db, qy.order_by(CorrelationRule.name), page, limit)
    return page_out([rule_out(r) for r in rows], total, page, limit)


class RuleIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=2, max_length=200)
    description: str = Field(default="", max_length=5000)
    strategy: Literal["ioc_overlap", "time_window", "kill_chain", "threshold"]
    config: dict[str, Any] = Field(default_factory=dict)
    severity_boost: int = Field(default=1, ge=0, le=4)
    enabled: bool = True
    client_id: str | None = None


@router.post("/rules", status_code=201)
def create_rule(body: RuleIn, p: Principal = Depends(require("correlation.write")), db: Session = Depends(get_db)) -> dict[str, Any]:
    if body.strategy not in STRATEGIES:
        raise HTTPException(400, f"unknown strategy: {body.strategy}")
    r = CorrelationRule(
        name=body.name,
        description=body.description,
        strategy=body.strategy,
        config=body.config,
        severity_boost=body.severity_boost,
        enabled=body.enabled,
        client_id=body.client_id,
        created_by=p.label,
    )
    db.add(r)
    db.flush()
    audit.record(db, "correlation_rule.create", actor=p.label, actor_id=p.user.id, resource_type="correlation_rule", resource_id=r.id, client_id=r.client_id, ip=p.ip)
    return rule_out(r)


@router.get("/rules/{rule_id}")
def get_rule(rule_id: str, p: Principal = Depends(require("correlation.read")), db: Session = Depends(get_db)) -> dict[str, Any]:
    return rule_out(scoped_get(db, CorrelationRule, rule_id, p))


class RuleUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str | None = Field(default=None, min_length=2, max_length=200)
    description: str | None = Field(default=None, max_length=5000)
    config: dict[str, Any] | None = None
    severity_boost: int | None = Field(default=None, ge=0, le=4)
    enabled: bool | None = None


@router.patch("/rules/{rule_id}")
def update_rule(rule_id: str, body: RuleUpdate, p: Principal = Depends(require("correlation.write")), db: Session = Depends(get_db)) -> dict[str, Any]:
    r = scoped_get(db, CorrelationRule, rule_id, p)
    for field in ("name", "description", "config", "severity_boost", "enabled"):
        v = getattr(body, field)
        if v is not None:
            setattr(r, field, v)
    r.updated_at = utcnow()
    audit.record(db, "correlation_rule.update", actor=p.label, actor_id=p.user.id, resource_type="correlation_rule", resource_id=r.id, client_id=r.client_id, ip=p.ip)
    return rule_out(r)


@router.delete("/rules/{rule_id}", status_code=204)
def delete_rule(rule_id: str, p: Principal = Depends(require("correlation.write")), db: Session = Depends(get_db)) -> None:
    r = scoped_get(db, CorrelationRule, rule_id, p)
    audit.record(db, "correlation_rule.delete", actor=p.label, actor_id=p.user.id, resource_type="correlation_rule", resource_id=r.id, client_id=r.client_id, ip=p.ip)
    db.delete(r)


# ── run correlation engine ─────────────────────────────────────────

@router.post("/run", status_code=201)
def trigger_correlation(
    p: Principal = Depends(require("correlation.write")),
    db: Session = Depends(get_db),
    client_id: str | None = None,
) -> dict[str, Any]:
    incidents = run_correlation(db, client_id=client_id)
    db.flush()
    for inc in incidents:
        events.publish(db, "incident.created", id=inc.id, severity=inc.severity, client_id=inc.client_id)
    return {"created": len(incidents), "incidents": [incident_out(i) for i in incidents]}


# ── incidents ──────────────────────────────────────────────────────

def incident_out(i: Incident, detail: bool = False) -> dict[str, Any]:
    d = {
        "id": i.id,
        "name": i.name,
        "severity": i.severity,
        "status": i.status,
        "strategy": i.strategy,
        "rule_name": i.rule_name,
        "alert_count": i.alert_count,
        "first_alert_time": iso(i.first_alert_time),
        "last_alert_time": iso(i.last_alert_time),
        "case_id": i.case_id,
        "client_id": i.client_id,
        "assignee_id": i.assignee_id,
        "created_at": iso(i.created_at),
        "updated_at": iso(i.updated_at),
    }
    if detail:
        d.update({
            "description": i.description,
            "rule_id": i.rule_id,
            "alert_ids": i.alert_ids or [],
            "shared_iocs": i.shared_iocs or {},
            "kill_chain_stages": i.kill_chain_stages or [],
        })
    return d


@router.get("/incidents")
def list_incidents(
    p: Principal = Depends(require("incidents.read")),
    db: Session = Depends(get_db),
    status: str | None = None,
    severity: str | None = None,
    q: str | None = Query(default=None, max_length=200),
    page: int = 1,
    limit: int = 50,
) -> dict[str, Any]:
    qy = select(Incident).where(p.scope(Incident.client_id))
    if status:
        qy = qy.where(Incident.status == status)
    if severity:
        qy = qy.where(Incident.severity == severity)
    if q:
        qy = qy.where(Incident.name.contains(q, autoescape=True))
    rows, total = paginate(db, qy.order_by(Incident.created_at.desc(), Incident.id), page, limit)
    return page_out([incident_out(i) for i in rows], total, page, limit)


@router.get("/incidents/{incident_id}")
def get_incident(incident_id: str, p: Principal = Depends(require("incidents.read")), db: Session = Depends(get_db)) -> dict[str, Any]:
    return incident_out(scoped_get(db, Incident, incident_id, p), detail=True)


class IncidentPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Literal["open", "investigating", "resolved", "false_positive"] | None = None
    assignee_id: str | None = None
    severity: Literal["info", "low", "medium", "high", "critical"] | None = None


@router.patch("/incidents/{incident_id}")
def update_incident(incident_id: str, body: IncidentPatch, p: Principal = Depends(require("incidents.write")), db: Session = Depends(get_db)) -> dict[str, Any]:
    inc = scoped_get(db, Incident, incident_id, p)
    for field in ("status", "assignee_id", "severity"):
        v = getattr(body, field)
        if v is not None:
            setattr(inc, field, v)
    inc.updated_at = utcnow()
    audit.record(db, "incident.update", actor=p.label, actor_id=p.user.id, resource_type="incident", resource_id=inc.id, client_id=inc.client_id, ip=p.ip)
    return incident_out(inc, detail=True)


@router.delete("/incidents/{incident_id}", status_code=204)
def delete_incident(incident_id: str, p: Principal = Depends(require("incidents.write")), db: Session = Depends(get_db)) -> None:
    inc = scoped_get(db, Incident, incident_id, p)
    audit.record(db, "incident.delete", actor=p.label, actor_id=p.user.id, resource_type="incident", resource_id=inc.id, client_id=inc.client_id, ip=p.ip)
    db.delete(inc)


@router.get("/strategies")
def list_strategies(p: Principal = Depends(require("correlation.read"))) -> list[dict[str, str]]:
    return [
        {"key": "ioc_overlap", "label": "IOC overlap", "description": "Group alerts sharing common indicators (IPs, hosts, users, hashes) within a time window"},
        {"key": "time_window", "label": "Time window", "description": "Group alerts by shared attributes when N+ arrive within a time window"},
        {"key": "kill_chain", "label": "Kill chain", "description": "Detect multi-stage attacks by matching MITRE ATT&CK tactics across alerts"},
        {"key": "threshold", "label": "Threshold", "description": "Fire when the same alert rule triggers N+ times within a window"},
    ]
