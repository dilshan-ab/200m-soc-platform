from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import distinct, func, select, update
from sqlalchemy.orm import Session

from .. import audit
from ..db import get_db
from ..deps import Principal, require, scoped_get
from ..models import ActionRequest, Alert, AlertReceipt, Case, CaseEvidence, EnrichmentJob, Incident, NotificationDelivery, RetentionPolicy, SavedView, ShiftHandoff, User, utcnow
from ..policy import SEVERITIES
from ..services import cases as cases_svc
from ..services import events
from .common import iso, page_out, paginate

router = APIRouter(prefix="/api/alerts", tags=["alerts"])
STATUSES = ["new", "acknowledged", "investigating", "resolved", "false_positive"]


def alert_out(a: Alert, detail: bool = False) -> dict[str, Any]:
    d: dict[str, Any] = {
        "id": a.id, "source": a.source, "time": iso(a.time), "first_seen": iso(a.first_seen), "last_seen": iso(a.last_seen), "severity": a.severity,
        "title": a.title, "rule_id": a.rule_id, "mitre": a.mitre, "host": a.host, "src_ip": a.src_ip, "dst_ip": a.dst_ip, "username": a.username,
        "status": a.status, "assignee_id": a.assignee_id, "case_id": a.case_id, "client_id": a.client_id, "count": a.count, "category": a.category,
        "ack_due": iso(a.ack_due), "resolve_due": iso(a.resolve_due), "sla_breached": a.sla_breached, "version": a.version,
    }
    if detail:
        d.update({"description": a.description, "compliance": a.compliance, "file_hash": a.file_hash, "raw": a.raw, "tuning_note": a.tuning_note,
                  "enrichment": a.enrichment, "acknowledged_at": iso(a.acknowledged_at), "resolved_at": iso(a.resolved_at), "asset_id": a.asset_id})
    return d


@router.get("")
def list_alerts(
    p: Principal = Depends(require("alerts.read")), db: Session = Depends(get_db), severity: list[str] = Query(default=[]), status: list[str] = Query(default=[]),
    source: str | None = None, category: str | None = None, client_id: str | None = None, host: str | None = None, q: str | None = Query(default=None, max_length=200),
    unassigned_client: bool = False, since: datetime | None = None, until: datetime | None = None, sla_breached: bool | None = None, unassigned: bool | None = None,
    sort: Literal["time", "-time", "severity", "-severity"] = "-time", page: int = 1, limit: int = 50,
) -> dict[str, Any]:
    qy = select(Alert).where(p.scope(Alert.client_id))
    if severity:
        qy = qy.where(Alert.severity.in_([s for s in severity if s in SEVERITIES]))
    if status:
        qy = qy.where(Alert.status.in_(status))
    if source:
        qy = qy.where(Alert.source == source)
    if category:
        qy = qy.where(Alert.category == category)
    if client_id:
        qy = qy.where(Alert.client_id == client_id)
    if unassigned_client:
        qy = qy.where(Alert.client_id.is_(None))
    if host:
        qy = qy.where(Alert.host == host)
    if since:
        qy = qy.where(Alert.time >= since)
    if until:
        qy = qy.where(Alert.time <= until)
    if sla_breached is not None:
        qy = qy.where(Alert.sla_breached.is_(sla_breached))
    if unassigned:
        qy = qy.where(Alert.assignee_id.is_(None))
    if q:
        qy = qy.where(Alert.title.contains(q, autoescape=True) | Alert.host.contains(q, autoescape=True) | Alert.src_ip.contains(q, autoescape=True) | Alert.rule_id.contains(q, autoescape=True) | Alert.username.contains(q, autoescape=True) | Alert.dst_ip.contains(q, autoescape=True))
    col = {"time": Alert.time, "severity": Alert.severity}[sort.lstrip("-")]
    qy = qy.order_by(col.desc() if sort.startswith("-") else col.asc(), Alert.id)
    rows, total = paginate(db, qy, page, limit)
    return page_out([alert_out(a) for a in rows], total, page, limit)


@router.get("/queue")
def triage_queue(
    p: Principal = Depends(require("alerts.triage")), db: Session = Depends(get_db),
    unassigned_only: bool = True, severity: list[str] = Query(default=[]), limit: int = Query(default=25, ge=1, le=100),
) -> dict[str, Any]:
    """Prioritised live triage queue: new alerts ordered by severity, then SLA urgency."""
    from sqlalchemy import case as sql_case

    sev_rank = sql_case(*[(Alert.severity == s, i) for i, s in enumerate(SEVERITIES)], else_=0)
    conditions = [p.scope(Alert.client_id), Alert.status == "new"]
    if unassigned_only:
        conditions.append(Alert.assignee_id.is_(None))
    if severity:
        conditions.append(Alert.severity.in_([s for s in severity if s in SEVERITIES]))

    qy = select(Alert).where(*conditions).order_by(sev_rank.desc(), Alert.ack_due.asc().nulls_last(), Alert.time.asc())
    items = db.execute(qy.limit(limit)).scalars().all()

    stats_rows = db.execute(select(Alert.severity, func.count()).where(*conditions).group_by(Alert.severity)).all()
    by_severity = {s: 0 for s in SEVERITIES}
    by_severity.update({sev: n for sev, n in stats_rows})
    oldest = db.execute(select(func.min(Alert.time)).where(*conditions)).scalar()
    return {
        "items": [alert_out(a) for a in items],
        "total_waiting": sum(by_severity.values()),
        "by_severity": by_severity,
        "oldest_waiting": iso(oldest),
    }


@router.get("/stats")
def stats(p: Principal = Depends(require("alerts.read")), db: Session = Depends(get_db)) -> dict[str, Any]:
    from sqlalchemy import func

    rows = db.execute(select(Alert.severity, Alert.status, func.count()).where(p.scope(Alert.client_id)).group_by(Alert.severity, Alert.status)).all()
    out: dict[str, dict[str, int]] = {}
    for sev, st, n in rows:
        out.setdefault(sev, {})[st] = n
    return out


@router.get("/sources")
def alert_sources(p: Principal = Depends(require("alerts.read")), db: Session = Depends(get_db)) -> list[str]:
    return list(db.scalars(select(Alert.source).where(p.scope(Alert.client_id), Alert.source != "").distinct().order_by(Alert.source)))


@router.get("/correlations")
def correlations(
    p: Principal = Depends(require("alerts.read")), db: Session = Depends(get_db),
    days: int = Query(default=7, ge=1, le=30),
) -> dict[str, Any]:
    since = utcnow() - timedelta(days=days)
    sources = func.count(distinct(Alert.source))
    count = func.count()
    rows = db.execute(
        select(Alert.client_id, Alert.host, sources, count, func.max(Alert.time))
        .where(p.scope(Alert.client_id), Alert.time >= since, Alert.host != "", Alert.source != "")
        .group_by(Alert.client_id, Alert.host).having(sources > 1)
        .order_by(count.desc(), Alert.host, Alert.client_id).limit(50)
    )
    return {
        "since": iso(since),
        "items": [
            {"client_id": client, "host": host, "sources": source_count, "alerts": alert_count, "last_seen": iso(last_seen)}
            for client, host, source_count, alert_count, last_seen in rows
        ],
    }


@router.get("/{alert_id}")
def get_alert(alert_id: str, p: Principal = Depends(require("alerts.read")), db: Session = Depends(get_db)) -> dict[str, Any]:
    return alert_out(scoped_get(db, Alert, alert_id, p), detail=True)


class AlertPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: int
    status: Literal["new", "acknowledged", "investigating", "resolved", "false_positive"] | None = None
    assignee_id: str | None = None
    unassign: bool = False
    tuning_note: str | None = Field(default=None, max_length=2000)
    severity: Literal["info", "low", "medium", "high", "critical"] | None = None


def _apply_patch(db: Session, p: Principal, a: Alert, body: AlertPatch) -> None:
    if a.version != body.version:
        raise HTTPException(409, "alert was modified by someone else; reload")
    changed: dict[str, Any] = {}
    now = utcnow()
    if body.status and body.status != a.status:
        if body.status == "false_positive" and not (body.tuning_note or a.tuning_note):
            raise HTTPException(400, "a tuning note is required to mark a false positive")
        a.status = body.status
        if body.status == "acknowledged" and a.acknowledged_at is None:
            a.acknowledged_at = now
        if body.status in ("investigating",) and a.acknowledged_at is None:
            a.acknowledged_at = now
        if body.status in ("resolved", "false_positive"):
            a.resolved_at = now
            if a.acknowledged_at is None:
                a.acknowledged_at = now
        changed["status"] = body.status
    if body.assignee_id:
        u = db.get(User, body.assignee_id)
        if u is None or not u.active or not (u.all_clients or True):
            raise HTTPException(400, "invalid assignee")
        a.assignee_id = u.id
        changed["assignee"] = u.id
    if body.unassign:
        a.assignee_id = None
    if body.tuning_note is not None:
        if not p.can("alerts.tune"):
            raise HTTPException(403, "missing capability alerts.tune")
        a.tuning_note = body.tuning_note
        changed["tuning_note"] = True
    if body.severity and body.severity != a.severity:
        if not p.can("alerts.tune"):
            raise HTTPException(403, "missing capability alerts.tune")
        a.severity = body.severity
        changed["severity"] = body.severity
    if changed:
        a.version += 1
        audit.record(db, "alert.update", actor=p.label, actor_id=p.user.id, resource_type="alert", resource_id=a.id, client_id=a.client_id, ip=p.ip, meta=changed)
        events.publish(db, "alert.updated", id=a.id, client_id=a.client_id, severity=a.severity)


@router.patch("/{alert_id}")
def patch_alert(alert_id: str, body: AlertPatch, p: Principal = Depends(require("alerts.triage")), db: Session = Depends(get_db)) -> dict[str, Any]:
    a = scoped_get(db, Alert, alert_id, p)
    _apply_patch(db, p, a, body)
    return alert_out(a, detail=True)


class BulkIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ids: list[str] = Field(min_length=1, max_length=100)
    status: Literal["acknowledged", "investigating", "resolved"] | None = None
    assignee_id: str | None = None


@router.post("/bulk")
def bulk(body: BulkIn, p: Principal = Depends(require("alerts.triage")), db: Session = Depends(get_db)) -> dict[str, Any]:
    done, skipped = 0, []
    for aid in dict.fromkeys(body.ids):
        a = db.get(Alert, aid)
        if a is None or not p.can_see_client(a.client_id):
            skipped.append(aid)
            continue
        _apply_patch(db, p, a, AlertPatch(version=a.version, status=body.status, assignee_id=body.assignee_id))
        done += 1
    return {"updated": done, "skipped": skipped}


class DeleteAlertsIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ids: list[str] = Field(min_length=1, max_length=100)


def _delete_alerts(db: Session, p: Principal, ids: list[str]) -> int:
    policy = db.execute(select(RetentionPolicy).where(RetentionPolicy.dataset == "alerts")).scalar_one_or_none()
    if policy and policy.legal_hold:
        raise HTTPException(409, "alerts are under legal hold; an administrator must release the hold before deletion")
    unique_ids = set(ids)
    alerts = db.execute(select(Alert).where(Alert.id.in_(unique_ids), p.scope(Alert.client_id)).with_for_update()).scalars().all()
    if len(alerts) != len(unique_ids):
        raise HTTPException(404, "one or more alerts were not found in your scope; no alerts were deleted")

    for model in (ActionRequest, AlertReceipt, CaseEvidence, EnrichmentJob, NotificationDelivery):
        db.execute(update(model).where(model.alert_id.in_(unique_ids)).values(alert_id=None))
    for incident in db.execute(select(Incident).where(p.scope(Incident.client_id)).with_for_update()).scalars():
        if unique_ids.intersection(incident.alert_ids):
            incident.alert_ids = [aid for aid in incident.alert_ids if aid not in unique_ids]
            incident.alert_count = len(incident.alert_ids)
            times = db.execute(select(func.min(Alert.time), func.max(Alert.time)).where(Alert.id.in_(incident.alert_ids))).one()
            incident.first_alert_time, incident.last_alert_time = times
    for handoff in db.execute(select(ShiftHandoff).where(p.scope(ShiftHandoff.client_id) | ShiftHandoff.client_id.is_(None)).with_for_update()).scalars():
        if unique_ids.intersection(handoff.alert_ids):
            handoff.alert_ids = [aid for aid in handoff.alert_ids if aid not in unique_ids]
    for alert in alerts:
        if alert.case_id:
            case = db.get(Case, alert.case_id)
            if case:
                cases_svc.add_event(db, case, p.label, "alert", f"Alert deleted: {alert.title}", {"alert_id": alert.id})
        audit.record(db, "alert.delete", actor=p.label, actor_id=p.user.id, resource_type="alert", resource_id=alert.id,
                     client_id=alert.client_id, ip=p.ip, meta={"title": alert.title, "case_id": alert.case_id})
        events.publish(db, "alert.deleted", id=alert.id, client_id=alert.client_id)
        db.delete(alert)
    return len(alerts)


@router.post("/bulk-delete")
def bulk_delete(body: DeleteAlertsIn, p: Principal = Depends(require("alerts.delete")), db: Session = Depends(get_db)) -> dict[str, int]:
    return {"deleted": _delete_alerts(db, p, body.ids)}


@router.post("/delete-all")
def delete_all(p: Principal = Depends(require("alerts.delete")), db: Session = Depends(get_db)) -> dict[str, int]:
    """Delete every alert in the caller's scope (not just the current page/filter)."""
    all_ids = db.execute(select(Alert.id).where(p.scope(Alert.client_id))).scalars().all()
    deleted = 0
    for i in range(0, len(all_ids), 200):
        deleted += _delete_alerts(db, p, all_ids[i:i + 200])
    return {"deleted": deleted}


@router.delete("/{alert_id}", status_code=204)
def delete_alert(alert_id: str, p: Principal = Depends(require("alerts.delete")), db: Session = Depends(get_db)) -> None:
    _delete_alerts(db, p, [alert_id])


class CaseFromAlerts(BaseModel):
    model_config = ConfigDict(extra="forbid")
    alert_ids: list[str] = Field(min_length=1, max_length=50)
    title: str | None = Field(default=None, max_length=300)
    template: str | None = Field(default=None, max_length=80)


@router.post("/to-case", status_code=201)
def to_case(body: CaseFromAlerts, p: Principal = Depends(require("cases.write")), db: Session = Depends(get_db)) -> dict[str, Any]:
    alerts = []
    for aid in dict.fromkeys(body.alert_ids):
        a = scoped_get(db, Alert, aid, p)
        if a.case_id:
            raise HTTPException(409, f"alert {aid} is already in a case")
        alerts.append(a)
    try:
        c = cases_svc.create_case_from_alerts(db, alerts, actor=p.label, template=body.template, title=body.title, owner_id=p.user.id)
    except ValueError as e:
        raise HTTPException(400, str(e)) from e
    audit.record(db, "case.create", actor=p.label, actor_id=p.user.id, resource_type="case", resource_id=c.id, client_id=c.client_id, ip=p.ip, meta={"alerts": len(alerts)})
    return {"id": c.id, "number": c.number}


class ViewIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=120)
    filters: dict[str, Any]


@router.get("/views/mine")
def my_views(p: Principal = Depends(require("alerts.read")), db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    return [{"id": v.id, "name": v.name, "filters": v.filters} for v in db.execute(select(SavedView).where(SavedView.user_id == p.user.id, SavedView.scope == "alerts")).scalars()]


@router.post("/views", status_code=201)
def save_view(body: ViewIn, p: Principal = Depends(require("alerts.read")), db: Session = Depends(get_db)) -> dict[str, Any]:
    v = SavedView(user_id=p.user.id, name=body.name, filters=body.filters)
    db.add(v)
    db.flush()
    return {"id": v.id}


@router.delete("/views/{vid}")
def delete_view(vid: str, p: Principal = Depends(require("alerts.read")), db: Session = Depends(get_db)) -> dict[str, bool]:
    v = db.get(SavedView, vid)
    if v is None or v.user_id != p.user.id:
        raise HTTPException(404, "not found")
    db.delete(v)
    return {"ok": True}
