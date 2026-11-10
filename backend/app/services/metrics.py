"""SOC metrics (single definition used by dashboards and reports)."""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models import Alert, Asset, Case, Finding, Server, User, utcnow
from ..policy import SEVERITIES

if TYPE_CHECKING:
    from ..deps import Principal

METRIC_VERSION = 1


def _avg_minutes(rows: Any) -> float | None:
    deltas = [(end - start).total_seconds() for start, end in rows if start is not None and end is not None]
    return sum(deltas) / len(deltas) / 60 if deltas else None


def soc_metrics(db: Session, p: Principal, since: datetime | None = None, client_id: str | None = None) -> dict[str, Any]:
    since = since or utcnow() - timedelta(days=7)
    af = [Alert.time >= since, p.scope(Alert.client_id)]
    if client_id:
        af.append(Alert.client_id == client_id)
    sev = {s: 0 for s in SEVERITIES}
    for s, n in db.execute(select(Alert.severity, func.count()).where(*af).group_by(Alert.severity)):
        sev[s] = n
    total = sum(sev.values())
    by_status = dict(db.execute(select(Alert.status, func.count()).where(*af).group_by(Alert.status)).all())
    acked = db.execute(select(Alert.first_seen, Alert.acknowledged_at).where(*af, Alert.acknowledged_at.is_not(None))).all()
    resolved = db.execute(select(Alert.first_seen, Alert.resolved_at).where(*af, Alert.resolved_at.is_not(None))).all()
    mtta = _avg_minutes(acked)
    mttr = _avg_minutes(resolved)
    breached = db.execute(select(func.count()).where(*af, Alert.sla_breached.is_(True))).scalar_one()
    sla_pct = round(100 * (1 - breached / total), 1) if total else 100.0
    cf = [p.scope(Case.client_id)] + ([Case.client_id == client_id] if client_id else [])
    open_cases = db.execute(select(func.count()).where(*cf, Case.status.in_(["open", "in_progress"]))).scalar_one()
    sf = [p.scope(Server.client_id)] + ([Server.client_id == client_id] if client_id else [])
    servers = dict(db.execute(select(Server.status, func.count()).where(*sf).group_by(Server.status)).all())
    ff = [p.scope(Finding.client_id), Finding.status == "open"] + ([Finding.client_id == client_id] if client_id else [])
    vulns = dict(db.execute(select(Finding.severity, func.count()).where(*ff).group_by(Finding.severity)).all())
    af2 = [p.scope(Asset.client_id), Asset.decommissioned.is_(False)] + ([Asset.client_id == client_id] if client_id else [])
    assets_total = db.execute(select(func.count()).where(*af2)).scalar_one()
    assets_active = db.execute(select(func.count()).where(*af2, Asset.agent_status == "active")).scalar_one()
    return {
        "since": since.isoformat(), "metric_version": METRIC_VERSION, "alerts_total": total, "alerts_by_severity": sev, "alerts_by_status": by_status,
        "mtta_minutes": round(mtta, 1) if mtta is not None else None, "mttr_minutes": round(mttr, 1) if mttr is not None else None,
        "sla_compliance_pct": sla_pct, "sla_breached": breached, "open_cases": open_cases, "servers_by_status": servers,
        "open_vulns_by_severity": vulns, "assets_total": assets_total, "agents_active": assets_active,
        "agent_coverage_pct": round(100 * assets_active / assets_total, 1) if assets_total else 0.0,
    }


def analyst_metrics(db: Session, p: Principal, since: datetime, client_id: str | None = None) -> dict[str, Any]:
    """Per-analyst MTTA/MTTR, SLA adherence and case volume, grouped by the alert's assignee / case's owner."""
    af = [Alert.time >= since, p.scope(Alert.client_id), Alert.assignee_id.is_not(None)]
    if client_id:
        af.append(Alert.client_id == client_id)
    alert_rows = db.execute(
        select(Alert.assignee_id, Alert.first_seen, Alert.acknowledged_at, Alert.resolved_at, Alert.sla_breached, Alert.severity).where(*af)
    ).all()

    cf = [Case.created_at >= since, p.scope(Case.client_id), Case.owner_id.is_not(None)]
    if client_id:
        cf.append(Case.client_id == client_id)
    case_rows = db.execute(select(Case.owner_id, Case.created_at, Case.closed_at, Case.status).where(*cf)).all()

    buckets: dict[str, dict[str, Any]] = {}

    def bucket(uid: str) -> dict[str, Any]:
        return buckets.setdefault(uid, {
            "alerts_assigned": 0, "alerts_acknowledged": 0, "alerts_resolved": 0, "alerts_breached": 0, "critical_high": 0,
            "ack_deltas": [], "res_deltas": [], "cases_owned": 0, "cases_closed": 0, "case_deltas": [],
        })

    for assignee_id, first_seen, ack, res, breached, sev in alert_rows:
        if not assignee_id:
            continue
        b = bucket(assignee_id)
        b["alerts_assigned"] += 1
        if sev in ("critical", "high"):
            b["critical_high"] += 1
        if breached:
            b["alerts_breached"] += 1
        if ack is not None:
            b["alerts_acknowledged"] += 1
            b["ack_deltas"].append((first_seen, ack))
        if res is not None:
            b["alerts_resolved"] += 1
            b["res_deltas"].append((first_seen, res))

    for owner_id, created_at, closed_at, status in case_rows:
        if not owner_id:
            continue
        b = bucket(owner_id)
        b["cases_owned"] += 1
        if status == "closed":
            b["cases_closed"] += 1
            if closed_at is not None:
                b["case_deltas"].append((created_at, closed_at))

    users = {u.id: u for u in db.execute(select(User).where(User.id.in_(list(buckets)))).scalars()} if buckets else {}

    analysts = []
    for uid, b in buckets.items():
        u = users.get(uid)
        mtta, mttr, case_mttr = _avg_minutes(b["ack_deltas"]), _avg_minutes(b["res_deltas"]), _avg_minutes(b["case_deltas"])
        analysts.append({
            "id": uid, "name": (u.name or u.email) if u else "Unknown analyst", "email": u.email if u else None,
            "role": u.role if u else None, "active": u.active if u else False,
            "alerts_assigned": b["alerts_assigned"], "alerts_acknowledged": b["alerts_acknowledged"], "alerts_resolved": b["alerts_resolved"],
            "alerts_breached": b["alerts_breached"], "critical_high_handled": b["critical_high"],
            "mtta_minutes": round(mtta, 1) if mtta is not None else None, "mttr_minutes": round(mttr, 1) if mttr is not None else None,
            "cases_owned": b["cases_owned"], "cases_closed": b["cases_closed"],
            "case_mttr_minutes": round(case_mttr, 1) if case_mttr is not None else None,
        })
    analysts.sort(key=lambda a: (a["alerts_resolved"], a["cases_closed"]), reverse=True)

    team_mtta = _avg_minutes([d for b in buckets.values() for d in b["ack_deltas"]])
    team_mttr = _avg_minutes([d for b in buckets.values() for d in b["res_deltas"]])
    team_case_mttr = _avg_minutes([d for b in buckets.values() for d in b["case_deltas"]])
    return {
        "since": since.isoformat(), "analysts": analysts,
        "team": {
            "analysts_active": len(analysts), "alerts_resolved": sum(a["alerts_resolved"] for a in analysts),
            "cases_closed": sum(a["cases_closed"] for a in analysts),
            "mtta_minutes": round(team_mtta, 1) if team_mtta is not None else None,
            "mttr_minutes": round(team_mttr, 1) if team_mttr is not None else None,
            "case_mttr_minutes": round(team_case_mttr, 1) if team_case_mttr is not None else None,
        },
    }
