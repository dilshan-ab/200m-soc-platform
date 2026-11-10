"""SLA policy helpers: versioned targets, due-date calculation, breach detection."""
from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import Alert, SlaPolicy, utcnow

DEFAULT_TARGETS = {
    "critical": {"ack_minutes": 5, "resolve_minutes": 60},
    "high": {"ack_minutes": 15, "resolve_minutes": 240},
    "medium": {"ack_minutes": 60, "resolve_minutes": 1440},
    "low": {"ack_minutes": 240, "resolve_minutes": 4320},
    "info": {"ack_minutes": 1440, "resolve_minutes": 10080},
}


def active_policy(db: Session) -> SlaPolicy:
    p = db.execute(select(SlaPolicy).where(SlaPolicy.active.is_(True)).order_by(SlaPolicy.version.desc())).scalars().first()
    if p is None:
        p = SlaPolicy(version=1, active=True, targets=DEFAULT_TARGETS, pause_statuses=["pending_customer"], created_by="system")
        db.add(p)
        db.flush()
    return p


def due_dates(policy: SlaPolicy, severity: str, start: datetime) -> tuple[datetime, datetime]:
    t = policy.targets.get(severity) or DEFAULT_TARGETS.get(severity) or DEFAULT_TARGETS["low"]
    return start + timedelta(minutes=t["ack_minutes"]), start + timedelta(minutes=t["resolve_minutes"])


def apply_sla(db: Session, alert: Alert) -> None:
    p = active_policy(db)
    alert.ack_due, alert.resolve_due = due_dates(p, alert.severity, alert.first_seen)
    alert.sla_policy_version = p.version


def check_breaches(db: Session) -> list[Alert]:
    """Mark alerts whose SLA is breached. Returns newly breached alerts."""
    now = utcnow()
    out: list[Alert] = []
    q = select(Alert).where(Alert.sla_breached.is_(False), Alert.status.in_(["new", "acknowledged", "investigating"]))
    for a in db.execute(q).scalars():
        ack_breach = a.acknowledged_at is None and a.ack_due is not None and now > a.ack_due
        res_breach = a.resolved_at is None and a.resolve_due is not None and now > a.resolve_due
        if ack_breach or res_breach:
            a.sla_breached = True
            out.append(a)
    return out
