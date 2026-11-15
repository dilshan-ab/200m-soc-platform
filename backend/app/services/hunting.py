"""Threat hunting workbench: hypothesis-driven queries over already-ingested alerts.

A "search" hunt needs no connected tooling — it runs its query directly against the alert
corpus already in the platform. A "collection" hunt (the original behaviour) still dispatches
an approval-gated artifact pull via a connector such as Velociraptor.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Alert, Hunt, utcnow

if TYPE_CHECKING:
    from ..deps import Principal

MAX_STORED_RESULTS = 200
MAX_QUERY_ROWS = 2000


def _iso(d: datetime | None) -> str | None:
    return d.isoformat() + "Z" if d else None


def _alert_summary(a: Alert) -> dict[str, Any]:
    return {"id": a.id, "title": a.title, "severity": a.severity, "status": a.status, "host": a.host, "time": _iso(a.time), "mitre": a.mitre}


def matching_alerts(db: Session, p: Principal, query: dict[str, Any]) -> list[Alert]:
    """Run a hunt's structured query against the alert corpus, scoped like every other alert read."""
    conditions = [p.scope(Alert.client_id)]
    days = query.get("days")
    if days:
        conditions.append(Alert.time >= utcnow() - timedelta(days=int(days)))
    severities = query.get("severities") or []
    if severities:
        conditions.append(Alert.severity.in_(severities))
    if query.get("host"):
        conditions.append(Alert.host.contains(str(query["host"]), autoescape=True))
    if query.get("rule_id"):
        conditions.append(Alert.rule_id.contains(str(query["rule_id"]), autoescape=True))
    q = query.get("q")
    if q:
        like = str(q)
        conditions.append(
            Alert.title.contains(like, autoescape=True) | Alert.description.contains(like, autoescape=True)
            | Alert.host.contains(like, autoescape=True) | Alert.src_ip.contains(like, autoescape=True)
        )
    rows = db.execute(select(Alert).where(*conditions).order_by(Alert.time.desc()).limit(MAX_QUERY_ROWS)).scalars().all()
    technique_ids = set(query.get("technique_ids") or [])
    if technique_ids:
        rows = [a for a in rows if technique_ids & set(a.mitre or [])]
    return list(rows)


def run_hunt(db: Session, p: Principal, hunt: Hunt) -> list[Alert]:
    """Execute (or re-run) a search hunt's query and snapshot the matches onto the hunt record."""
    rows = matching_alerts(db, p, hunt.query)
    hunt.match_count = len(rows)
    hunt.results = [_alert_summary(a) for a in rows[:MAX_STORED_RESULTS]]
    if hunt.status == "draft":
        hunt.status = "active"
    return rows
