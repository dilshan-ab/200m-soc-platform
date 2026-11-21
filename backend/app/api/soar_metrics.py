"""SOAR metrics: playbook effectiveness, automation coverage, response action stats."""
from __future__ import annotations

from datetime import timedelta
from typing import Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import Principal, require
from ..models import (
    ActionRequest,
    Alert,
    AutomationRule,
    AutomationRun,
    Playbook,
    PlaybookRun,
    utcnow,
)

router = APIRouter(prefix="/api/soar", tags=["soar"])


def _avg_minutes(pairs: list[tuple[Any, Any]]) -> float | None:
    deltas = [(end - start).total_seconds() for start, end in pairs if start and end]
    return round(sum(deltas) / len(deltas) / 60, 1) if deltas else None


@router.get("/metrics")
def soar_metrics(
    p: Principal = Depends(require("metrics.read")),
    db: Session = Depends(get_db),
    days: int = Query(default=30, ge=1, le=365),
    client_id: str | None = None,
) -> dict[str, Any]:
    since = utcnow() - timedelta(days=days)

    # --- Alert response times (MTTA / MTTR) ---
    af = [Alert.time >= since, p.scope(Alert.client_id)]
    if client_id:
        af.append(Alert.client_id == client_id)
    total_alerts = db.execute(select(func.count()).where(*af)).scalar_one()
    acked = db.execute(select(Alert.first_seen, Alert.acknowledged_at).where(*af, Alert.acknowledged_at.is_not(None))).all()
    resolved = db.execute(select(Alert.first_seen, Alert.resolved_at).where(*af, Alert.resolved_at.is_not(None))).all()
    breached = db.execute(select(func.count()).where(*af, Alert.sla_breached.is_(True))).scalar_one()
    sev_dist = dict(db.execute(select(Alert.severity, func.count()).where(*af).group_by(Alert.severity)).all())

    # --- Playbook stats ---
    total_playbooks = db.execute(select(func.count()).select_from(Playbook)).scalar_one()
    published_playbooks = db.execute(select(func.count()).where(Playbook.status == "published")).scalar_one()
    pf = [PlaybookRun.started_at >= since]
    total_runs = db.execute(select(func.count()).where(*pf)).scalar_one()
    run_statuses = dict(db.execute(select(PlaybookRun.status, func.count()).where(*pf).group_by(PlaybookRun.status)).all())
    run_times = db.execute(select(PlaybookRun.started_at, PlaybookRun.finished_at).where(*pf, PlaybookRun.finished_at.is_not(None))).all()

    top_playbooks_q = (
        select(Playbook.name, func.count().label("runs"))
        .join(PlaybookRun, PlaybookRun.playbook_id == Playbook.id)
        .where(PlaybookRun.started_at >= since)
        .group_by(Playbook.name)
        .order_by(func.count().desc())
        .limit(5)
    )
    top_playbooks = [{"name": n, "runs": r} for n, r in db.execute(top_playbooks_q)]

    # --- Automation rule stats ---
    total_rules = db.execute(select(func.count()).select_from(AutomationRule)).scalar_one()
    enabled_rules = db.execute(select(func.count()).where(AutomationRule.enabled.is_(True))).scalar_one()
    rf = [AutomationRun.created_at >= since, AutomationRun.dry_run.is_(False)]
    auto_runs = db.execute(select(func.count()).where(*rf)).scalar_one()
    auto_matched = db.execute(select(func.count()).where(*rf, AutomationRun.matched.is_(True))).scalar_one()
    auto_failed = db.execute(select(func.count()).where(*rf, AutomationRun.status == "error")).scalar_one()

    # --- Response action stats ---
    arf = [ActionRequest.created_at >= since]
    if client_id:
        arf.append(ActionRequest.client_id == client_id)
    total_actions = db.execute(select(func.count()).where(*arf)).scalar_one()
    action_statuses = dict(db.execute(select(ActionRequest.status, func.count()).where(*arf).group_by(ActionRequest.status)).all())
    action_types = dict(db.execute(
        select(ActionRequest.action_key, func.count()).where(*arf).group_by(ActionRequest.action_key).order_by(func.count().desc())
    ).all())
    approval_times = db.execute(
        select(ActionRequest.created_at, ActionRequest.started_at).where(*arf, ActionRequest.started_at.is_not(None))
    ).all()
    execution_times = db.execute(
        select(ActionRequest.started_at, ActionRequest.finished_at).where(*arf, ActionRequest.finished_at.is_not(None))
    ).all()

    # --- Automation coverage ---
    auto_handled = db.execute(
        select(func.count()).where(*af, Alert.status.in_(["resolved", "false_positive"]))
        .where(Alert.assignee_id.is_(None))
    ).scalar_one()
    manual_handled = db.execute(
        select(func.count()).where(*af, Alert.status.in_(["resolved", "false_positive"]))
        .where(Alert.assignee_id.is_not(None))
    ).scalar_one()

    return {
        "since": since.isoformat(),
        "days": days,
        "alerts": {
            "total": total_alerts,
            "mtta_minutes": _avg_minutes(acked),
            "mttr_minutes": _avg_minutes(resolved),
            "sla_breached": breached,
            "sla_compliance_pct": round(100 * (1 - breached / total_alerts), 1) if total_alerts else 100.0,
            "by_severity": sev_dist,
        },
        "playbooks": {
            "total": total_playbooks,
            "published": published_playbooks,
            "runs": total_runs,
            "by_status": run_statuses,
            "avg_duration_minutes": _avg_minutes(run_times),
            "success_rate_pct": round(100 * run_statuses.get("completed", 0) / total_runs, 1) if total_runs else None,
            "top": top_playbooks,
        },
        "automation": {
            "rules_total": total_rules,
            "rules_enabled": enabled_rules,
            "evaluations": auto_runs,
            "matched": auto_matched,
            "match_rate_pct": round(100 * auto_matched / auto_runs, 1) if auto_runs else None,
            "failures": auto_failed,
            "coverage": {
                "auto_resolved": auto_handled,
                "manual_resolved": manual_handled,
                "auto_pct": round(100 * auto_handled / (auto_handled + manual_handled), 1) if (auto_handled + manual_handled) else None,
            },
        },
        "response_actions": {
            "total": total_actions,
            "by_status": action_statuses,
            "by_type": action_types,
            "avg_approval_minutes": _avg_minutes(approval_times),
            "avg_execution_minutes": _avg_minutes(execution_times),
        },
    }
