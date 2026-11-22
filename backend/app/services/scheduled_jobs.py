"""Scheduled jobs dashboard: unified view across enrichment, report, automation, playbook, and backup jobs."""
from __future__ import annotations

from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models import (
    AutomationRule,
    AutomationRun,
    BackupJob,
    EnrichmentJob,
    PlaybookRun,
    ReportJob,
    ReportSchedule,
    utcnow,
)


def get_overview(db: Session) -> dict[str, Any]:
    now = utcnow()

    enrichment_total = db.execute(select(func.count()).select_from(EnrichmentJob)).scalar_one()
    enrichment_running = db.execute(select(func.count()).select_from(EnrichmentJob).where(EnrichmentJob.status.in_(("queued", "running")))).scalar_one()
    enrichment_failed = db.execute(select(func.count()).select_from(EnrichmentJob).where(EnrichmentJob.status == "failed")).scalar_one()

    report_total = db.execute(select(func.count()).select_from(ReportJob)).scalar_one()
    report_running = db.execute(select(func.count()).select_from(ReportJob).where(ReportJob.status.in_(("queued", "running")))).scalar_one()
    report_failed = db.execute(select(func.count()).select_from(ReportJob).where(ReportJob.status == "failed")).scalar_one()

    schedule_total = db.execute(select(func.count()).select_from(ReportSchedule)).scalar_one()
    schedule_active = db.execute(select(func.count()).select_from(ReportSchedule).where(ReportSchedule.paused.is_(False))).scalar_one()
    schedule_paused = db.execute(select(func.count()).select_from(ReportSchedule).where(ReportSchedule.paused.is_(True))).scalar_one()

    auto_total = db.execute(select(func.count()).select_from(AutomationRule)).scalar_one()
    auto_enabled = db.execute(select(func.count()).select_from(AutomationRule).where(AutomationRule.enabled.is_(True))).scalar_one()
    from datetime import timedelta
    cutoff = now - timedelta(days=1)
    auto_runs_24h = db.execute(
        select(func.count()).select_from(AutomationRun).where(AutomationRun.created_at >= cutoff)
    ).scalar_one()

    playbook_total = db.execute(select(func.count()).select_from(PlaybookRun)).scalar_one()
    playbook_running = db.execute(select(func.count()).select_from(PlaybookRun).where(PlaybookRun.status == "running")).scalar_one()
    playbook_failed = db.execute(select(func.count()).select_from(PlaybookRun).where(PlaybookRun.status == "failed")).scalar_one()

    backup_total = db.execute(select(func.count()).select_from(BackupJob)).scalar_one()

    return {
        "enrichment": {"total": enrichment_total, "active": enrichment_running, "failed": enrichment_failed},
        "reports": {"total": report_total, "active": report_running, "failed": report_failed},
        "schedules": {"total": schedule_total, "active": schedule_active, "paused": schedule_paused},
        "automation": {"total_rules": auto_total, "enabled": auto_enabled, "runs_24h": auto_runs_24h},
        "playbooks": {"total_runs": playbook_total, "running": playbook_running, "failed": playbook_failed},
        "backups": {"total": backup_total},
    }


def list_jobs(db: Session, category: str | None = None, status: str | None = None,
              size: int = 50, page: int = 1) -> dict[str, Any]:
    items: list[dict[str, Any]] = []

    if not category or category == "enrichment":
        eq = select(EnrichmentJob)
        if status:
            eq = eq.where(EnrichmentJob.status == status)
        for ej in db.execute(eq.order_by(EnrichmentJob.created_at.desc()).limit(size)).scalars():
            items.append({
                "id": ej.id, "category": "enrichment", "name": f"Enrich: {ej.indicator}",
                "type": ej.indicator_type, "status": ej.status, "verdict": ej.verdict,
                "created_at": ej.created_at.isoformat() if ej.created_at else "",
                "finished_at": "", "error": "",
            })

    if not category or category == "report":
        rq = select(ReportJob)
        if status:
            rq = rq.where(ReportJob.status == status)
        for rj in db.execute(rq.order_by(ReportJob.created_at.desc()).limit(size)).scalars():
            items.append({
                "id": rj.id, "category": "report", "name": f"Report: {rj.kind} ({rj.fmt})",
                "type": rj.kind, "status": rj.status, "verdict": "",
                "created_at": rj.created_at.isoformat() if rj.created_at else "",
                "finished_at": rj.finished_at.isoformat() if rj.finished_at else "",
                "error": rj.error,
            })

    if not category or category == "automation":
        aq = select(AutomationRun)
        if status:
            aq = aq.where(AutomationRun.status == status)
        for ar in db.execute(aq.order_by(AutomationRun.created_at.desc()).limit(size)).scalars():
            rule = db.get(AutomationRule, ar.rule_id)
            items.append({
                "id": ar.id, "category": "automation", "name": f"Rule: {rule.name if rule else ar.rule_id[:8]}",
                "type": "automation_run", "status": ar.status,
                "verdict": "matched" if ar.matched else "no_match",
                "created_at": ar.created_at.isoformat() if ar.created_at else "",
                "finished_at": "", "error": "",
            })

    if not category or category == "playbook":
        pq = select(PlaybookRun)
        if status:
            pq = pq.where(PlaybookRun.status == status)
        for pr in db.execute(pq.order_by(PlaybookRun.started_at.desc()).limit(size)).scalars():
            items.append({
                "id": pr.id, "category": "playbook", "name": f"Playbook run: {pr.trigger_ref}",
                "type": "playbook_run", "status": pr.status, "verdict": "",
                "created_at": pr.started_at.isoformat() if pr.started_at else "",
                "finished_at": pr.finished_at.isoformat() if pr.finished_at else "",
                "error": pr.error,
            })

    if not category or category == "backup":
        for bj in db.execute(select(BackupJob).order_by(BackupJob.name)).scalars():
            items.append({
                "id": bj.id, "category": "backup", "name": f"Backup: {bj.name}",
                "type": bj.component, "status": bj.last_status, "verdict": "",
                "created_at": bj.last_success_at.isoformat() if bj.last_success_at else "",
                "finished_at": "", "error": "",
            })

    items.sort(key=lambda x: x["created_at"] or "", reverse=True)
    start = (page - 1) * size
    page_items = items[start:start + size]
    return {"total": len(items), "items": page_items}


def list_schedules(db: Session) -> list[dict[str, Any]]:
    rows = []
    for s in db.execute(select(ReportSchedule).order_by(ReportSchedule.name)).scalars():
        rows.append({
            "id": s.id, "name": s.name, "kind": s.kind, "cadence": s.cadence,
            "hour": s.hour, "timezone": s.timezone, "fmt": s.fmt,
            "paused": s.paused,
            "next_run_at": s.next_run_at.isoformat() if s.next_run_at else "",
            "last_run_at": s.last_run_at.isoformat() if s.last_run_at else "",
            "last_status": s.last_status,
        })
    return rows


