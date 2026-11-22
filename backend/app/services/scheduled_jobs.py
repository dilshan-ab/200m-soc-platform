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
        q = select(EnrichmentJob)
        if status:
            q = q.where(EnrichmentJob.status == status)
        for j in db.execute(q.order_by(EnrichmentJob.created_at.desc()).limit(size)).scalars():
            items.append({
                "id": j.id, "category": "enrichment", "name": f"Enrich: {j.indicator}",
                "type": j.indicator_type, "status": j.status, "verdict": j.verdict,
                "created_at": j.created_at.isoformat() if j.created_at else "",
                "finished_at": "", "error": "",
            })

    if not category or category == "report":
        q = select(ReportJob)
        if status:
            q = q.where(ReportJob.status == status)
        for j in db.execute(q.order_by(ReportJob.created_at.desc()).limit(size)).scalars():
            items.append({
                "id": j.id, "category": "report", "name": f"Report: {j.kind} ({j.fmt})",
                "type": j.kind, "status": j.status, "verdict": "",
                "created_at": j.created_at.isoformat() if j.created_at else "",
                "finished_at": j.finished_at.isoformat() if j.finished_at else "",
                "error": j.error,
            })

    if not category or category == "automation":
        q = select(AutomationRun)
        if status:
            q = q.where(AutomationRun.status == status)
        for r in db.execute(q.order_by(AutomationRun.created_at.desc()).limit(size)).scalars():
            rule = db.get(AutomationRule, r.rule_id)
            items.append({
                "id": r.id, "category": "automation", "name": f"Rule: {rule.name if rule else r.rule_id[:8]}",
                "type": "automation_run", "status": r.status,
                "verdict": "matched" if r.matched else "no_match",
                "created_at": r.created_at.isoformat() if r.created_at else "",
                "finished_at": "", "error": "",
            })

    if not category or category == "playbook":
        q = select(PlaybookRun)
        if status:
            q = q.where(PlaybookRun.status == status)
        for r in db.execute(q.order_by(PlaybookRun.started_at.desc()).limit(size)).scalars():
            items.append({
                "id": r.id, "category": "playbook", "name": f"Playbook run: {r.trigger_ref}",
                "type": "playbook_run", "status": r.status, "verdict": "",
                "created_at": r.started_at.isoformat() if r.started_at else "",
                "finished_at": r.finished_at.isoformat() if r.finished_at else "",
                "error": r.error,
            })

    if not category or category == "backup":
        for j in db.execute(select(BackupJob).order_by(BackupJob.name)).scalars():
            items.append({
                "id": j.id, "category": "backup", "name": f"Backup: {j.name}",
                "type": j.component, "status": j.last_status, "verdict": "",
                "created_at": j.last_success_at.isoformat() if j.last_success_at else "",
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


