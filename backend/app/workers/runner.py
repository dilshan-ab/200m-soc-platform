"""In-process background scheduler (threads). Also runnable standalone: python -m app.workers.runner"""
from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from datetime import timedelta
from typing import Any, cast

from fastapi import FastAPI
from sqlalchemy import delete, select
from sqlalchemy.engine import CursorResult

from ..config import get_settings
from ..db import session_factory, session_scope
from ..models import Alert, EnrichmentJob, OidcState, ReportJob, RetentionPolicy, SessionRecord, WebhookReplay, utcnow
from ..services import events, notifications, polling, reports, response
from ..sla import check_breaches

_last_low_clear_date: str | None = None

log = logging.getLogger("soc.workers")


def clear_low_alerts() -> int:
    """Auto-resolve low and info severity alerts once per day."""
    global _last_low_clear_date
    today = utcnow().strftime("%Y-%m-%d")
    if _last_low_clear_date == today:
        return 0
    with session_scope() as db:
        stale = db.execute(
            select(Alert).where(
                Alert.severity.in_(["low", "info"]),
                Alert.status.notin_(["resolved", "false_positive"]),
            )
        ).scalars().all()
        now = utcnow()
        for a in stale:
            a.status = "resolved"
            a.resolved_at = now
            if a.acknowledged_at is None:
                a.acknowledged_at = now
            a.version += 1
        count = len(stale)
    _last_low_clear_date = today
    if count:
        log.info("daily cleanup: resolved %d low/info alerts", count)
    return count


def tick_maintenance() -> None:
    with session_scope() as db:
        for a in check_breaches(db):
            events.publish(db, "sla.breached", id=a.id, severity=a.severity, client_id=a.client_id)
        notifications.escalate_pending(db)
        response.revert_due(db)
        response.reconcile_stale(db)
        reports.run_due_schedules(db)
        now = utcnow()
        db.execute(delete(OidcState).where(OidcState.expires_at < now))
        db.execute(delete(WebhookReplay).where(WebhookReplay.seen_at < now - timedelta(hours=1)))
        db.execute(delete(SessionRecord).where(SessionRecord.expires_at < now - timedelta(days=7)))
    clear_low_alerts()


def apply_retention() -> dict[str, int]:
    """Delete data past retention (never when legal hold is set; audit is never deleted before its policy)."""
    out: dict[str, int] = {}
    with session_scope() as db:
        now = utcnow()
        for pol in db.execute(select(RetentionPolicy)).scalars():
            if pol.legal_hold:
                continue
            cutoff = now - timedelta(days=pol.days)
            if pol.dataset == "alerts":
                r = db.execute(delete(Alert).where(Alert.time < cutoff, Alert.case_id.is_(None), Alert.status.in_(["resolved", "false_positive"])))
            elif pol.dataset == "reports":
                r = db.execute(delete(ReportJob).where(ReportJob.created_at < cutoff))
            elif pol.dataset == "raw_events":
                r = db.execute(delete(EnrichmentJob).where(EnrichmentJob.created_at < cutoff))
            elif pol.dataset == "audit":
                continue  # audit is chained; pruning requires an explicit, approved archive-and-truncate procedure
            else:
                continue
            out[pol.dataset] = cast(CursorResult[Any], r).rowcount or 0
    return out


class Worker(threading.Thread):
    def __init__(self, name: str, interval: float, fn: Callable[[], object], stop: threading.Event) -> None:
        super().__init__(name=name, daemon=True)
        self.interval, self.fn, self.stop_ev = interval, fn, stop

    def run(self) -> None:
        while not self.stop_ev.is_set():
            try:
                self.fn()
            except Exception:
                log.exception("worker %s failed", self.name)
            self.stop_ev.wait(self.interval)


def start_workers(app: FastAPI) -> None:
    s = get_settings()
    if not s.workers_enabled:
        return
    stop = threading.Event()
    sf = session_factory()
    ws = [
        Worker("outbox", s.outbox_tick_seconds, lambda: events.dispatch_once(sf), stop),
        Worker("poll", s.poll_tick_seconds, lambda: polling.poll_due(sf), stop),
        Worker("maintenance", 30, tick_maintenance, stop),
    ]
    for w in ws:
        w.start()
    app.state.worker_stop, app.state.workers = stop, ws


def stop_workers(app: FastAPI) -> None:
    stop = getattr(app.state, "worker_stop", None)
    if stop is not None:
        stop.set()
        for w in getattr(app.state, "workers", []):
            w.join(timeout=5)


if __name__ == "__main__":  # pragma: no cover
    logging.basicConfig(level=logging.INFO)
    stop_ev = threading.Event()
    sf = session_factory()
    for w in (Worker("outbox", 2, lambda: events.dispatch_once(sf), stop_ev), Worker("poll", 5, lambda: polling.poll_due(sf), stop_ev), Worker("maintenance", 30, tick_maintenance, stop_ev)):
        w.start()
    while True:
        time.sleep(3600)
