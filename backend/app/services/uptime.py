"""Uptime monitoring: async HTTP checks for 2000+ sites, 2-day retention."""
from __future__ import annotations

import logging
import time
from collections.abc import Callable
from datetime import timedelta

import httpx
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from ..db import session_scope
from ..models import UptimeCheck, UptimeMonitor, utcnow
from . import events

log = logging.getLogger("soc.uptime")

BATCH_SIZE = 200
RETENTION_DAYS = 2


def _check_one(client: httpx.Client, m: UptimeMonitor) -> tuple[str, int | None, int | None, str | None]:
    try:
        t0 = time.monotonic()
        r = client.request(m.method, m.url, headers=m.headers or {}, timeout=m.timeout_seconds, follow_redirects=True)
        elapsed_ms = int((time.monotonic() - t0) * 1000)
        if r.status_code == m.expected_status or (m.expected_status == 200 and 200 <= r.status_code < 400):
            status = "degraded" if elapsed_ms > 5000 else "up"
        else:
            status = "down"
        return status, r.status_code, elapsed_ms, None
    except httpx.TimeoutException:
        return "down", None, None, "timeout"
    except httpx.ConnectError as e:
        return "down", None, None, f"connect error: {type(e).__name__}"
    except httpx.HTTPError as e:
        return "down", None, None, str(e)[:500]


def run_checks(sf: Callable[[], Session]) -> None:
    with session_scope() as db:
        monitors = list(db.execute(select(UptimeMonitor).where(UptimeMonitor.enabled.is_(True))).scalars())

    if not monitors:
        return

    with httpx.Client(verify=False, limits=httpx.Limits(max_connections=BATCH_SIZE, max_keepalive_connections=50)) as client:
        for i in range(0, len(monitors), BATCH_SIZE):
            batch = monitors[i:i + BATCH_SIZE]
            results: list[tuple[UptimeMonitor, str, int | None, int | None, str | None]] = []
            for m in batch:
                status, code, rt, err = _check_one(client, m)
                results.append((m, status, code, rt, err))

            with session_scope() as db:
                now = utcnow()
                for m, status, code, rt, err in results:
                    mon = db.get(UptimeMonitor, m.id)
                    if mon is None:
                        continue
                    db.add(UptimeCheck(monitor_id=mon.id, status=status, status_code=code, response_time_ms=rt, error=err, checked_at=now))

                    was_down = mon.status == "down"
                    was_up = mon.status in ("up", "unknown")

                    if status == "down":
                        mon.consecutive_failures += 1
                        if mon.consecutive_failures >= mon.fail_threshold and not was_down:
                            mon.status = "down"
                            mon.last_status_change = now
                            events.publish(db, "uptime.down", id=mon.id, name=mon.name, url=mon.url, client_id=mon.client_id, error=err)
                            log.warning("site down: %s (%s)", mon.name, mon.url)
                    else:
                        if was_down:
                            events.publish(db, "uptime.recovered", id=mon.id, name=mon.name, url=mon.url, client_id=mon.client_id)
                            log.info("site recovered: %s (%s)", mon.name, mon.url)
                            mon.last_status_change = now
                        mon.consecutive_failures = 0
                        mon.status = status

                    mon.last_checked_at = now

    log.debug("checked %d monitors", len(monitors))


def purge_old_checks() -> int:
    cutoff = utcnow() - timedelta(days=RETENTION_DAYS)
    with session_scope() as db:
        r = db.execute(delete(UptimeCheck).where(UptimeCheck.checked_at < cutoff))
        count = r.rowcount or 0
    if count:
        log.info("purged %d old uptime checks (>%d days)", count, RETENTION_DAYS)
    return count
