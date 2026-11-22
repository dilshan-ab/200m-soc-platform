"""Checkpointed connector pollers + ingestion of webhook payloads."""
from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..connectors.base import ConnectorError, NormAlert
from ..models import Tool, utcnow
from . import ingest, tools_svc

log = logging.getLogger("soc.polling")
POLLABLE = {"poll_alerts", "poll_assets", "poll_findings"}


def ingest_batch(db: Session, tool: Tool, alerts: list[NormAlert]) -> int:
    created = 0
    for n in alerts:
        a, new = ingest.ingest_alert(db, tool, n)
        if new:
            created += 1
            ingest.handle_infra_status(db, a)
    return created


def poll_tool(db: Session, tool: Tool) -> dict[str, Any]:
    st = tools_svc.ensure_state(db, tool)
    now = utcnow()
    st.last_attempt_at = now
    try:
        conn = tools_svc.build_connector(db, tool)
        try:
            res = conn.poll(dict(st.checkpoint or {}), limit=500)
        finally:
            conn.close()
    except ConnectorError as e:
        st.error_count += 1
        st.last_error = str(e)[:500]
        return {"ok": False, "error": st.last_error}
    created = ingest_batch(db, tool, res.alerts)
    assets = ingest.upsert_assets(db, tool, res.assets) if res.assets else 0
    findings = ingest.upsert_findings(db, tool, res.findings) if res.findings else 0
    st.checkpoint = res.checkpoint or st.checkpoint
    st.last_success_at, st.error_count, st.last_error = now, 0, ""
    day = now.strftime("%Y-%m-%d")
    if st.items_day != day:
        st.items_day, st.items_today = day, 0
    st.items_today += created
    st.items_total += created
    newest = max((a.time for a in res.alerts if a.time), default=None)
    st.lag_seconds = max(0, int((now - newest).total_seconds())) if newest else 0
    return {"ok": True, "alerts": len(res.alerts), "created": created, "assets": assets, "findings": findings}


def is_due(tool: Tool) -> bool:
    st = tool.state
    if st is None or st.last_attempt_at is None:
        return True
    interval = max(tool.poll_interval, 5)
    backoff = min(interval * (2 ** min(st.error_count, 6)), 900) if st.error_count else interval
    return utcnow() >= st.last_attempt_at + timedelta(seconds=backoff)


def poll_due(session_factory: Callable[[], Session]) -> int:
    from ..connectors.base import get_connector_cls

    db = session_factory()
    try:
        ids = [t.id for t in db.execute(select(Tool).where(Tool.enabled.is_(True))).scalars() if POLLABLE & set(get_connector_cls(t.type).manifest.capabilities) and is_due(t)]
    finally:
        db.close()
    n = 0
    for tid in ids:
        s = session_factory()
        try:
            t = s.get(Tool, tid)
            if t is not None and t.enabled:
                poll_tool(s, t)
                s.commit()
                n += 1
        except Exception:
            s.rollback()
            log.exception("poll failed for %s", tid)
        finally:
            s.close()
    return n
