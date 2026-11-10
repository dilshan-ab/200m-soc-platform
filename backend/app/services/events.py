"""Transactional outbox + event fan-out (SSE hub, optional Redis Streams)."""
from __future__ import annotations

import asyncio
import logging
import queue
import threading
from collections.abc import Callable
from datetime import timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..models import Outbox, utcnow

log = logging.getLogger("soc.events")
Handler = Callable[[Session, dict[str, Any]], None]
HANDLERS: dict[str, Handler] = {}
MAX_ATTEMPTS = 8
STREAM = "soc:events"


def handler(kind: str) -> Callable[[Handler], Handler]:
    def deco(fn: Handler) -> Handler:
        HANDLERS[kind] = fn
        return fn

    return deco


def enqueue(db: Session, kind: str, payload: dict[str, Any], delay_seconds: int = 0) -> Outbox:
    row = Outbox(kind=kind, payload=payload, run_after=utcnow() + timedelta(seconds=delay_seconds))
    db.add(row)
    db.flush()
    return row


def publish(db: Session, type_: str, **payload: Any) -> None:
    """Record a domain event atomically with the business change."""
    enqueue(db, "event", {"type": type_, **payload})


# ------------------------------------------------------------------ SSE hub
class Hub:
    """Fan-out of identifier-only events to SSE subscribers.

    Thread subscribers get a ``queue.Queue``; async subscribers (the SSE endpoint) pass their event loop and
    get an ``asyncio.Queue``, so an open stream never occupies a worker thread.
    """

    def __init__(self) -> None:
        self._subs: set[tuple[Any, Callable[[dict[str, Any]], bool], asyncio.AbstractEventLoop | None]] = set()
        self._lock = threading.Lock()

    def subscribe(self, allow: Callable[[dict[str, Any]], bool], loop: asyncio.AbstractEventLoop | None = None) -> Any:
        q: Any = asyncio.Queue(maxsize=200) if loop is not None else queue.Queue(maxsize=200)
        with self._lock:
            self._subs.add((q, allow, loop))
        return q

    def unsubscribe(self, q: Any) -> None:
        with self._lock:
            self._subs = {s for s in self._subs if s[0] is not q}

    @staticmethod
    def _put_async(q: Any, ev: dict[str, Any]) -> None:
        try:
            q.put_nowait(ev)
        except asyncio.QueueFull:
            pass

    def broadcast(self, ev: dict[str, Any]) -> None:
        with self._lock:
            subs = list(self._subs)
        for q, allow, loop in subs:
            if not allow(ev):
                continue
            if loop is not None:
                try:
                    loop.call_soon_threadsafe(self._put_async, q, ev)
                except RuntimeError:  # loop closed: subscriber is gone
                    self.unsubscribe(q)
            else:
                try:
                    q.put_nowait(ev)
                except queue.Full:
                    pass


hub = Hub()

_redis: Any = None


def set_redis(client: Any) -> None:
    global _redis
    _redis = client


def get_redis() -> Any:
    global _redis
    url = get_settings().redis_url
    if _redis is None and url:
        import redis

        _redis = redis.Redis.from_url(url, decode_responses=True)
    return _redis


@handler("event")
def _fanout(db: Session, ev: dict[str, Any]) -> None:
    # Only identifiers go to the browser (no alert content) - the UI refetches through authorised APIs.
    hub.broadcast({k: ev.get(k) for k in ("type", "id", "client_id", "severity")})
    r = get_redis()
    if r is not None:
        r.xadd(STREAM, {"type": str(ev.get("type")), "id": str(ev.get("id", "")), "client_id": str(ev.get("client_id") or "")}, maxlen=100_000, approximate=True)
    from . import automation, notifications

    automation.on_event(db, ev)
    notifications.on_event(db, ev)


def read_stream(group: str, consumer: str, count: int = 100) -> list[tuple[str, dict[str, str]]]:
    """Consume the Redis stream via a consumer group (used by external consumers and tests)."""
    r = get_redis()
    if r is None:
        return []
    try:
        r.xgroup_create(STREAM, group, id="0", mkstream=True)
    except Exception as e:  # BUSYGROUP
        if "BUSYGROUP" not in str(e):
            raise
    resp = r.xreadgroup(group, consumer, {STREAM: ">"}, count=count, block=10)
    out: list[tuple[str, dict[str, str]]] = []
    for _s, msgs in resp or []:
        for mid, data in msgs:
            out.append((mid, data))
            r.xack(STREAM, group, mid)
    return out


# ------------------------------------------------------------------ dispatcher
def dispatch_once(session_factory: Callable[[], Session], limit: int = 50) -> int:
    from ..db import session_scope  # noqa: F401

    done = 0
    db = session_factory()
    try:
        rows = list(
            db.execute(
                select(Outbox).where(Outbox.status == "pending", Outbox.run_after <= utcnow()).order_by(Outbox.id).limit(limit).with_for_update(skip_locked=True)
            ).scalars()
        )
        ids = [r.id for r in rows]
        db.commit()
    finally:
        db.close()
    for oid in ids:
        s = session_factory()
        try:
            row = s.get(Outbox, oid)
            if row is None or row.status != "pending":
                continue
            fn = HANDLERS.get(row.kind)
            try:
                if fn is None:
                    raise RuntimeError(f"no handler for {row.kind}")
                fn(s, row.payload)
                row.status = "done"
                s.commit()
                done += 1
            except Exception as e:
                s.rollback()
                row = s.get(Outbox, oid)
                if row is not None:
                    row.attempts += 1
                    row.last_error = f"{type(e).__name__}: {e}"[:400]
                    if row.attempts >= MAX_ATTEMPTS:
                        row.status = "dead"
                    else:
                        row.run_after = utcnow() + timedelta(seconds=min(2**row.attempts, 300))
                    s.commit()
                log.warning("outbox %s failed: %s", oid, e)
        finally:
            s.close()
    return done
