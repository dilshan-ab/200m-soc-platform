"""Tamper-evident (hash-chained), append-only audit log."""
from __future__ import annotations

import threading
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import get_settings
from .models import AuditEvent, utcnow
from .security import canonical_json, hmac_sha256, sha256_hex

_lock = threading.Lock()
GENESIS = "0" * 64
_SENSITIVE = ("password", "secret", "token", "key", "totp", "authorization", "cookie")


def scrub(meta: dict[str, Any] | None) -> dict[str, Any]:
    """Remove secret-like values before they hit the audit log."""
    out: dict[str, Any] = {}
    for k, v in (meta or {}).items():
        if any(s in k.lower() for s in _SENSITIVE):
            out[k] = "[redacted]"
        elif isinstance(v, dict):
            out[k] = scrub(v)
        else:
            out[k] = v
    return out


def _digest(prev: str, e: AuditEvent) -> str:
    body = canonical_json(
        {
            "prev": prev,
            "ts": e.ts.isoformat(),
            "actor_id": e.actor_id,
            "actor": e.actor,
            "action": e.action,
            "rt": e.resource_type,
            "rid": e.resource_id,
            "outcome": e.outcome,
            "client_id": e.client_id,
            "cid": e.correlation_id,
            "meta": e.meta,
        }
    )
    key = get_settings().audit_hmac_key
    return hmac_sha256(key, body) if key else sha256_hex(body)


def record(
    db: Session,
    action: str,
    *,
    actor_id: str | None = None,
    actor: str = "system",
    resource_type: str = "",
    resource_id: str = "",
    outcome: str = "success",
    client_id: str | None = None,
    correlation_id: str = "",
    ip: str = "",
    meta: dict[str, Any] | None = None,
) -> AuditEvent:
    with _lock:
        last = db.execute(select(AuditEvent).order_by(AuditEvent.id.desc()).limit(1)).scalar_one_or_none()
        prev = last.hash if last else GENESIS
        e = AuditEvent(
            ts=utcnow(), actor_id=actor_id, actor=actor, action=action, resource_type=resource_type,
            resource_id=str(resource_id), outcome=outcome, client_id=client_id, correlation_id=correlation_id,
            ip=ip, meta=scrub(meta), prev_hash=prev,
        )
        e.hash = _digest(prev, e)
        db.add(e)
        db.flush()
    return e


def verify_chain(db: Session) -> dict[str, Any]:
    prev = GENESIS
    n = 0
    for e in db.execute(select(AuditEvent).order_by(AuditEvent.id)).scalars():
        if e.prev_hash != prev or _digest(prev, e) != e.hash:
            return {"ok": False, "broken_at": e.id, "checked": n}
        prev = e.hash
        n += 1
    return {"ok": True, "checked": n, "head": prev}
