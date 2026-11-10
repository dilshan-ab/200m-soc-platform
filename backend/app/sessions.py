"""Server-side session lifecycle."""
from __future__ import annotations

from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import get_settings
from .models import SessionRecord, User, utcnow
from .security import new_token, sha256_hex


def cookie_name() -> str:
    return "__Host-soc_session" if get_settings().cookie_secure else "soc_session"


def create_session(db: Session, user: User, *, ip: str, user_agent: str, step_up: bool = False, oidc_sid: str | None = None) -> tuple[str, SessionRecord]:
    s = get_settings()
    now = utcnow()
    active = list(
        db.execute(
            select(SessionRecord)
            .where(SessionRecord.user_id == user.id, SessionRecord.revoked.is_(False), SessionRecord.expires_at > now)
            .order_by(SessionRecord.created_at)
        ).scalars()
    )
    while len(active) >= s.max_sessions_per_user:
        active.pop(0).revoked = True
    raw = new_token(32)
    rec = SessionRecord(
        sid_hash=sha256_hex(raw), user_id=user.id, csrf_token=new_token(24), created_at=now, last_seen_at=now,
        expires_at=now + timedelta(hours=s.session_absolute_hours), ip=ip[:64], user_agent=user_agent[:255],
        step_up_until=(now + timedelta(minutes=s.step_up_minutes)) if step_up else None, oidc_sid=oidc_sid,
    )
    db.add(rec)
    db.flush()
    return raw, rec


def load_session(db: Session, raw: str) -> SessionRecord | None:
    s = get_settings()
    rec = db.execute(select(SessionRecord).where(SessionRecord.sid_hash == sha256_hex(raw))).scalar_one_or_none()
    if rec is None or rec.revoked:
        return None
    now = utcnow()
    if now >= rec.expires_at or now - rec.last_seen_at > timedelta(minutes=s.session_idle_minutes):
        rec.revoked = True
        return None
    if now - rec.last_seen_at > timedelta(seconds=30):
        rec.last_seen_at = now
    return rec


def revoke_all(db: Session, user_id: str) -> int:
    n = 0
    for rec in db.execute(select(SessionRecord).where(SessionRecord.user_id == user_id, SessionRecord.revoked.is_(False))).scalars():
        rec.revoked = True
        n += 1
    return n
