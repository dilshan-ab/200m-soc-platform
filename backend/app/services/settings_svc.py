from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from ..models import Setting, User, utcnow

DEFAULTS: dict[str, Any] = {
    "response_kill_switch": False,
    "response_policy_version": 1,
    "protected_targets": [],
    "response_max_per_hour": 20,
    "alert_dedup_minutes": 10,
    "reputation_dedup_minutes": 60,
    "approval_window_minutes": 240,
    "severity_labels": {"info": "Info", "low": "Low", "medium": "Medium", "high": "High", "critical": "Critical"},
}


def get_setting(db: Session, key: str, default: Any = None) -> Any:
    row = db.get(Setting, key)
    if row is not None:
        return row.value
    return DEFAULTS.get(key, default)


def set_setting(db: Session, key: str, value: Any) -> None:
    row = db.get(Setting, key)
    if row is None:
        db.add(Setting(key=key, value=value))
    else:
        row.value = value
        row.version += 1
        row.updated_at = utcnow()
    db.flush()


SYSTEM_SUBJECT = "system:automation"


def system_user(db: Session) -> User:
    from sqlalchemy import select

    u = db.execute(select(User).where(User.subject == SYSTEM_SUBJECT)).scalar_one_or_none()
    if u is None:
        u = User(subject=SYSTEM_SUBJECT, email="automation@system.invalid", name="Automation", role="l1", active=False, all_clients=True)
        db.add(u)
        db.flush()
    return u
