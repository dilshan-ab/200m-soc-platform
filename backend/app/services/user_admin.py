"""Removing a user from SOC: end access, release work, and either delete the row or keep an anonymised tombstone."""
from __future__ import annotations

from sqlalchemy import delete, func, select, update
from sqlalchemy.orm import Session

from ..models import Base, User

TOMBSTONE_PREFIX = "deleted:"
_ASSIGNMENT_COLUMNS = {"assignee_id", "owner_id"}


def is_tombstone(u: User) -> bool:
    return u.subject.startswith(TOMBSTONE_PREFIX)


def _user_columns() -> tuple[list, list, list]:
    """Columns that reference users.id: (cascade, assignments that can be released, everything else)."""
    cascade, assign, other = [], [], []
    for table in Base.metadata.sorted_tables:
        for col in table.columns:
            for fk in col.foreign_keys:
                if fk.column.table.name != "users":
                    continue
                if (fk.ondelete or "").upper() == "CASCADE":
                    cascade.append(col)
                elif col.name in _ASSIGNMENT_COLUMNS and col.nullable:
                    assign.append(col)
                else:
                    other.append(col)
    return cascade, assign, other


def remove_user(db: Session, u: User) -> bool:
    """Revoke everything the user holds and remove them. Returns True when the row had to be kept as an anonymised
    "Deleted user" because requests, approvals or records they created still point at it; False when it was deleted.

    Sessions, API tokens, client memberships and saved views are deleted; alerts, cases, tasks and incidents assigned
    to them are unassigned. The audit log is never touched (it stores the actor's label, not a foreign key).
    """
    cascade, assign, other = _user_columns()
    db.flush()  # pending ORM changes (e.g. revoked sessions) must reach the database before bulk deletes remove those rows
    for col in cascade:
        db.execute(delete(col.table).where(col == u.id))
    for col in assign:
        db.execute(update(col.table).where(col == u.id).values({col.name: None}))
    db.flush()
    still_referenced = sum(db.execute(select(func.count()).select_from(col.table).where(col == u.id)).scalar_one() for col in other)
    if not still_referenced:
        db.delete(u)
        return False
    u.subject, u.email, u.name = f"{TOMBSTONE_PREFIX}{u.id}", f"deleted-{u.id[:8]}@deleted.invalid", "Deleted user"
    u.role, u.grants, u.denied, u.all_clients, u.active = "viewer", [], [], False, False
    u.password_hash = u.totp_secret = u.locked_until = None
    u.failed_logins = 0
    return True
