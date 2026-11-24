"""Reconciling SOC accounts with Keycloak, shared by the Sync with Keycloak button and the scheduled sync."""
from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit
from .. import keycloak_admin as kc
from ..config import get_settings
from ..models import ApiToken, User, utcnow
from ..sessions import revoke_all
from . import user_admin
from .settings_svc import get_setting, set_setting

log = logging.getLogger("soc.keycloak_sync")
STATUS_KEY = "keycloak_sync_status"
SYSTEM_ACTOR = "system:keycloak-sync"


def available() -> bool:
    """True when users are managed in the bundled Keycloak and the admin API is configured."""
    s = get_settings()
    return s.auth_mode == "oidc" and bool(s.kc_admin_url) and kc.configured()


def _local(u: User) -> bool:
    return u.subject.startswith(("dev:", "pending:"))


def reconcile(db: Session, remote: list[dict[str, Any]], *, actor: str, actor_id: str | None, ip: str = "",
              self_id: str | None = None, prune: bool = False, disable_orphans: bool = False) -> dict[str, Any]:
    """Apply Keycloak's users to SOC: import new ones, link local placeholders, and take name, role and enabled state from
    Keycloak. Accounts whose Keycloak identity is gone ("orphans") are listed; `disable_orphans` signs them out and disables
    them (reversible), `prune` removes them. The super admin and the acting user are never changed."""
    def rec(action: str, u: User, meta: dict[str, Any]) -> None:
        audit.record(db, action, actor=actor, actor_id=actor_id, resource_type="user", resource_id=u.id, ip=ip, meta=meta)

    by_id = {r["id"]: r for r in remote}
    local = {u.subject: u for u in db.execute(select(User).where(User.subject != "system:automation")).scalars() if not user_admin.is_tombstone(u)}
    by_email = {u.email: u for u in local.values()}
    imported: list[str] = []
    linked: list[str] = []
    updated: list[str] = []
    skipped: list[dict[str, str]] = []
    for r in remote:
        if r["role"] == "superadmin" or r["role"] == "" or not r["email"]:
            if r["role"] != "superadmin":
                skipped.append({"email": r["email"] or r["id"], "reason": "no SOC role in Keycloak" if r["email"] else "no email"})
            continue
        u = local.get(r["id"])
        if u is None:
            existing = by_email.get(r["email"])
            if existing is not None and not _local(existing):
                skipped.append({"email": r["email"], "reason": "email belongs to a different Keycloak identity"})
                continue
            if existing is not None:  # a local placeholder: link it to its Keycloak account, which now owns its credentials
                existing.subject, existing.password_hash, existing.totp_secret = r["id"], None, None
                u = existing
                linked.append(r["email"])
            else:
                u = User(subject=r["id"], email=r["email"], name=r["name"], role=r["role"], active=r["enabled"], all_clients=False)
                db.add(u)
                db.flush()
                imported.append(r["email"])
                rec("user.sync_import", u, {"email": r["email"], "role": r["role"]})
                continue
        if u.role == "superadmin" or u.id == self_id:
            continue
        changes: dict[str, Any] = {}
        if u.role != r["role"]:
            changes["role"] = r["role"]
        if u.active != r["enabled"]:
            changes["active"] = r["enabled"]
        if r["name"] and u.name != r["name"]:
            changes["name"] = r["name"]
        if u.email != r["email"] and not db.execute(select(User.id).where(User.email == r["email"], User.id != u.id)).first():
            changes["email"] = r["email"]
        if changes:
            for k, v in changes.items():
                setattr(u, k, v)
            if "role" in changes or "active" in changes or "email" in changes:
                revoke_all(db, u.id)
            if r["email"] not in linked:
                updated.append(r["email"])
            rec("user.sync_update", u, {"email": r["email"], "changes": list(changes)})
    unlinked = sorted(u.email for u in local.values() if _local(u) and u.active)  # in SOC but never created in Keycloak
    # judged on the subject each account had before this run: a placeholder linked just now is not an orphan
    orphans = [u for sub, u in local.items() if not sub.startswith(("dev:", "pending:")) and sub not in by_id and u.role != "superadmin" and u.id != self_id]
    removed: list[str] = []
    disabled: list[str] = []
    if prune:
        for u in orphans:
            email = u.email
            revoke_all(db, u.id)
            anonymised = user_admin.remove_user(db, u)
            removed.append(email)
            rec("user.sync_remove", u, {"email": email, "kept_as_deleted_user": anonymised})
    elif disable_orphans:
        for u in orphans:
            if not u.active:
                continue
            u.active = False
            revoke_all(db, u.id)
            for t in db.execute(select(ApiToken).where(ApiToken.user_id == u.id, ApiToken.revoked.is_(False))).scalars():
                t.revoked = True
            disabled.append(u.email)
            rec("user.sync_disable", u, {"email": u.email, "reason": "no longer in Keycloak"})
    return {"imported": imported, "linked": linked, "updated": updated, "skipped": skipped, "removed": removed, "disabled": disabled,
            "orphans": [] if prune else [u.email for u in orphans], "unlinked": unlinked}


def record_status(db: Session, source: str, ok: bool, *, error: str = "", result: dict[str, Any] | None = None, keycloak_users: int | None = None) -> None:
    r = result or {}
    set_setting(db, STATUS_KEY, {
        "at": utcnow().isoformat(), "source": source, "ok": ok, "error": error[:300], "keycloak_users": keycloak_users,
        **{k: len(r.get(k, [])) for k in ("imported", "linked", "updated", "disabled", "removed")},
        "orphans": r.get("orphans", []), "disabled_accounts": r.get("disabled", []), "unlinked": r.get("unlinked", []),
    })


def status(db: Session) -> dict[str, Any]:
    s = get_settings()
    return {"enabled": available() and s.keycloak_sync_minutes > 0, "interval_minutes": s.keycloak_sync_minutes, "last": get_setting(db, STATUS_KEY)}


def run_scheduled(session_factory: Callable[[], Session]) -> dict[str, Any] | None:
    """One scheduled sync: users only (groups and permissions are refreshed by the button and by permission changes).
    Users deleted in Keycloak are signed out and disabled, never deleted. Returns the result, or None when sync is off."""
    if not available() or get_settings().keycloak_sync_minutes <= 0:
        return None
    from ..api.auth import get_http

    db = session_factory()
    try:
        try:
            remote = kc.list_users(get_http())
        except kc.KcError as e:
            record_status(db, "scheduled", False, error=str(e))
            db.commit()
            log.warning("scheduled Keycloak sync failed: %s", e)
            return {"ok": False, "error": str(e)}
        if not remote:
            record_status(db, "scheduled", False, error="Keycloak returned no users; nothing was changed", keycloak_users=0)
            db.commit()
            return {"ok": False, "error": "Keycloak returned no users"}
        ids = {r["id"] for r in remote}
        linked_users = [u for u in db.execute(select(User).where(User.subject != "system:automation")).scalars()
                        if not _local(u) and not user_admin.is_tombstone(u) and u.role != "superadmin"]
        linked_total, n = len(linked_users), sum(1 for u in linked_users if u.subject not in ids)
        if n > 1 and n > linked_total / 2:  # most accounts vanished at once: more likely a Keycloak problem than real deletions
            result = reconcile(db, remote, actor=SYSTEM_ACTOR, actor_id=None)
            record_status(db, "scheduled", False, result=result, keycloak_users=len(remote),
                          error=f"{n} of {linked_total} accounts are missing from Keycloak; not disabling them automatically. Check Keycloak, then run Sync with Keycloak.")
        else:
            result = reconcile(db, remote, actor=SYSTEM_ACTOR, actor_id=None, disable_orphans=True)
            record_status(db, "scheduled", True, result=result, keycloak_users=len(remote))
        db.commit()
        return {"ok": True, **result}
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
