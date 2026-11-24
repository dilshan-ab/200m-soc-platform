"""The scheduled Sync with Keycloak: imports, role changes, users deleted in Keycloak, safety guards and status."""
from __future__ import annotations

from datetime import timedelta

from sqlalchemy import select

from app import db as dbmod
from app.config import reset_settings_cache
from app.db import session_factory
from app.models import ApiToken, AuditEvent, SessionRecord, User, utcnow
from app.services import keycloak_sync
from tests.test_keycloak_groups import kcg  # noqa: F401  (stateful fake Keycloak fixture)


def run():
    return keycloak_sync.run_scheduled(session_factory())


def linked(email, subject, role="viewer", active=True):
    with dbmod.session_scope() as db:
        u = User(subject=subject, email=email, name=email.split("@")[0], role=role, active=active)
        db.add(u)
        db.flush()
        return u.id


def with_session_and_token(uid):
    with dbmod.session_scope() as db:
        db.add(SessionRecord(sid_hash=f"h-{uid}", user_id=uid, csrf_token="c", expires_at=utcnow() + timedelta(hours=1)))
        db.add(ApiToken(user_id=uid, name="tok", token_hash=f"t-{uid}", prefix="soc_x", scopes=["alerts.read"], expires_at=utcnow() + timedelta(days=1)))


def row(uid):
    with dbmod.session_scope() as db:
        u = db.get(User, uid)
        db.expunge(u)
        return u


def test_off_outside_keycloak_or_when_interval_is_zero(monkeypatch):
    assert run() is None  # dev mode
    for k, v in {"SOC_AUTH_MODE": "oidc", "SOC_KC_ADMIN_URL": "http://keycloak:8080", "SOC_KC_ADMIN_CLIENT_SECRET": "svc", "SOC_KEYCLOAK_SYNC_MINUTES": "0",
                 "SOC_OIDC_ISSUER": "http://kc/realms/soc", "SOC_OIDC_CLIENT_ID": "soc-platform", "SOC_OIDC_CLIENT_SECRET": "s", "SOC_OIDC_REDIRECT_URI": "http://x/cb"}.items():
        monkeypatch.setenv(k, v)
    reset_settings_cache()
    try:
        assert run() is None
    finally:
        monkeypatch.undo()
        reset_settings_cache()


def test_imports_and_applies_role_changes_made_in_keycloak(kcg):  # noqa: F811
    kcg.add_user("new@t.local", groups=["SOC L2 Analysts"])
    moved = kcg.add_user("moved@t.local", groups=["SOC Admins"])
    uid = linked("moved@t.local", moved, role="viewer")
    with_session_and_token(uid)
    out = run()
    assert out["ok"] and out["imported"] == ["new@t.local"] and out["updated"] == ["moved@t.local"]
    assert row(uid).role == "admin"
    with dbmod.session_scope() as db:
        assert db.execute(select(SessionRecord).where(SessionRecord.user_id == uid)).scalar_one().revoked  # signed out on a role change
        ev = db.execute(select(AuditEvent).where(AuditEvent.action == "user.sync_import")).scalars().one()
        assert ev.actor == "system:keycloak-sync" and ev.actor_id is None


def test_user_deleted_in_keycloak_is_signed_out_and_disabled_not_deleted(kcg):  # noqa: F811
    keep = kcg.add_user("keep@t.local", groups=["SOC Viewers"])
    linked("keep@t.local", keep)
    kcg.add_user("a@t.local", groups=["SOC Viewers"])
    kcg.add_user("b@t.local", groups=["SOC Viewers"])
    gone = linked("gone@t.local", "kc-deleted", role="l1")
    with_session_and_token(gone)
    out = run()
    assert out["disabled"] == ["gone@t.local"] and out["removed"] == []
    u = row(gone)
    assert u is not None and u.active is False and u.email == "gone@t.local"  # kept, reversible
    with dbmod.session_scope() as db:
        assert db.execute(select(SessionRecord).where(SessionRecord.user_id == gone)).scalar_one().revoked
        assert db.execute(select(ApiToken).where(ApiToken.user_id == gone)).scalar_one().revoked
    assert run()["disabled"] == []  # an already disabled account is not reported again
    with dbmod.session_scope() as db:
        last = keycloak_sync.status(db)["last"]
    assert last["ok"] and last["source"] == "scheduled" and last["disabled_accounts"] == [] and last["orphans"] == ["gone@t.local"]


def test_does_not_disable_when_most_accounts_vanish_at_once(kcg):  # noqa: F811
    kcg.add_user("only@t.local", groups=["SOC Viewers"])
    ids = [linked(f"u{i}@t.local", f"kc-missing-{i}") for i in range(3)]
    out = run()
    assert out["disabled"] == []
    assert all(row(i).active for i in ids)
    with dbmod.session_scope() as db:
        last = keycloak_sync.status(db)["last"]
    assert last["ok"] is False and "not disabling them automatically" in last["error"]


def test_super_admin_is_never_disabled(kcg):  # noqa: F811
    kcg.add_user("x@t.local", groups=["SOC Viewers"])
    owner = linked("owner@t.local", "kc-owner-gone", role="superadmin")
    run()
    assert row(owner).active is True


def test_empty_keycloak_and_errors_change_nothing_and_are_reported(kcg):  # noqa: F811
    uid = linked("safe@t.local", "kc-safe")
    out = run()
    assert out["ok"] is False and row(uid).active is True
    kcg.deny_groups = True  # listing users needs the groups API too
    kcg.add_user("y@t.local", groups=["SOC Viewers"])
    out = run()
    assert out["ok"] is False and row(uid).active is True
    with dbmod.session_scope() as db:
        assert keycloak_sync.status(db)["last"]["ok"] is False


def test_status_endpoint_and_manual_sync_record(superadmin, kcg):  # noqa: F811
    st = superadmin.get("/api/admin/users/sync").json()
    assert st["enabled"] is True and st["interval_minutes"] == 15 and st["last"] is None
    kcg.add_user("m@t.local", groups=["SOC Viewers"])
    assert superadmin.post("/api/admin/users/sync", {}).status_code == 200
    last = superadmin.get("/api/admin/users/sync").json()["last"]
    assert last["source"] == "manual" and last["ok"] and last["imported"] == 1 and last["keycloak_users"] == 1
