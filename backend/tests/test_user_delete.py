"""Deleting accounts (SOC + Keycloak) and reconciling SOC with Keycloak."""
from __future__ import annotations

import httpx
import pytest
from sqlalchemy import select

from app import db as dbmod
from app import keycloak_admin as kc
from app.api import auth as auth_api
from app.config import reset_settings_cache
from app.models import Alert, AuditEvent, ClientMembership, ReportJob, SessionRecord, User
from tests.conftest import make_user
from tests.helpers import mk_alert

KC = "http://keycloak:8080"


def _uid(email: str) -> str:
    with dbmod.session_scope() as db:
        return db.execute(select(User.id).where(User.email == email)).scalar_one()


def _row(uid: str) -> User | None:
    with dbmod.session_scope() as db:
        u = db.get(User, uid)
        if u is not None:
            db.expunge(u)
        return u


# --------------------------------------------------------------------------- development (local) accounts
def test_admin_deletes_account_with_no_history(admin, make_session):
    target = make_session("gone@t.local", "l1")
    uid = _uid("gone@t.local")
    assert target.get("/api/auth/me").status_code == 200
    r = admin.delete(f"/api/admin/users/{uid}")
    assert r.status_code == 200 and r.json() == {"deleted": True, "keycloak": "not_linked", "kept_as_deleted_user": False}
    assert _row(uid) is None
    assert uid not in [u["id"] for u in admin.get("/api/admin/users").json()]
    assert target.get("/api/auth/me").status_code == 401  # signed out immediately
    with dbmod.session_scope() as db:
        assert db.execute(select(SessionRecord).where(SessionRecord.user_id == uid)).first() is None
        ev = db.execute(select(AuditEvent).where(AuditEvent.action == "user.delete")).scalars().one()
        assert ev.meta["email"] == "gone@t.local" and ev.resource_id == uid
    assert admin.post("/api/admin/users", {"email": "gone@t.local", "password": "Str0ng-Passw0rd!x"}).status_code == 201  # the email is free again


def test_account_with_history_is_kept_as_anonymised_deleted_user(admin, make_session, clients):
    make_session("worker@t.local", "l2", client_ids=[clients[0]], all_clients=False)
    uid = _uid("worker@t.local")
    alert_id = mk_alert(client_id=clients[0])
    with dbmod.session_scope() as db:
        db.get(Alert, alert_id).assignee_id = uid
        db.add(ReportJob(kind="soc_metrics", requester_id=uid))  # history that must keep pointing at a user row
    r = admin.delete(f"/api/admin/users/{uid}")
    assert r.status_code == 200 and r.json()["kept_as_deleted_user"] is True
    u = _row(uid)
    assert u is not None and u.email.endswith("@deleted.invalid") and u.name == "Deleted user" and u.active is False
    assert u.password_hash is None and u.totp_secret is None and u.role == "viewer"
    with dbmod.session_scope() as db:
        assert db.get(Alert, alert_id).assignee_id is None  # open work is released
        assert db.execute(select(ClientMembership).where(ClientMembership.user_id == uid)).first() is None
        assert db.execute(select(ReportJob).where(ReportJob.requester_id == uid)).first() is not None
    assert uid not in [x["id"] for x in admin.get("/api/admin/users").json()]
    assert admin.delete(f"/api/admin/users/{uid}").status_code == 404  # already deleted


def test_delete_protections(admin, superadmin, make_session):
    me, owner = admin.get("/api/auth/me").json()["id"], superadmin.get("/api/auth/me").json()["id"]
    assert admin.delete(f"/api/admin/users/{me}").status_code == 403
    assert superadmin.delete(f"/api/admin/users/{owner}").status_code == 403
    assert admin.delete(f"/api/admin/users/{owner}").status_code == 403
    assert admin.delete("/api/admin/users/not-a-user").status_code == 404
    l2 = make_session("l2@t.local", "l2")
    victim = _uid("super@t.local")
    assert l2.delete(f"/api/admin/users/{victim}").status_code == 403
    assert _row(owner) is not None and _row(me) is not None


def test_super_admin_and_admins_can_delete_accounts(superadmin, admin, make_session):
    make_session("a@t.local", "admin")
    make_session("b@t.local", "viewer")
    assert superadmin.delete(f"/api/admin/users/{_uid('a@t.local')}").status_code == 200
    assert admin.delete(f"/api/admin/users/{_uid('b@t.local')}").status_code == 200


def test_delete_requires_recent_mfa(make_session):
    from app.models import SessionRecord as SR

    weak = make_session("stale-admin@t.local", "admin")
    make_user("victim@t.local", "viewer")
    weak.get("/api/auth/me")
    with dbmod.session_scope() as db:
        for s in db.execute(select(SR)).scalars():
            s.step_up_until = None
    r = weak.delete(f"/api/admin/users/{_uid('victim@t.local')}")
    assert r.status_code == 403 and "step_up_required" in r.text
    assert _row(_uid("victim@t.local")) is not None


def test_external_idp_accounts_must_be_removed_in_the_idp(admin, make_session, monkeypatch):
    uid = make_user("sso@t.local", "viewer")[0]
    for k, v in {"SOC_AUTH_MODE": "oidc", "SOC_OIDC_ISSUER": "http://kc/realms/soc", "SOC_OIDC_CLIENT_ID": "c", "SOC_OIDC_CLIENT_SECRET": "s", "SOC_OIDC_REDIRECT_URI": "http://x/cb"}.items():
        monkeypatch.setenv(k, v)
    reset_settings_cache()
    r = admin.delete(f"/api/admin/users/{uid}")
    assert r.status_code == 400 and "identity provider" in r.text
    assert _row(uid) is not None


# --------------------------------------------------------------------------- Keycloak
class FakeKeycloak:
    """Just enough of the Keycloak admin API: users, realm roles, delete, paging."""

    def __init__(self):
        self.users: dict[str, dict] = {}
        self.roles: dict[str, set[str]] = {r: set() for r in ("viewer", "l1", "l2", "admin", "superadmin")}
        self.calls: list[tuple[str, str]] = []
        self.fail_delete = 0

    def add(self, uid, email, role="viewer", enabled=True, first="", last=""):
        self.users[uid] = {"id": uid, "email": email, "username": email, "enabled": enabled, "firstName": first, "lastName": last}
        if role:
            self.roles[role].add(uid)

    def handler(self, req: httpx.Request) -> httpx.Response:
        p, q = req.url.path, req.url.params
        self.calls.append((req.method, p))
        if p.endswith("/openid-connect/token"):
            return httpx.Response(200, json={"access_token": "tok"})
        if req.method == "DELETE" and "/users/" in p:
            if self.fail_delete:
                return httpx.Response(self.fail_delete)
            uid = p.rsplit("/", 1)[-1]
            if uid not in self.users:
                return httpx.Response(404)
            del self.users[uid]
            for ids in self.roles.values():
                ids.discard(uid)
            return httpx.Response(204)
        if req.method == "GET":
            first, mx = int(q.get("first", 0)), int(q.get("max", 100))
            if "/roles/" in p and p.endswith("/users"):
                ids = sorted(self.roles[p.split("/roles/")[1].split("/")[0]])
                return httpx.Response(200, json=[self.users[i] for i in ids[first:first + mx] if i in self.users])
            if p.endswith("/users"):
                return httpx.Response(200, json=list(self.users.values())[first:first + mx])
            if p.endswith("/groups"):
                return httpx.Response(200, json=[])  # no groups exist; tests for groups use their own fake
        if req.method == "POST" and p.endswith("/groups"):
            return httpx.Response(403)  # creating groups is refused here: sync must carry on and report it
        return httpx.Response(404)


@pytest.fixture()
def keycloak(monkeypatch):
    for k, v in {"SOC_AUTH_MODE": "oidc", "SOC_KC_ADMIN_URL": KC, "SOC_KC_ADMIN_CLIENT_SECRET": "svc", "SOC_OIDC_ISSUER": "http://kc/realms/soc", "SOC_OIDC_CLIENT_ID": "c", "SOC_OIDC_CLIENT_SECRET": "s", "SOC_OIDC_REDIRECT_URI": "http://x/cb"}.items():
        monkeypatch.setenv(k, v)
    reset_settings_cache()
    fake = FakeKeycloak()
    auth_api.set_http(httpx.Client(transport=httpx.MockTransport(fake.handler)))
    yield fake
    auth_api.set_http(None)


def _linked(email, subject, role="viewer"):
    with dbmod.session_scope() as db:
        u = User(subject=subject, email=email, name=email.split("@")[0], role=role)
        db.add(u)
        db.flush()
        return u.id


def test_delete_removes_the_account_from_keycloak_then_soc(superadmin, keycloak):
    keycloak.add("kc-1", "linked@t.local")
    uid = _linked("linked@t.local", "kc-1")
    r = superadmin.delete(f"/api/admin/users/{uid}")
    assert r.status_code == 200 and r.json()["keycloak"] == "deleted"
    assert "kc-1" not in keycloak.users and _row(uid) is None
    assert ("DELETE", "/admin/realms/soc/users/kc-1") in keycloak.calls


def test_delete_succeeds_when_account_is_already_gone_from_keycloak(superadmin, keycloak):
    uid = _linked("ghost@t.local", "kc-missing")
    r = superadmin.delete(f"/api/admin/users/{uid}")
    assert r.status_code == 200 and r.json()["keycloak"] == "already_gone" and _row(uid) is None


def test_keycloak_failure_leaves_the_account_untouched(superadmin, keycloak):
    keycloak.add("kc-2", "stays@t.local")
    uid = _linked("stays@t.local", "kc-2")
    keycloak.fail_delete = 500
    r = superadmin.delete(f"/api/admin/users/{uid}")
    assert r.status_code == 502 and _row(uid) is not None and "kc-2" in keycloak.users
    keycloak.fail_delete = 0
    assert superadmin.delete(f"/api/admin/users/{uid}").status_code == 200  # retry works


def test_unlinked_local_account_is_deleted_without_touching_keycloak(superadmin, keycloak):
    keycloak.add("kc-same-email", "pending@t.local")  # a different identity that happens to share the email
    with dbmod.session_scope() as db:
        u = User(subject="pending:pending@t.local", email="pending@t.local", role="viewer")
        db.add(u)
        db.flush()
        uid = u.id
    r = superadmin.delete(f"/api/admin/users/{uid}")
    assert r.status_code == 200 and r.json()["keycloak"] == "not_linked"
    assert "kc-same-email" in keycloak.users and not [c for c in keycloak.calls if c[0] == "DELETE"]


def test_keycloak_not_configured_is_a_clear_error(superadmin, keycloak, monkeypatch):
    uid = _linked("x@t.local", "kc-x")
    monkeypatch.setenv("SOC_KC_ADMIN_CLIENT_SECRET", "")
    reset_settings_cache()
    r = superadmin.delete(f"/api/admin/users/{uid}")
    assert r.status_code in (400, 503) and _row(uid) is not None


# --------------------------------------------------------------------------- sync
def test_sync_imports_links_updates_and_lists_orphans(superadmin, keycloak):
    keycloak.add("kc-new", "new@t.local", "l2", first="Nia", last="Ng")
    keycloak.add("kc-link", "placeholder@t.local", "admin")
    keycloak.add("kc-change", "changed@t.local", "l1", enabled=False, first="Chad", last="Lee")
    keycloak.add("kc-norole", "norole@t.local", "")
    keycloak.add("kc-owner", "owner@t.local", "superadmin")
    keycloak.add("kc-me", "super@t.local", "superadmin")
    with dbmod.session_scope() as db:
        db.add(User(subject="pending:placeholder@t.local", email="placeholder@t.local", role="viewer", password_hash="x", totp_secret="y"))
    changed = _linked("changed@t.local", "kc-change", "viewer")
    orphan = _linked("removed-in-kc@t.local", "kc-gone", "l1")

    r = superadmin.post("/api/admin/users/sync", {})
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["imported"] == ["new@t.local"] and out["linked"] == ["placeholder@t.local"] and out["updated"] == ["changed@t.local"]
    assert out["orphans"] == ["removed-in-kc@t.local"] and out["removed"] == []  # listed, not removed
    assert {"email": "norole@t.local", "reason": "no SOC role in Keycloak"} in out["skipped"]
    assert not any("owner@t.local" in str(s) for s in out["skipped"])  # superadmin identities are left alone
    with dbmod.session_scope() as db:
        new = db.execute(select(User).where(User.email == "new@t.local")).scalar_one()
        assert (new.subject, new.role, new.name, new.active, new.all_clients) == ("kc-new", "l2", "Nia Ng", True, False)
        link = db.execute(select(User).where(User.email == "placeholder@t.local")).scalar_one()
        assert (link.subject, link.role, link.password_hash, link.totp_secret) == ("kc-link", "admin", None, None)
        ch = db.get(User, changed)
        assert (ch.role, ch.active, ch.name) == ("l1", False, "Chad Lee")
        assert db.get(User, orphan) is not None
        assert db.execute(select(User).where(User.email == "owner@t.local")).first() is None
    assert superadmin.post("/api/admin/users/sync", {}).json()["imported"] == []  # idempotent


def test_sync_prune_removes_only_accounts_missing_from_keycloak(superadmin, keycloak):
    keycloak.add("kc-keep", "keep@t.local", "l1")
    keep, orphan = _linked("keep@t.local", "kc-keep", "l1"), _linked("orphan@t.local", "kc-gone", "l1")
    local_only = make_user("localonly@t.local", "viewer")[0]  # dev: account, never linked: not an orphan
    out = superadmin.post("/api/admin/users/sync", {"prune": True}).json()
    assert out["removed"] == ["orphan@t.local"] and out["orphans"] == []
    assert _row(orphan) is None and _row(keep) is not None and _row(local_only) is not None
    with dbmod.session_scope() as db:
        assert db.execute(select(AuditEvent).where(AuditEvent.action == "user.sync_remove")).scalars().one().meta["email"] == "orphan@t.local"


def test_sync_refuses_to_change_anything_if_keycloak_returns_no_users(superadmin, keycloak):
    uid = _linked("safe@t.local", "kc-safe")
    r = superadmin.post("/api/admin/users/sync", {"prune": True})
    assert r.status_code == 409 and _row(uid) is not None


def test_sync_requires_privilege_and_oidc(admin, make_session, monkeypatch):
    assert admin.post("/api/admin/users/sync", {}).status_code == 400  # dev mode: nothing to sync with
    viewer = make_session("v@t.local", "viewer")
    assert viewer.post("/api/admin/users/sync", {}).status_code == 403


def test_keycloak_listing_pages_through_all_users():
    fake = FakeKeycloak()
    for i in range(250):
        fake.add(f"id{i}", f"u{i}@t.local", "viewer" if i % 2 else "l1")
    client = httpx.Client(transport=httpx.MockTransport(fake.handler))
    import os

    os.environ.update({"SOC_KC_ADMIN_URL": KC, "SOC_KC_ADMIN_CLIENT_SECRET": "svc"})
    reset_settings_cache()
    try:
        rows = kc.list_users(client)
    finally:
        os.environ.pop("SOC_KC_ADMIN_URL"), os.environ.pop("SOC_KC_ADMIN_CLIENT_SECRET")
        reset_settings_cache()
    assert len(rows) == 250 and {r["role"] for r in rows} == {"viewer", "l1"} and rows[0]["email"] == "u0@t.local"
