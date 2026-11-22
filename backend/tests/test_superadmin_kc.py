"""Super admin provisioning through the Keycloak Admin API (mocked)."""
from __future__ import annotations

import json

import httpx
import pytest

from app.api import auth as auth_api
from app.config import reset_settings_cache

PASSWORD = "Str0ng-Passw0rd!x"

KC = "http://keycloak:8080"


@pytest.fixture()
def kc(monkeypatch):
    for k, v in {"SOC_AUTH_MODE": "oidc", "SOC_KC_ADMIN_URL": KC, "SOC_KC_ADMIN_CLIENT_SECRET": "svc-secret", "SOC_OIDC_ISSUER": "http://kc/realms/soc", "SOC_OIDC_CLIENT_ID": "c", "SOC_OIDC_CLIENT_SECRET": "s", "SOC_OIDC_REDIRECT_URI": "http://x/cb"}.items():
        monkeypatch.setenv(k, v)
    reset_settings_cache()
    calls: list[tuple[str, str, object]] = []
    remote_user = {"id": "kc-123"}

    def handler(req: httpx.Request) -> httpx.Response:
        p = req.url.path
        body = json.loads(req.content) if req.content and req.headers.get("content-type", "").startswith("application/json") else None
        calls.append((req.method, p, body))
        if p.endswith("/openid-connect/token"):
            assert b"client_credentials" in req.content
            return httpx.Response(200, json={"access_token": "tok"})
        assert req.headers["authorization"] == "Bearer tok"
        if req.method == "GET" and "/roles/" in p:
            return httpx.Response(200, json={"id": "r1", "name": p.rsplit("/", 1)[-1]})
        if req.method == "GET" and p.endswith("/users/kc-123"):
            return httpx.Response(200, json=remote_user)
        if req.method == "GET" and p.endswith("/users"):
            return httpx.Response(200, json=[{"id": "kc-123"}])
        if req.method == "GET" and p.endswith("/role-mappings/realm"):
            return httpx.Response(200, json=[{"id": "old", "name": "viewer"}])
        if req.method == "DELETE" and p.endswith("/role-mappings/realm"):
            return httpx.Response(204)
        if req.method == "PUT" and p.endswith("/users/kc-123"):
            remote_user.update(body)
            return httpx.Response(204)
        if req.method == "PUT" and p.endswith("/reset-password"):
            return httpx.Response(204)
        if req.method == "POST" and p.endswith("/logout"):
            return httpx.Response(204)
        if req.method == "POST" and p.endswith("/users"):
            remote_user.update({k: v for k, v in body.items() if k != "credentials"})
            return httpx.Response(201, headers={"location": f"{KC}/admin/realms/soc/users/kc-123"})
        if req.method == "POST" and p.endswith("/role-mappings/realm"):
            return httpx.Response(204)
        return httpx.Response(404)

    auth_api.set_http(httpx.Client(transport=httpx.MockTransport(handler)))
    yield calls
    auth_api.set_http(None)


def test_super_admin_creates_user_in_keycloak(superadmin, kc):
    # superadmin fixture logs in via dev password; switch is only for the provisioning branch
    r = superadmin.post("/api/admin/users", {"email": "new@t.local", "name": "New Person", "role": "admin", "password": PASSWORD})
    assert r.status_code == 201, r.text
    create = next(c for c in kc if c[0] == "POST" and c[1].endswith("/users"))
    assert create[2]["credentials"][0]["temporary"] is True and "UPDATE_PASSWORD" in create[2]["requiredActions"] and create[2]["emailVerified"] is True
    assert any(c[1].endswith("/users/kc-123/role-mappings/realm") for c in kc)
    from app import db as dbmod
    from app.models import User
    with dbmod.session_scope() as db:
        assert db.get(User, r.json()["id"]).subject == "kc-123"
    assert PASSWORD not in json.dumps(r.json())  # the password is never echoed back


def test_plain_admin_can_provision(admin, kc):
    assert admin.post("/api/admin/users", {"email": "n@t.local", "role": "viewer", "password": PASSWORD}).status_code == 201
    assert [c for c in kc if c[1].endswith("/users")]


def test_not_configured_is_clear_error(superadmin, monkeypatch, kc):
    monkeypatch.setenv("SOC_KC_ADMIN_CLIENT_SECRET", "")
    reset_settings_cache()
    assert superadmin.post("/api/admin/users", {"email": "n@t.local", "role": "viewer", "password": PASSWORD}).status_code == 503


def test_owner_resets_keycloak_password(superadmin, kc):
    created = superadmin.post("/api/admin/users", {"email": "reset@t.local", "password": PASSWORD}).json()
    r = superadmin.post(f"/api/admin/users/{created['id']}/password", {"password": PASSWORD})
    assert r.status_code == 200, r.text
    assert ("PUT", "/admin/realms/soc/users/kc-123/reset-password", {"type": "password", "value": PASSWORD, "temporary": True}) in kc
    assert any(c[1].endswith("/logout") for c in kc)
    assert PASSWORD not in r.text
    assert PASSWORD not in superadmin.get("/api/admin/audit").text


def test_password_failure_and_identity_mismatch(superadmin, kc, monkeypatch):
    from app import keycloak_admin as client
    created = superadmin.post("/api/admin/users", {"email": "reset@t.local", "password": PASSWORD}).json()
    original = client._call
    def reject(c, method, path, **kw):
        if path.endswith("/reset-password"):
            return httpx.Response(400)
        return original(c, method, path, **kw)
    monkeypatch.setattr(client, "_call", reject)
    r = superadmin.post(f"/api/admin/users/{created['id']}/password", {"password": PASSWORD})
    assert r.status_code == 400 and "policy" in r.text
    def mismatch(c, method, path, **kw):
        if method == "GET" and path == "/users/kc-123":
            return httpx.Response(200, json={"id": "different-identity"})
        return original(c, method, path, **kw)
    monkeypatch.setattr(client, "_call", mismatch)
    kc.clear()
    assert superadmin.post(f"/api/admin/users/{created['id']}/password", {"password": PASSWORD}).status_code == 409
    assert not kc


def test_provision_legacy_local_account(superadmin, kc):
    from app import db as dbmod
    from app.models import User
    with dbmod.session_scope() as db:
        u = User(subject="dev:legacy@t.local", email="legacy@t.local", name="Legacy", role="l1", all_clients=True)
        db.add(u)
        db.flush()
        uid = u.id
    r = superadmin.post(f"/api/admin/users/{uid}/provision", {"password": PASSWORD})
    assert r.status_code == 200 and r.json()["identity_status"] == "linked", r.text
    with dbmod.session_scope() as db:
        assert db.get(User, uid).subject == "kc-123"
    assert superadmin.post(f"/api/admin/users/{uid}/provision", {"password": PASSWORD}).status_code == 409


def test_failed_keycloak_create_does_not_create_local_user(superadmin, kc, monkeypatch):
    from app import keycloak_admin as client
    def fail(*a):
        raise client.KcError("service account denied", 502)
    monkeypatch.setattr(client, "create_user", fail)
    r = superadmin.post("/api/admin/users", {"email": "fail@t.local", "password": PASSWORD})
    assert r.status_code == 502
    assert not any(u["email"] == "fail@t.local" for u in superadmin.get("/api/admin/users").json())


def test_local_password_reset_and_permissions(superadmin, admin, make_session):
    target = make_session("reset@t.local", "viewer")
    uid = target.get("/api/auth/me").json()["id"]
    new_password = "An0ther-Secure-password!"
    assert admin.post(f"/api/admin/users/{uid}/password", {"password": new_password}).status_code == 200
    assert superadmin.post(f"/api/admin/users/{uid}/password", {"password": "weak"}).status_code == 422
    owner = superadmin.get("/api/auth/me").json()["id"]
    assert superadmin.post(f"/api/admin/users/{owner}/password", {"password": new_password}).status_code == 403
    assert superadmin.post(f"/api/admin/users/{uid}/password", {"password": new_password}).status_code == 200
    assert target.get("/api/auth/me").status_code == 401
    assert target.login().status_code == 401
    assert target.login(password=new_password).status_code == 200
    assert new_password not in superadmin.get("/api/admin/audit").text


def test_external_provider_password_is_not_changed(superadmin, make_session, monkeypatch):
    from app.config import get_settings
    target = make_session("reset@t.local", "viewer")
    uid = target.get("/api/auth/me").json()["id"]
    monkeypatch.setattr(get_settings(), "auth_mode", "oidc")
    r = superadmin.post(f"/api/admin/users/{uid}/password", {"password": PASSWORD})
    assert r.status_code == 400 and "identity provider" in r.text


def test_reset_links_legacy_account_and_clears_local_credentials(superadmin, kc):
    from app import db as dbmod
    from app.models import User
    with dbmod.session_scope() as db:
        u = User(subject="dev:legacy@t.local", email="legacy@t.local", role="viewer", password_hash="old-local-hash", totp_secret="old-local-secret")
        db.add(u)
        db.flush()
        uid = u.id
    assert superadmin.post(f"/api/admin/users/{uid}/password", {"password": PASSWORD}).status_code == 200
    with dbmod.session_scope() as db:
        u = db.get(User, uid)
        assert u.subject == "kc-123" and u.password_hash is None and u.totp_secret is None


def test_missing_keycloak_account_is_actionable(superadmin, kc, monkeypatch):
    from app import keycloak_admin as client
    created = superadmin.post("/api/admin/users", {"email": "missing@t.local", "password": PASSWORD}).json()
    original = client._call
    def missing(c, method, path, **kw):
        if method == "GET" and path == "/users/kc-123":
            return httpx.Response(404)
        return original(c, method, path, **kw)
    monkeypatch.setattr(client, "_call", missing)
    kc.clear()
    r = superadmin.post(f"/api/admin/users/{created['id']}/password", {"password": PASSWORD})
    assert r.status_code == 404 and "restore the original account" in r.text
    assert not kc


def test_password_reset_requires_fresh_mfa(superadmin, make_session):
    from datetime import timedelta

    from sqlalchemy import select

    from app import db as dbmod
    from app.models import SessionRecord, utcnow
    target = make_session("reset@t.local", "viewer")
    uid = target.get("/api/auth/me").json()["id"]
    owner = superadmin.get("/api/auth/me").json()["id"]
    with dbmod.session_scope() as db:
        for rec in db.execute(select(SessionRecord).where(SessionRecord.user_id == owner)).scalars():
            rec.step_up_until = utcnow() - timedelta(minutes=1)
    r = superadmin.post(f"/api/admin/users/{uid}/password", {"password": PASSWORD})
    assert r.status_code == 403 and "step_up_required" in r.text


def test_admin_edits_keycloak_profile_role_scope_and_password(admin, kc):
    created = admin.post("/api/admin/users", {"email": "person@t.local", "password": PASSWORD}).json()
    uid = created["id"]
    r = admin.patch(f"/api/admin/users/{uid}", {"name": "Updated Person", "email": "updated@t.local", "role": "admin", "all_clients": True, "grants": ["alerts.read"], "denied": ["alerts.delete"]})
    assert r.status_code == 200, r.text
    assert r.json()["email"] == "updated@t.local" and r.json()["role"] == "admin"
    assert "pending_approval" not in r.json()
    assert ("PUT", "/admin/realms/soc/users/kc-123", {"firstName": "Updated", "lastName": "Person", "email": "updated@t.local", "emailVerified": False}) in kc
    assert admin.post(f"/api/admin/users/{uid}/password", {"password": PASSWORD}).status_code == 200
    assert admin.patch(f"/api/admin/users/{uid}", {"active": False}).status_code == 200
    assert ("PUT", "/admin/realms/soc/users/kc-123", {"enabled": False}) in kc


def test_name_only_edit_syncs_to_keycloak(admin, kc):
    uid = admin.post("/api/admin/users", {"email": "person@t.local", "password": PASSWORD}).json()["id"]
    r = admin.patch(f"/api/admin/users/{uid}", {"name": "New Name"})
    assert r.status_code == 200, r.text
    assert ("PUT", "/admin/realms/soc/users/kc-123", {"firstName": "New", "lastName": "Name", "email": "person@t.local"}) in kc


def test_invalid_scope_does_not_partially_edit_keycloak(admin, kc):
    uid = admin.post("/api/admin/users", {"email": "person@t.local", "password": PASSWORD}).json()["id"]
    kc.clear()
    r = admin.patch(f"/api/admin/users/{uid}", {"name": "Changed", "role": "admin", "client_ids": ["missing-client"]})
    assert r.status_code == 400 and not kc


def test_edit_uses_linked_id_when_soc_email_is_stale(admin, kc, monkeypatch):
    from app import keycloak_admin as client
    uid = admin.post("/api/admin/users", {"email": "old@t.local", "password": PASSWORD}).json()["id"]
    # The account exists by immutable ID, but its email was changed directly in Keycloak.
    monkeypatch.setattr(client, "find_user_id", lambda *a: None)
    kc.clear()
    r = admin.patch(f"/api/admin/users/{uid}", {"email": "new@t.local", "name": "Updated Name", "role": "admin"})
    assert r.status_code == 200, r.text
    assert r.json()["email"] == "new@t.local"
    assert ("PUT", "/admin/realms/soc/users/kc-123", {"firstName": "Updated", "lastName": "Name", "email": "new@t.local", "emailVerified": False}) in kc
    assert not any(method == "GET" and path.endswith("/users") for method, path, body in kc)


def test_reset_and_disable_use_linked_id_after_external_email_change(admin, kc, monkeypatch):
    from app import keycloak_admin as client
    uid = admin.post('/api/admin/users', {'email': 'old@t.local', 'password': PASSWORD}).json()['id']
    def no_search(*a):
        raise AssertionError('linked identities must not be resolved by email')
    monkeypatch.setattr(client, 'find_user_id', no_search)
    assert admin.post(f'/api/admin/users/{uid}/password', {'password': PASSWORD}).status_code == 200
    assert admin.patch(f'/api/admin/users/{uid}', {'active': False}).status_code == 200
    assert ('PUT', '/admin/realms/soc/users/kc-123', {'enabled': False}) in kc


def test_legacy_username_lookup_links_profile_without_recreating_user(admin, kc, monkeypatch):
    from app import db as dbmod
    from app import keycloak_admin as client
    from app.models import User
    with dbmod.session_scope() as db:
        user = User(subject='pending:old@t.local', email='old@t.local', role='l1', name='Old Name')
        db.add(user)
        db.flush()
        uid = user.id
    original = client._call
    lookups = []
    def search(c, method, path, **kw):
        if method == 'GET' and path == '/users':
            lookups.append(kw['params'])
            return httpx.Response(200, json=[] if 'email' in kw['params'] else [{'id': 'kc-123'}])
        return original(c, method, path, **kw)
    monkeypatch.setattr(client, '_call', search)
    kc.clear()
    r = admin.patch(f'/api/admin/users/{uid}', {'name': 'New Name', 'email': 'new@t.local'})
    assert r.status_code == 200 and r.json()['identity_status'] == 'linked', r.text
    assert lookups == [{'email': 'old@t.local', 'exact': 'true'}, {'username': 'old@t.local', 'exact': 'true'}]
    assert not any(method == 'POST' and path.endswith('/users') for method, path, body in kc)
    with dbmod.session_scope() as db:
        assert db.get(User, uid).subject == 'kc-123'


def test_deleted_linked_identity_never_falls_back_to_reused_email(admin, kc, monkeypatch):
    from app import keycloak_admin as client
    uid = admin.post('/api/admin/users', {'email': 'reused@t.local', 'password': PASSWORD}).json()['id']
    original = client._call
    def missing(c, method, path, **kw):
        if method == 'GET' and path == '/users/kc-123':
            return httpx.Response(404)
        if method == 'GET' and path == '/users':
            raise AssertionError('must not adopt another account with the old email')
        return original(c, method, path, **kw)
    monkeypatch.setattr(client, '_call', missing)
    kc.clear()
    for body in ({'email': 'new@t.local'}, {'role': 'admin'}, {'active': False}):
        r = admin.patch(f'/api/admin/users/{uid}', body)
        assert r.status_code == 404, r.text
    assert not any(method in ('PUT', 'DELETE', 'POST') and '/openid-connect/' not in path for method, path, body in kc)


def test_ambiguous_legacy_lookup_is_rejected(kc, monkeypatch):
    from app import keycloak_admin as client
    monkeypatch.setattr(client, '_call', lambda *a, **kw: httpx.Response(200, json=[{'id': 'one'}, {'id': 'two'}]))
    with pytest.raises(client.KcError, match='multiple Keycloak accounts'):
        client.find_user_id(auth_api.get_http(), 'ambiguous@t.local')
