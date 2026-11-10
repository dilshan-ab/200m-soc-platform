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
        if req.method == "POST" and p.endswith("/users"):
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
    assert PASSWORD not in json.dumps(r.json())  # the password is never echoed back


def test_plain_admin_cannot_provision(admin, kc):
    assert admin.post("/api/admin/users", {"email": "n@t.local", "role": "viewer", "password": PASSWORD}).status_code == 403
    assert not [c for c in kc if c[1].endswith("/users")]


def test_not_configured_is_clear_error(superadmin, monkeypatch, kc):
    monkeypatch.setenv("SOC_KC_ADMIN_CLIENT_SECRET", "")
    reset_settings_cache()
    assert superadmin.post("/api/admin/users", {"email": "n@t.local", "role": "viewer", "password": PASSWORD}).status_code == 503
