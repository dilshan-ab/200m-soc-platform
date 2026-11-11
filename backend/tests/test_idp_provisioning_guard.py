from __future__ import annotations

from app.config import get_settings
from tests.conftest import PASSWORD


def test_add_user_and_role_change_refused_when_users_live_in_external_idp(superadmin, make_session, monkeypatch):
    """OIDC mode without a Keycloak admin API (e.g. Asgardeo): accounts and roles belong to the IdP."""
    target = make_session("l1@t.local", "l1")
    uid = target.get("/api/auth/me").json()["id"]
    monkeypatch.setattr(get_settings(), "auth_mode", "oidc")  # kc_admin_url is unset in tests -> kc.configured() is False

    cfg = superadmin.get("/api/auth/config").json()
    assert cfg["auth_mode"] == "oidc" and cfg["user_provisioning"] is False

    r = superadmin.post("/api/admin/users", {"email": "new@t.local", "name": "New", "role": "l1", "all_clients": True, "password": PASSWORD})
    assert r.status_code == 400 and "identity provider" in r.json()["detail"]

    r = superadmin.patch(f"/api/admin/users/{uid}", {"role": "l2"})
    assert r.status_code == 400 and "identity provider" in r.json()["detail"]

    # per-user permission overrides are still local and still work
    assert superadmin.patch(f"/api/admin/users/{uid}", {"grants": ["servers.write"]}).status_code == 200


def test_account_url_override(superadmin, monkeypatch):
    s = get_settings()
    monkeypatch.setattr(s, "auth_mode", "oidc")
    monkeypatch.setattr(s, "oidc_issuer", "https://api.asgardeo.io/t/zeit200m/oauth2/token")
    assert superadmin.get("/api/auth/config").json()["account_url"] == "https://api.asgardeo.io/t/zeit200m/oauth2/token/account/"
    monkeypatch.setattr(s, "oidc_account_url", "https://myaccount.asgardeo.io/t/zeit200m")
    assert superadmin.get("/api/auth/config").json()["account_url"] == "https://myaccount.asgardeo.io/t/zeit200m"
