from __future__ import annotations

from datetime import timedelta

import pyotp
from fastapi.testclient import TestClient

from app import db as dbmod
from app.models import SessionRecord, User, utcnow
from tests.conftest import PASSWORD, Session, make_user


def test_auth_config_exposes_no_account_url_in_dev_mode(app):
    from fastapi.testclient import TestClient

    c = TestClient(app)
    body = c.get("/api/auth/config").json()
    assert body["auth_mode"] == "dev" and body["account_url"] is None  # self-service link only makes sense under OIDC


def test_login_me_logout(app):
    _, secret = make_user("a@t.local", "l1")
    s = Session(app, "a@t.local", secret)
    me = s.get("/api/auth/me").json()
    assert me["role"] == "l1" and "alerts.triage" in me["capabilities"] and "admin.users" not in me["capabilities"]
    assert s.post("/api/auth/logout").status_code == 200
    assert s.get("/api/auth/me").status_code == 401


def test_cookie_flags(app):
    _, secret = make_user("a@t.local")
    c = TestClient(app, client=("10.0.0.5", 1))
    r = c.post("/api/auth/login", json={"email": "a@t.local", "password": PASSWORD, "totp": pyotp.TOTP(secret).now()})
    sc = r.headers["set-cookie"].lower()
    assert "httponly" in sc and "samesite=strict" in sc
    assert r.headers["x-content-type-options"] == "nosniff" and r.headers["x-frame-options"] == "DENY"


def test_cookie_is_secure_and_host_prefixed_when_cookie_secure(app, monkeypatch):
    """With SOC_COOKIE_SECURE=true (the production setting), the session cookie must carry Secure
    and use the __Host- prefix, which browsers refuse to accept without Secure + Path=/ + no Domain."""
    from app.config import get_settings

    monkeypatch.setattr(get_settings(), "cookie_secure", True)
    _, secret = make_user("b@t.local")
    c = TestClient(app, client=("10.0.0.5", 1))
    r = c.post("/api/auth/login", json={"email": "b@t.local", "password": PASSWORD, "totp": pyotp.TOTP(secret).now()})
    sc = r.headers["set-cookie"]
    assert sc.startswith("__Host-soc_session=")
    low = sc.lower()
    assert "secure" in low and "httponly" in low and "samesite=strict" in low and "path=/" in low and "domain=" not in low


def test_bad_password_and_totp_are_generic(app):
    _, secret = make_user("a@t.local")
    s = Session(app)
    s.email, s.totp_secret = "a@t.local", secret
    r1 = s.login(password="wrong-password-123A")
    r2 = s.c.post("/api/auth/login", json={"email": "nobody@t.local", "password": PASSWORD, "totp": "123456"})
    r3 = s.login(code="000000")
    assert r1.status_code == r2.status_code == r3.status_code == 401
    assert r1.json() == r2.json() == r3.json()


def test_account_lockout(app):
    _, secret = make_user("a@t.local")
    s = Session(app)
    s.email, s.totp_secret = "a@t.local", secret
    for _ in range(5):
        s.login(password="wrong-password-123A")
    s.csrf = None
    assert s.login().status_code == 401  # correct credentials rejected while locked
    with dbmod.session_scope() as db:
        u = db.query(User).filter_by(email="a@t.local").one()
        assert u.locked_until is not None
        u.locked_until = utcnow() - timedelta(seconds=1)
    from app.ratelimit import limiter

    limiter.reset()
    assert s.login().status_code == 200


def test_login_rate_limit(app):
    s = Session(app)
    codes = [s.c.post("/api/auth/login", json={"email": "x@t.local", "password": "x", "totp": "1"}).status_code for _ in range(14)]
    assert 429 in codes


def test_csrf_required_for_mutations(app):
    _, secret = make_user("a@t.local", "l1")
    s = Session(app, "a@t.local", secret)
    r = s.c.post("/api/alerts/bulk", json={"ids": ["x"], "status": "acknowledged"})  # no CSRF header
    assert r.status_code == 403
    r = s.c.post("/api/alerts/bulk", json={"ids": ["x"], "status": "acknowledged"}, headers={"X-CSRF-Token": "wrong", })
    assert r.status_code == 403
    r = s.c.post("/api/alerts/bulk", json={"ids": ["x"], "status": "acknowledged"}, headers={"X-CSRF-Token": s.csrf, "Origin": "https://evil.example"})
    assert r.status_code == 403
    assert s.post("/api/alerts/bulk", json={"ids": ["x"], "status": "acknowledged"}).status_code == 200


def test_session_idle_and_absolute_expiry(app):
    _, secret = make_user("a@t.local")
    s = Session(app, "a@t.local", secret)
    with dbmod.session_scope() as db:
        rec = db.query(SessionRecord).one()
        rec.last_seen_at = utcnow() - timedelta(minutes=16)
    assert s.get("/api/auth/me").status_code == 401
    s2 = Session(app, "a@t.local", secret)
    with dbmod.session_scope() as db:
        rec = db.query(SessionRecord).filter_by(revoked=False).one()
        rec.expires_at = utcnow() - timedelta(seconds=1)
    assert s2.get("/api/auth/me").status_code == 401


def test_max_concurrent_sessions(app):
    _, secret = make_user("a@t.local")
    sessions = [Session(app, "a@t.local", secret) for _ in range(4)]
    assert sessions[0].get("/api/auth/me").status_code == 401  # oldest evicted
    assert sessions[3].get("/api/auth/me").status_code == 200


def test_disabled_user_loses_access(app, admin):
    uid, secret = make_user("victim@t.local", "l1")
    v = Session(app, "victim@t.local", secret)
    admin.step_up()
    r = admin.patch(f"/api/admin/users/{uid}", {"active": False})
    assert r.status_code == 200
    assert v.get("/api/auth/me").status_code == 401


def test_unauthenticated_endpoints_rejected(app):
    c = TestClient(app, client=("10.0.0.5", 1))
    for path in ("/api/alerts", "/api/cases", "/api/servers", "/api/admin/users", "/api/integrations/tools", "/api/dashboard", "/api/stream"):
        assert c.get(path).status_code == 401, path


def test_step_up_required_for_admin_changes(app, superadmin):
    admin = superadmin
    other = {"email": "n@t.local", "role": "viewer", "password": PASSWORD}
    # login grants a fresh step-up window; simulate expiry
    with dbmod.session_scope() as db:
        rec = db.query(SessionRecord).one()
        rec.step_up_until = utcnow() - timedelta(seconds=1)
    r = admin.post("/api/admin/users", other)
    assert r.status_code == 403 and r.json()["detail"]["code"] == "step_up_required"
    assert admin.step_up().status_code == 200
    assert admin.post("/api/admin/users", other).status_code == 201


def test_weak_password_rejected_on_user_create(superadmin):
    admin = superadmin
    r = admin.post("/api/admin/users", {"email": "n@t.local", "role": "viewer", "password": "short"})
    assert r.status_code == 400


def test_dev_login_disabled_in_oidc_mode(app, monkeypatch):
    monkeypatch.setenv("SOC_AUTH_MODE", "oidc")
    from app.config import reset_settings_cache

    reset_settings_cache()
    r = TestClient(app, client=("10.0.0.5", 1)).post("/api/auth/login", json={"email": "a", "password": "b", "totp": "1"})
    assert r.status_code == 404
