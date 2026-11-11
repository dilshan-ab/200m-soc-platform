from __future__ import annotations

import json
import time
from urllib.parse import parse_qs, urlparse

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from app import db as dbmod
from app import oidc
from app.api import auth as auth_api
from app.config import reset_settings_cache
from app.models import OidcState, SessionRecord, User

ISS = "https://kc.corp.local/realms/soc"
CID = "soc-bff"


@pytest.fixture()
def idp(monkeypatch, app):
    for k, v in {"SOC_AUTH_MODE": "oidc", "SOC_OIDC_ISSUER": ISS, "SOC_OIDC_CLIENT_ID": CID, "SOC_OIDC_CLIENT_SECRET": "cs", "SOC_OIDC_REDIRECT_URI": "https://soc.corp.local/api/auth/oidc/callback"}.items():
        monkeypatch.setenv(k, v)
    reset_settings_cache()
    oidc.clear_cache()
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    jwk.update({"kid": "k1", "alg": "RS256", "use": "sig"})
    holder: dict = {"token": None}

    def handler(req: httpx.Request):
        p = req.url.path
        if p.endswith("openid-configuration"):
            return httpx.Response(200, json={"issuer": ISS, "authorization_endpoint": f"{ISS}/auth", "token_endpoint": f"{ISS}/token", "jwks_uri": f"{ISS}/certs"})
        if p.endswith("/certs"):
            return httpx.Response(200, json={"keys": [jwk]})
        if p.endswith("/token"):
            assert b"code_verifier" in req.content and b"client_secret" in req.content
            return httpx.Response(200, json={"id_token": holder["token"]})
        return httpx.Response(404)

    auth_api.set_http(httpx.Client(transport=httpx.MockTransport(handler)))

    def mint(nonce, **over):
        now = int(time.time())
        claims = {"iss": ISS, "aud": CID, "sub": "user-1", "exp": now + 300, "iat": now, "nonce": nonce, "email": "oidc@corp.local", "name": "OIDC User", "soc_role": ["l2"], "azp": CID, "auth_time": now, "acr": "mfa-webauthn", "sid": "kc-sid"}
        claims.update(over)
        return jwt.encode(claims, key, algorithm="RS256", headers={"kid": "k1"})

    yield {"holder": holder, "mint": mint, "key": key}
    auth_api.set_http(None)


def _begin(app, purpose_path="/api/auth/oidc/login?return_to=/alerts"):
    c = TestClient(app, client=("10.0.0.5", 1), follow_redirects=False)
    r = c.get(purpose_path)
    assert r.status_code == 302
    q = parse_qs(urlparse(r.headers["location"]).query)
    return c, q


def test_auth_config_exposes_account_console_url_under_oidc(app, idp):
    c = TestClient(app)
    body = c.get("/api/auth/config").json()
    assert body == {"auth_mode": "oidc", "account_url": f"{ISS}/account/", "user_provisioning": False}


def test_login_redirect_uses_pkce_state_nonce(app, idp):
    _, q = _begin(app)
    assert q["code_challenge_method"] == ["S256"] and q["response_type"] == ["code"] and q["state"][0] and q["nonce"][0] and q["code_challenge"][0]
    assert "client_secret" not in q  # confidential client secret never goes through the browser


def test_successful_login_creates_session_with_role(app, idp):
    c, q = _begin(app)
    idp["holder"]["token"] = idp["mint"](q["nonce"][0])
    r = c.get("/api/auth/oidc/callback", params={"code": "abc", "state": q["state"][0]})
    assert r.status_code == 302 and r.headers["location"] == "/alerts"
    me = c.get("/api/auth/me").json()
    assert me["role"] == "l2" and me["email"] == "oidc@corp.local"
    with dbmod.session_scope() as db:
        assert db.query(User).one().subject == "user-1" and db.query(OidcState).count() == 0
    # state is single-use
    assert c.get("/api/auth/oidc/callback", params={"code": "abc", "state": q["state"][0]}).status_code == 400


@pytest.mark.parametrize("override,label", [
    ({"nonce": "other"}, "nonce"),
    ({"aud": "someone-else"}, "aud"),
    ({"iss": "https://evil.example/realms/soc"}, "iss"),
    ({"exp": int(time.time()) - 600}, "expired"),
    ({"azp": "other-client"}, "azp"),
])
def test_invalid_id_tokens_rejected(app, idp, override, label):
    c, q = _begin(app)
    idp["holder"]["token"] = idp["mint"](override.get("nonce", q["nonce"][0]), **{k: v for k, v in override.items() if k != "nonce"})
    r = c.get("/api/auth/oidc/callback", params={"code": "abc", "state": q["state"][0]})
    assert r.status_code == 400, label
    assert c.get("/api/auth/me").status_code == 401


def test_alg_none_and_hs256_confusion_rejected(app, idp):
    c, q = _begin(app)
    now = int(time.time())
    claims = {"iss": ISS, "aud": CID, "sub": "u", "exp": now + 300, "iat": now, "nonce": q["nonce"][0], "soc_role": ["admin"]}
    idp["holder"]["token"] = jwt.encode(claims, "secret", algorithm="HS256", headers={"kid": "k1"})
    assert c.get("/api/auth/oidc/callback", params={"code": "a", "state": q["state"][0]}).status_code == 400
    c, q = _begin(app)
    claims["nonce"] = q["nonce"][0]
    idp["holder"]["token"] = jwt.encode(claims, None, algorithm="none", headers={"kid": "k1"})
    assert c.get("/api/auth/oidc/callback", params={"code": "a", "state": q["state"][0]}).status_code == 400


def test_token_signed_by_unknown_key_rejected(app, idp):
    c, q = _begin(app)
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = int(time.time())
    claims = {"iss": ISS, "aud": CID, "sub": "u", "exp": now + 300, "iat": now, "nonce": q["nonce"][0], "soc_role": ["admin"]}
    idp["holder"]["token"] = jwt.encode(claims, other, algorithm="RS256", headers={"kid": "k1"})
    assert c.get("/api/auth/oidc/callback", params={"code": "a", "state": q["state"][0]}).status_code == 400


def test_no_role_claim_is_denied(app, idp):
    c, q = _begin(app)
    idp["holder"]["token"] = idp["mint"](q["nonce"][0], soc_role=[])
    assert c.get("/api/auth/oidc/callback", params={"code": "a", "state": q["state"][0]}).status_code == 403


def test_open_redirect_is_neutralised(app, idp):
    for evil in ("https://evil.example", "//evil.example", "/\\evil.example"):
        c, q = _begin(app, f"/api/auth/oidc/login?return_to={evil}")
        idp["holder"]["token"] = idp["mint"](q["nonce"][0])
        r = c.get("/api/auth/oidc/callback", params={"code": "a", "state": q["state"][0]})
        assert r.headers["location"] == "/"


def test_role_comes_from_idp_every_login(app, idp):
    c, q = _begin(app)
    idp["holder"]["token"] = idp["mint"](q["nonce"][0])
    c.get("/api/auth/oidc/callback", params={"code": "a", "state": q["state"][0]})
    c2, q2 = _begin(app)
    idp["holder"]["token"] = idp["mint"](q2["nonce"][0], soc_role=["viewer"])
    c2.get("/api/auth/oidc/callback", params={"code": "a", "state": q2["state"][0]})
    assert c2.get("/api/auth/me").json()["role"] == "viewer"


def test_step_up_requires_mfa_acr_and_fresh_auth(app, idp):
    c, q = _begin(app)
    idp["holder"]["token"] = idp["mint"](q["nonce"][0], acr="pwd")  # logged in without MFA acr
    c.get("/api/auth/oidc/callback", params={"code": "a", "state": q["state"][0]})
    assert c.get("/api/auth/me").json()["step_up_until"] is None
    r = c.get("/api/auth/oidc/step-up")
    q2 = parse_qs(urlparse(r.headers["location"]).query)
    assert q2["acr_values"] == ["mfa-webauthn"] and q2["max_age"] == ["0"] and q2["prompt"] == ["login"]
    idp["holder"]["token"] = idp["mint"](q2["nonce"][0], acr="pwd")
    assert c.get("/api/auth/oidc/callback", params={"code": "a", "state": q2["state"][0]}).status_code == 400
    r = c.get("/api/auth/oidc/step-up")
    q3 = parse_qs(urlparse(r.headers["location"]).query)
    idp["holder"]["token"] = idp["mint"](q3["nonce"][0], auth_time=int(time.time()) - 3600)
    assert c.get("/api/auth/oidc/callback", params={"code": "a", "state": q3["state"][0]}).status_code == 400
    r = c.get("/api/auth/oidc/step-up")
    q4 = parse_qs(urlparse(r.headers["location"]).query)
    idp["holder"]["token"] = idp["mint"](q4["nonce"][0])
    assert c.get("/api/auth/oidc/callback", params={"code": "a", "state": q4["state"][0]}).status_code == 302
    assert c.get("/api/auth/me").json()["step_up_until"] is not None
    with dbmod.session_scope() as db:
        assert db.query(SessionRecord).count() == 1  # step-up upgrades the session, doesn't create another


def test_pending_provisioned_user_is_linked_by_verified_email(app, idp):
    with dbmod.session_scope() as db:
        db.add(User(subject="pending:oidc@corp.local", email="oidc@corp.local", role="viewer"))
    c, q = _begin(app)
    idp["holder"]["token"] = idp["mint"](q["nonce"][0], email_verified=True)
    c.get("/api/auth/oidc/callback", params={"code": "a", "state": q["state"][0]})
    with dbmod.session_scope() as db:
        u = db.query(User).one()
        assert u.subject == "user-1"


def test_unverified_email_does_not_hijack_pending_user(app, idp):
    with dbmod.session_scope() as db:
        db.add(User(subject="pending:oidc@corp.local", email="oidc@corp.local", role="admin"))
    c, q = _begin(app)
    idp["holder"]["token"] = idp["mint"](q["nonce"][0], email="oidc@corp.local")
    r = c.get("/api/auth/oidc/callback", params={"code": "a", "state": q["state"][0]})
    assert r.status_code == 403
    assert c.get("/api/auth/me").status_code == 401
    with dbmod.session_scope() as db:
        assert db.query(User).filter_by(subject="pending:oidc@corp.local").count() == 1


def test_production_requires_oidc_and_hardening(monkeypatch):
    from pydantic import ValidationError

    from app.config import Settings

    base = {"environment": "production", "auth_mode": "oidc", "cookie_secure": True, "database_url": "postgresql+psycopg://u:p@db/soc", "secrets_key": "x" * 44}
    Settings(**base)
    for bad in ({"auth_mode": "dev"}, {"cookie_secure": False}, {"database_url": "sqlite:///x.db"}, {"allow_http_connectors": True}, {"secrets_key": ""}):
        with pytest.raises(ValidationError):
            Settings(**{**base, **bad})
