"""OIDC (Keycloak) authorization-code + PKCE flow with strict ID-token validation."""
from __future__ import annotations

import base64
import hashlib
import json
import time
from datetime import timedelta
from typing import Any
from urllib.parse import urlencode

import httpx
import jwt
from sqlalchemy.orm import Session

from .config import get_settings
from .models import OidcState, utcnow
from .security import new_token


class OidcError(Exception):
    pass


_cache: dict[str, tuple[float, Any]] = {}


def _get_json(client: httpx.Client, url: str, ttl: int = 300) -> Any:
    hit = _cache.get(url)
    if hit and time.monotonic() - hit[0] < ttl:
        return hit[1]
    r = client.get(url, timeout=5.0)
    r.raise_for_status()
    try:
        data = r.json()
    except ValueError as e:
        raise OidcError("identity provider returned invalid JSON") from e
    if not isinstance(data, dict):
        raise OidcError("identity provider returned an invalid document")
    _cache[url] = (time.monotonic(), data)
    return data


def clear_cache() -> None:
    _cache.clear()


def _internal(url: str) -> str:
    """Server-to-server calls may use an internal base URL; the public issuer is still what tokens must carry."""
    s = get_settings()
    pub, internal = s.oidc_issuer.rstrip("/"), s.oidc_internal_issuer.rstrip("/")
    if internal and url.startswith(pub):
        pub_origin, int_origin = pub.split("/realms/")[0], internal.split("/realms/")[0]
        return int_origin + url[len(pub_origin):]
    return url


def discovery(client: httpx.Client) -> dict[str, Any]:
    s = get_settings()
    base = (s.oidc_internal_issuer or s.oidc_issuer).rstrip("/")
    doc = _get_json(client, f"{base}/.well-known/openid-configuration")
    if doc.get("issuer") != s.oidc_issuer.rstrip("/") and doc.get("issuer") != s.oidc_issuer:
        raise OidcError("issuer mismatch in discovery document")
    return doc  # type: ignore[no-any-return]


def end_session_url() -> str | None:
    """Keycloak RP-initiated logout URL (browser-facing), or None when OIDC is not configured."""
    s = get_settings()
    if not s.oidc_issuer:
        return None
    q = {"client_id": s.oidc_client_id}
    if s.oidc_post_logout_redirect_uri:
        q["post_logout_redirect_uri"] = s.oidc_post_logout_redirect_uri
    return f"{s.oidc_issuer.rstrip('/')}/protocol/openid-connect/logout?{urlencode(q)}"


def _pkce() -> tuple[str, str]:
    verifier = new_token(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def safe_return_to(value: str | None) -> str:
    """Only same-site relative paths (prevents open redirect)."""
    if not value or not value.startswith("/") or value.startswith("//") or "\\" in value or "\n" in value:
        return "/"
    return value


def authorization_url(db: Session, client: httpx.Client, *, purpose: str = "login", return_to: str = "/", session_id: str | None = None) -> str:
    s = get_settings()
    doc = discovery(client)
    verifier, challenge = _pkce()
    state, nonce = new_token(24), new_token(24)
    db.add(
        OidcState(
            state=state, nonce=nonce, code_verifier=verifier, purpose=purpose, return_to=safe_return_to(return_to),
            session_id=session_id, expires_at=utcnow() + timedelta(minutes=10),
        )
    )
    q = {
        "response_type": "code", "client_id": s.oidc_client_id, "redirect_uri": s.oidc_redirect_uri,
        "scope": "openid profile email", "state": state, "nonce": nonce,
        "code_challenge": challenge, "code_challenge_method": "S256",
    }
    if purpose == "step_up":
        q.update({"acr_values": s.oidc_step_up_acr, "max_age": "0", "prompt": "login"})
    return f"{doc['authorization_endpoint']}?{urlencode(q)}"


def exchange_and_validate(client: httpx.Client, code: str, st: OidcState) -> dict[str, Any]:
    s = get_settings()
    doc = discovery(client)
    r = client.post(
        _internal(doc["token_endpoint"]),
        data={
            "grant_type": "authorization_code", "code": code, "redirect_uri": s.oidc_redirect_uri,
            "client_id": s.oidc_client_id, "client_secret": s.oidc_client_secret, "code_verifier": st.code_verifier,
        },
        timeout=10.0,
    )
    if r.status_code != 200:
        raise OidcError("token exchange failed")
    try:
        body = r.json()
    except ValueError as e:
        raise OidcError("identity provider returned an invalid token response") from e
    id_token = body.get("id_token") if isinstance(body, dict) else None
    if not isinstance(id_token, str) or not id_token:
        raise OidcError("no id_token")
    return validate_id_token(client, id_token, nonce=st.nonce, step_up=st.purpose == "step_up")


def validate_id_token(client: httpx.Client, token: str, *, nonce: str, step_up: bool = False) -> dict[str, Any]:
    s = get_settings()
    doc = discovery(client)
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError as e:
        raise OidcError("invalid id_token header") from e
    alg = header.get("alg")
    if alg not in s.oidc_allowed_algs:  # pins algorithms, rejects none/HS*
        raise OidcError("disallowed token algorithm")
    jwks_url = _internal(doc["jwks_uri"])
    key = None
    for attempt in range(2):
        jwks = _get_json(client, jwks_url, ttl=600)
        keys = jwks.get("keys", [])
        if not isinstance(keys, list):
            raise OidcError("invalid signing key set")
        for candidate in keys:
            if isinstance(candidate, dict) and candidate.get("kid") == header.get("kid"):
                try:
                    key = jwt.PyJWK.from_dict(candidate).key
                except jwt.PyJWTError as e:
                    raise OidcError("invalid signing key") from e
                break
        if key is not None:
            break
        if attempt == 0:
            # Keycloak can rotate keys while this worker still has the old JWKS.
            # Refresh once during this callback instead of failing a valid login.
            _cache.pop(jwks_url, None)
    if key is None:
        raise OidcError("signing key not found")
    try:
        claims = jwt.decode(
            token, key, algorithms=list(s.oidc_allowed_algs), audience=s.oidc_client_id,
            issuer=doc["issuer"], options={"require": ["exp", "iat", "iss", "aud", "sub"]}, leeway=30,
        )
    except jwt.PyJWTError as e:
        raise OidcError(f"invalid id_token: {e}") from e
    if claims.get("nonce") != nonce:
        raise OidcError("nonce mismatch")
    azp = claims.get("azp")
    if azp and azp != s.oidc_client_id:
        raise OidcError("azp mismatch")
    if step_up:
        acr = claims.get("acr")
        if acr != s.oidc_step_up_acr:
            raise OidcError("step-up authentication level not achieved")
        auth_time = claims.get("auth_time")
        now = time.time()
        if not isinstance(auth_time, (int, float)) or isinstance(auth_time, bool) or not now - 120 <= auth_time <= now + 30:
            raise OidcError("step-up authentication is not fresh")
    return claims  # type: ignore[no-any-return]


def role_from_claims(claims: dict[str, Any]) -> str | None:
    s = get_settings()
    v: Any = claims
    for part in s.oidc_role_claim.split("."):
        v = v.get(part) if isinstance(v, dict) else None
    roles = v if isinstance(v, list) else [v] if v else []
    for r in ("superadmin", "admin", "l2", "l1", "viewer"):  # highest wins
        if r in roles:
            return r
    return None


def decode_unverified_debug(token: str) -> dict[str, Any]:  # pragma: no cover - diagnostics only
    return json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "=="))
