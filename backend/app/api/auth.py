from __future__ import annotations

import logging
from datetime import timedelta
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit, oidc
from ..config import get_settings
from ..db import get_db
from ..deps import Principal, client_ip, get_principal
from ..models import OidcState, SessionRecord, User, utcnow
from ..ratelimit import limiter
from ..security import verify_password, verify_totp
from ..sessions import cookie_name, create_session

log = logging.getLogger("soc.auth")
router = APIRouter(prefix="/api/auth", tags=["auth"])

_http: httpx.Client | None = None


def get_http() -> httpx.Client:
    global _http
    if _http is None:
        _http = httpx.Client(timeout=10.0)
    return _http


def set_http(c: httpx.Client | None) -> None:
    global _http
    _http = c


class LoginIn(BaseModel):
    email: str = Field(max_length=255)
    password: str = Field(max_length=256)
    totp: str = Field(max_length=10)


class StepUpIn(BaseModel):
    password: str = Field(max_length=256)
    totp: str = Field(max_length=10)


def _set_cookie(resp: Response, raw: str) -> None:
    s = get_settings()
    resp.set_cookie(
        cookie_name(), raw, httponly=True, secure=s.cookie_secure, samesite="strict", path="/",
        max_age=s.session_absolute_hours * 3600,
    )


def me_payload(p: Principal) -> dict:
    u = p.user
    from ..policy import CAPABILITIES

    caps = sorted(c for c in CAPABILITIES if p.can(c))
    return {
        "id": u.id, "email": u.email, "name": u.name, "role": u.role, "capabilities": caps,
        "all_clients": u.all_clients, "client_ids": None if p.client_ids is None else sorted(p.client_ids),
        "csrf_token": p.session.csrf_token if p.session else None,
        "step_up_until": p.session.step_up_until.isoformat() if p.session and p.session.step_up_until else None,
        "auth_mode": get_settings().auth_mode,
        "step_up_required": get_settings().step_up_required,
    }


@router.get("/config")
def auth_config() -> dict:
    s = get_settings()
    account_url = None
    if s.auth_mode == "oidc" and s.oidc_issuer:
        account_url = s.oidc_account_url or f"{s.oidc_issuer.rstrip('/')}/account/"
    # Accounts/roles can be created from the Admin page with local accounts or the bundled Keycloak (admin API);
    # with an external OIDC provider (no Keycloak URL) they are managed in the provider.
    return {"auth_mode": s.auth_mode, "account_url": account_url, "user_provisioning": s.auth_mode == "dev" or bool(s.kc_admin_url)}


@router.post("/login")
def login(body: LoginIn, request: Request, response: Response, db: Session = Depends(get_db)) -> dict:
    s = get_settings()
    if s.auth_mode != "dev":
        raise HTTPException(404, "not found")
    ip = client_ip(request)
    email = body.email.strip().lower()
    if not limiter.allow(f"login:{ip}", s.login_rate_per_minute) or not limiter.allow(f"login-u:{email}", s.login_rate_per_minute):
        raise HTTPException(429, "too many attempts")
    user = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
    generic = HTTPException(401, "invalid credentials")
    now = utcnow()
    if user is None:
        verify_password(None, body.password)
        audit.record(db, "auth.login", actor=email, outcome="failure", ip=ip, meta={"reason": "unknown_user"})
        db.commit()
        raise generic
    if user.locked_until and user.locked_until > now:
        audit.record(db, "auth.login", actor=email, actor_id=user.id, outcome="failure", ip=ip, meta={"reason": "locked"})
        db.commit()
        raise generic
    ok = verify_password(user.password_hash, body.password) and verify_totp(user.totp_secret, body.totp) and user.active
    if not ok:
        user.failed_logins += 1
        if user.failed_logins >= 5:
            user.locked_until = now + timedelta(minutes=15)
            user.failed_logins = 0
        audit.record(db, "auth.login", actor=email, actor_id=user.id, outcome="failure", ip=ip, meta={"reason": "bad_credentials"})
        db.commit()
        raise generic
    user.failed_logins, user.locked_until, user.last_login_at = 0, None, now
    raw, rec = create_session(db, user, ip=ip, user_agent=request.headers.get("user-agent", ""), step_up=True)
    audit.record(db, "auth.login", actor=email, actor_id=user.id, ip=ip, resource_type="session", resource_id=rec.id)
    _set_cookie(response, raw)
    from ..deps import visible_clients

    p = Principal(user, rec, None, visible_clients(db, user), ip, "")
    return me_payload(p)


@router.post("/step-up")
def step_up(body: StepUpIn, p: Principal = Depends(get_principal), db: Session = Depends(get_db)) -> dict:
    s = get_settings()
    if s.auth_mode != "dev" or p.session is None:
        raise HTTPException(400, "use the identity provider for step-up")
    if not limiter.allow(f"stepup:{p.user.id}", 5):
        raise HTTPException(429, "too many attempts")
    if not (verify_password(p.user.password_hash, body.password) and verify_totp(p.user.totp_secret, body.totp)):
        audit.record(db, "auth.step_up", actor=p.label, actor_id=p.user.id, outcome="failure", ip=p.ip)
        db.commit()
        raise HTTPException(401, "invalid credentials")
    p.session.step_up_until = utcnow() + timedelta(minutes=s.step_up_minutes)
    audit.record(db, "auth.step_up", actor=p.label, actor_id=p.user.id, ip=p.ip)
    return me_payload(p)


@router.get("/me")
def me(p: Principal = Depends(get_principal)) -> dict:
    return me_payload(p)


@router.post("/logout")
def logout(response: Response, p: Principal = Depends(get_principal), db: Session = Depends(get_db)) -> dict:
    if p.session:
        p.session.revoked = True
    audit.record(db, "auth.logout", actor=p.label, actor_id=p.user.id, ip=p.ip)
    response.delete_cookie(cookie_name(), path="/")
    return {"ok": True, "end_session_url": oidc.end_session_url() if get_settings().auth_mode == "oidc" else None}


@router.get("/sessions")
def my_sessions(p: Principal = Depends(get_principal), db: Session = Depends(get_db)) -> list[dict]:
    rows = db.execute(
        select(SessionRecord).where(SessionRecord.user_id == p.user.id, SessionRecord.revoked.is_(False), SessionRecord.expires_at > utcnow())
    ).scalars()
    return [
        {"id": r.id, "created_at": r.created_at, "last_seen_at": r.last_seen_at, "ip": r.ip, "user_agent": r.user_agent,
         "current": bool(p.session and p.session.id == r.id)} for r in rows
    ]


@router.delete("/sessions/{sid}")
def revoke_session(sid: str, p: Principal = Depends(get_principal), db: Session = Depends(get_db)) -> dict:
    rec = db.get(SessionRecord, sid)
    if rec is None or rec.user_id != p.user.id:
        raise HTTPException(404, "not found")
    rec.revoked = True
    audit.record(db, "auth.session_revoke", actor=p.label, actor_id=p.user.id, resource_type="session", resource_id=sid)
    return {"ok": True}


# ------------------------------------------------------------------ OIDC
def _oidc_failure(request: Request, db: Session, reason: str, *, status: int = 400, return_to: str = "/app") -> RedirectResponse:
    """Give browser navigations a safe recovery path and log a traceable cause."""
    reference = getattr(request.state, "correlation_id", "")
    audit.record(db, "auth.oidc_failure", outcome="failure", ip=client_ip(request), correlation_id=reference, meta={"reason": reason})
    log.warning("OIDC authentication failed reason=%s reference=%s", reason, reference)
    db.commit()
    if "text/html" not in request.headers.get("accept", "").lower():
        raise HTTPException(status, "authentication failed")
    destination = oidc.safe_return_to(return_to)
    if urlsplit(destination).path == "/login":
        destination = oidc.safe_return_to(parse_qs(urlsplit(destination).query).get("next", ["/app"])[0])
    params = urlencode({"auth_error": reason, "ref": reference, "next": destination})
    response = RedirectResponse(f"/login?{params}", status_code=302)
    response.headers["Cache-Control"] = "no-store"
    return response


@router.get("/oidc/login")
def oidc_login(request: Request, return_to: str = "/", db: Session = Depends(get_db)) -> RedirectResponse:
    if get_settings().auth_mode != "oidc":
        raise HTTPException(404, "not found")
    try:
        url = oidc.authorization_url(db, get_http(), return_to=return_to)
    except (httpx.HTTPError, oidc.OidcError):
        return _oidc_failure(request, db, "identity_provider", status=502, return_to=return_to)
    return RedirectResponse(url, status_code=302)


@router.get("/oidc/step-up")
def oidc_step_up(p: Principal = Depends(get_principal), return_to: str = "/", db: Session = Depends(get_db)) -> RedirectResponse:
    if get_settings().auth_mode != "oidc" or p.session is None:
        raise HTTPException(404, "not found")
    try:
        url = oidc.authorization_url(db, get_http(), purpose="step_up", return_to=return_to, session_id=p.session.id)
    except (httpx.HTTPError, oidc.OidcError):
        raise HTTPException(502, "identity provider unavailable") from None
    return RedirectResponse(url, status_code=302)


@router.get("/oidc/callback")
def oidc_callback(request: Request, code: str = "", state: str = "", error: str = "", db: Session = Depends(get_db)) -> RedirectResponse:
    s = get_settings()
    if s.auth_mode != "oidc":
        raise HTTPException(404, "not found")
    st = db.get(OidcState, state) if state else None
    if st is None:
        return _oidc_failure(request, db, "invalid_state")
    return_to = st.return_to
    if st.expires_at <= utcnow() or error or not code:
        reason = "expired_state" if st.expires_at <= utcnow() else "provider_denied" if error else "missing_code"
        db.delete(st)
        return _oidc_failure(request, db, reason, return_to=return_to)
    db.delete(st)  # single use
    db.flush()
    ip = client_ip(request)
    try:
        claims = oidc.exchange_and_validate(get_http(), code, st)
    except (oidc.OidcError, httpx.HTTPError) as e:
        audit.record(db, "auth.login", outcome="failure", ip=ip, meta={"reason": "oidc_validation"})
        log.warning("OIDC validation rejected purpose=%s cause=%s reference=%s", st.purpose, str(e)[:200], getattr(request.state, "correlation_id", ""))
        reason = "identity_provider" if isinstance(e, httpx.HTTPError) else "mfa_required" if st.purpose == "step_up" else "token_validation"
        return _oidc_failure(request, db, reason, return_to=return_to)
    role = oidc.role_from_claims(claims)
    if role is None:
        audit.record(db, "auth.login", actor=str(claims.get("email", claims["sub"])), outcome="failure", ip=ip, meta={"reason": "no_role"})
        return _oidc_failure(request, db, "no_role", status=403, return_to=return_to)
    user = db.execute(select(User).where(User.subject == claims["sub"])).scalar_one_or_none()
    if user is None and claims.get("email") and claims.get("email_verified") is True:
        pending = db.execute(select(User).where(User.email == str(claims["email"]).lower(), User.subject.startswith("pending:"))).scalar_one_or_none()
        if pending is not None:
            pending.subject = claims["sub"]
            user = pending
    if user is None:
        email_claim = str(claims.get("email", f"{claims['sub']}@unknown")).lower()
        if db.execute(select(User.id).where(User.email == email_claim)).first():
            audit.record(db, "auth.login", actor=email_claim, outcome="failure", ip=ip, meta={"reason": "email_conflict"})
            return _oidc_failure(request, db, "account_conflict", status=403, return_to=return_to)
        user = User(subject=claims["sub"], email=email_claim, name=str(claims.get("name", "")), role=role, all_clients=role == "superadmin")
        db.add(user)
        db.flush()
    else:
        user.role = role
        user.name = str(claims.get("name", user.name))
    if not user.active:
        return _oidc_failure(request, db, "account_disabled", status=403, return_to=return_to)
    user.last_login_at = utcnow()
    if st.purpose == "step_up" and st.session_id:
        rec = db.get(SessionRecord, st.session_id)
        if rec is None or rec.user_id != user.id or rec.revoked or rec.expires_at <= utcnow() or utcnow() - rec.last_seen_at > timedelta(minutes=s.session_idle_minutes):
            return _oidc_failure(request, db, "session_expired", return_to=return_to)
        rec.step_up_until = utcnow() + timedelta(minutes=s.step_up_minutes)
        audit.record(db, "auth.step_up", actor=user.email, actor_id=user.id, ip=ip)
        return RedirectResponse(oidc.safe_return_to(st.return_to), status_code=302)
    raw, rec = create_session(
        db, user, ip=ip, user_agent=request.headers.get("user-agent", ""), step_up=False,  # step-up is never auto-granted on login; admin actions trigger explicit re-auth
        oidc_sid=claims.get("sid"),
    )
    audit.record(db, "auth.login", actor=user.email, actor_id=user.id, ip=ip, resource_type="session", resource_id=rec.id)
    resp = RedirectResponse(oidc.safe_return_to(st.return_to), status_code=302)
    _set_cookie(resp, raw)
    return resp
