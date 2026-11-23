"""FastAPI dependencies: authentication, CSRF, RBAC and client scoping."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from fastapi import Depends, HTTPException, Request
from sqlalchemy import ColumnElement, false, select, true
from sqlalchemy.orm import Session

from .config import get_settings
from .db import get_db
from .models import ApiToken, ClientMembership, SessionRecord, User, utcnow
from .policy import has_capability
from .security import constant_eq, sha256_hex
from .sessions import cookie_name, load_session

UNSAFE = {"POST", "PUT", "PATCH", "DELETE"}


@dataclass
class Principal:
    user: User
    session: SessionRecord | None
    token: ApiToken | None
    client_ids: frozenset[str] | None  # None = all clients
    ip: str
    correlation_id: str

    @property
    def label(self) -> str:
        return self.user.email

    @property
    def is_superadmin(self) -> bool:
        """Owner authority is interactive; API tokens never inherit approval bypass."""
        return self.user.role == "superadmin" and self.session is not None and self.token is None

    def can(self, cap: str) -> bool:
        if self.token is not None and cap not in (self.token.scopes or []) and "*" not in (self.token.scopes or []):
            return False
        return has_capability(self.user.role, self.user.grants, cap, self.user.denied)

    def can_see_client(self, client_id: str | None) -> bool:
        if self.client_ids is None:
            return True
        return client_id is not None and client_id in self.client_ids

    def scope(self, col: Any) -> ColumnElement[bool]:
        """SQL filter restricting rows to clients this principal may see (NULL = admin-only)."""
        if self.client_ids is None:
            return true()
        if not self.client_ids:
            return false()
        return col.in_(self.client_ids)


def client_ip(request: Request) -> str:
    return request.client.host if request.client else ""


def _origin_ok(request: Request) -> bool:
    origin = request.headers.get("origin")
    if origin is None:
        return True  # non-browser client; CSRF header still required
    allowed = set(get_settings().allowed_origins) | {get_settings().public_base_url.rstrip("/")}
    return origin.rstrip("/") in allowed


def visible_clients(db: Session, user: User) -> frozenset[str] | None:
    if user.all_clients:
        return None
    rows = db.execute(select(ClientMembership.client_id).where(ClientMembership.user_id == user.id)).scalars()
    return frozenset(rows)


def get_principal(request: Request, db: Session = Depends(get_db)) -> Principal:
    cid = getattr(request.state, "correlation_id", "")
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        tok = db.execute(select(ApiToken).where(ApiToken.token_hash == sha256_hex(auth[7:].strip()))).scalar_one_or_none()
        if tok is None or tok.revoked or tok.expires_at <= utcnow():
            raise HTTPException(401, "invalid token")
        user = db.get(User, tok.user_id)
        if user is None or not user.active:
            raise HTTPException(401, "invalid token")
        tok.last_used_at = utcnow()
        return Principal(user, None, tok, visible_clients(db, user), client_ip(request), cid)
    raw = request.cookies.get(cookie_name())
    if not raw:
        raise HTTPException(401, "not authenticated")
    rec = load_session(db, raw)
    if rec is None:
        db.commit()  # persist revocation of expired session
        raise HTTPException(401, "session expired")
    user = db.get(User, rec.user_id)
    if user is None or not user.active:
        raise HTTPException(401, "account disabled")
    if request.method in UNSAFE:
        hdr = request.headers.get("x-csrf-token", "")
        if not hdr or not constant_eq(hdr, rec.csrf_token) or not _origin_ok(request):
            raise HTTPException(403, "CSRF validation failed")
    return Principal(user, rec, None, visible_clients(db, user), client_ip(request), cid)


def require(cap: str) -> Callable[..., Principal]:
    def dep(p: Principal = Depends(get_principal)) -> Principal:
        if not p.can(cap):
            raise HTTPException(403, f"missing capability {cap}")
        return p

    return dep


def require_step_up(p: Principal = Depends(get_principal)) -> Principal:
    if p.session is None:
        raise HTTPException(403, {"code": "step_up_required", "detail": "interactive session required"})
    if not get_settings().step_up_required:  # re-verification is off: a signed-in session is enough (API tokens are still refused above)
        return p
    if p.session.step_up_until is None or p.session.step_up_until <= utcnow():
        raise HTTPException(403, {"code": "step_up_required", "detail": "recent MFA required"})
    return p


def require_admin_step_up(cap: str) -> Callable[..., Principal]:
    def dep(p: Principal = Depends(require(cap))) -> Principal:
        return require_step_up(p)

    return dep


def scoped_get(db: Session, model: Any, id_: str, p: Principal, client_attr: str = "client_id") -> Any:
    """Fetch by id; 404 (not 403) when outside the principal's client scope."""
    obj = db.get(model, id_)
    if obj is None or not p.can_see_client(getattr(obj, client_attr, None)):
        raise HTTPException(404, "not found")
    return obj
