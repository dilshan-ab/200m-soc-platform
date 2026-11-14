from __future__ import annotations

import csv
import io
from datetime import datetime, timedelta
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit
from .. import keycloak_admin as kc
from ..config import get_settings
from ..db import get_db
from ..deps import Principal, require, require_admin_step_up
from ..models import ApiToken, AuditEvent, BackupJob, Client, ClientMembership, RetentionPolicy, SessionRecord, SlaPolicy, User, utcnow
from ..policy import CAPABILITIES, ROLES, SEVERITIES, role_capabilities, set_role_overrides
from ..security import hash_password, new_token, new_totp_secret, password_policy_ok, sha256_hex
from ..services.settings_svc import get_setting, set_setting
from ..sessions import revoke_all
from ..sla import active_policy
from .approvals import create_change
from .auth import get_http
from .common import iso, page_out, paginate

router = APIRouter(prefix="/api", tags=["admin"])


# ------------------------------------------------------------------------ users
def user_out(db: Session, u: User) -> dict[str, Any]:
    cids = list(db.execute(select(ClientMembership.client_id).where(ClientMembership.user_id == u.id)).scalars())
    return {"id": u.id, "email": u.email, "name": u.name, "role": u.role, "grants": u.grants, "denied": u.denied, "all_clients": u.all_clients, "client_ids": cids, "active": u.active, "last_login_at": iso(u.last_login_at)}


@router.get("/admin/users")
def list_users(p: Principal = Depends(require("admin.users")), db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    return [user_out(db, u) for u in db.execute(select(User).where(User.subject != "system:automation").order_by(User.email)).scalars()]


@router.get("/users/assignable")
def assignable(p: Principal = Depends(require("alerts.triage")), db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    return [{"id": u.id, "name": u.name or u.email} for u in db.execute(select(User).where(User.active.is_(True), User.role.in_(["l1", "l2", "admin"]))).scalars()]


class UserIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str = Field(max_length=255, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    name: str = Field(default="", max_length=160)
    role: Literal["viewer", "l1", "l2", "admin"] = "viewer"
    password: str | None = Field(default=None, max_length=256)
    all_clients: bool = False
    client_ids: list[str] = Field(default_factory=list, max_length=100)


def _external_idp() -> bool:
    """SSO through a provider other than the bundled Keycloak: no admin API, so accounts/roles live in the IdP.
    (A Keycloak URL that is set but incomplete is a misconfiguration instead — _kc reports that as 503.)"""
    s = get_settings()
    return s.auth_mode == "oidc" and not s.kc_admin_url


def _kc(fn: Any, *a: Any) -> Any:
    if not kc.configured():
        raise HTTPException(503, "Keycloak admin access is not configured (SOC_KC_ADMIN_URL / SOC_KC_ADMIN_CLIENT_SECRET)")
    try:
        return fn(get_http(), *a)
    except kc.KcError as e:
        raise HTTPException(e.status if e.status in (400, 404, 409) else 502, str(e)) from None


@router.post("/admin/users", status_code=201)
def create_user(body: UserIn, p: Principal = Depends(require_admin_step_up("users.provision")), db: Session = Depends(get_db)) -> dict[str, Any]:
    s = get_settings()
    email = body.email.strip().lower()
    if db.execute(select(User.id).where(User.email == email)).first():
        raise HTTPException(409, "user exists")
    u = User(subject=f"dev:{email}" if s.auth_mode == "dev" else f"pending:{email}", email=email, name=body.name, role=body.role, all_clients=body.all_clients)
    out: dict[str, Any] = {}
    if s.auth_mode == "dev":
        if not body.password or not password_policy_ok(body.password):
            raise HTTPException(400, "password must be 12+ chars with upper, lower and a digit")
        u.password_hash, u.totp_secret = hash_password(body.password), new_totp_secret()
        out["totp_secret"] = u.totp_secret  # shown once for authenticator enrolment
    else:  # SSO: the account is created in Keycloak (temporary password, forced change + authenticator enrolment)
        if _external_idp():
            raise HTTPException(400, "user accounts are managed in the identity provider; create the user there and assign a SOC role")
        if not body.password or not password_policy_ok(body.password):
            raise HTTPException(400, "initial password must be 12+ chars with upper, lower and a digit")
        for cid in body.client_ids:
            if db.get(Client, cid) is None:
                raise HTTPException(400, "unknown client")
        _kc(kc.create_user, email, body.name, body.role, body.password)
    db.add(u)
    db.flush()
    for cid in dict.fromkeys(body.client_ids):
        if db.get(Client, cid) is None:
            raise HTTPException(400, "unknown client")
        db.add(ClientMembership(user_id=u.id, client_id=cid))
    audit.record(db, "user.create", actor=p.label, actor_id=p.user.id, resource_type="user", resource_id=u.id, ip=p.ip, meta={"email": email, "role": u.role})
    return {**user_out(db, u), **out}


class UserPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str | None = Field(default=None, max_length=160)
    role: Literal["viewer", "l1", "l2", "admin"] | None = None
    grants: list[str] | None = Field(default=None, max_length=40)
    denied: list[str] | None = Field(default=None, max_length=40)
    all_clients: bool | None = None
    client_ids: list[str] | None = Field(default=None, max_length=100)
    active: bool | None = None


@router.patch("/admin/users/{uid}")
def patch_user(uid: str, body: UserPatch, p: Principal = Depends(require_admin_step_up("admin.users")), db: Session = Depends(get_db)) -> dict[str, Any]:
    u = db.get(User, uid)
    if u is None:
        raise HTTPException(404, "not found")
    if u.id == p.user.id:
        raise HTTPException(403, "you cannot change your own account")
    if u.role == "superadmin":
        raise HTTPException(403, "the super admin account cannot be modified from here")
    meta: dict[str, Any] = {}
    result_note: dict[str, Any] = {}
    if body.role and body.role != u.role:
        if get_settings().auth_mode == "oidc":
            if not p.can("users.provision"):
                raise HTTPException(403, "only the super admin can change roles")
            if _external_idp():  # the role is re-read from the IdP's claim at every login, so a local edit would not stick
                raise HTTPException(400, "roles are managed in the identity provider; change the user's role there")
            _kc(kc.set_role, u.email, body.role)
            u.role = body.role
            revoke_all(db, u.id)
            meta["role"] = body.role
        elif body.role == "admin":
            cr = create_change(db, "user.role", {"user_id": u.id, "role": "admin"}, p.user, f"Promote {u.email} to admin")
            result_note["pending_approval"] = cr.id
        else:
            u.role = body.role
            revoke_all(db, u.id)
            meta["role"] = body.role
    if body.grants is not None or body.denied is not None:
        if not p.can("users.provision"):
            raise HTTPException(403, "only the super admin can change permissions")
        new_grants = body.grants if body.grants is not None else u.grants
        new_denied = body.denied if body.denied is not None else u.denied
        bad = [c for c in (*new_grants, *new_denied) if c not in CAPABILITIES]
        if bad:
            raise HTTPException(400, f"unknown capabilities: {bad}")
        overlap = set(new_grants) & set(new_denied)
        if overlap:
            raise HTTPException(400, f"capabilities cannot be both granted and denied: {sorted(overlap)}")
        if body.grants is not None:
            u.grants, meta["grants"] = body.grants, body.grants
        if body.denied is not None:
            u.denied, meta["denied"] = body.denied, body.denied
    if body.name is not None:
        u.name = body.name
    if body.all_clients is not None:
        u.all_clients, meta["all_clients"] = body.all_clients, body.all_clients
    if body.client_ids is not None:
        for m in db.execute(select(ClientMembership).where(ClientMembership.user_id == u.id)).scalars():
            db.delete(m)
        db.flush()
        for cid in dict.fromkeys(body.client_ids):
            if db.get(Client, cid) is None:
                raise HTTPException(400, "unknown client")
            db.add(ClientMembership(user_id=u.id, client_id=cid))
        meta["client_ids"] = body.client_ids
    if body.active is not None and body.active != u.active:
        if get_settings().auth_mode == "oidc" and kc.configured() and p.can("users.provision"):
            _kc(kc.set_enabled, u.email, body.active)
        u.active = body.active
        meta["active"] = body.active
        if not body.active:
            revoke_all(db, u.id)
            for t in db.execute(select(ApiToken).where(ApiToken.user_id == u.id)).scalars():
                t.revoked = True
    audit.record(db, "user.update", actor=p.label, actor_id=p.user.id, resource_type="user", resource_id=u.id, ip=p.ip, meta=meta)
    return {**user_out(db, u), **result_note}


@router.post("/admin/users/{uid}/revoke-sessions")
def revoke_sessions(uid: str, p: Principal = Depends(require("admin.users")), db: Session = Depends(get_db)) -> dict[str, int]:
    n = revoke_all(db, uid)
    audit.record(db, "user.revoke_sessions", actor=p.label, actor_id=p.user.id, resource_type="user", resource_id=uid, ip=p.ip, meta={"count": n})
    return {"revoked": n}


# ------------------------------------------------------------------------ api tokens
class TokenIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=2, max_length=120)
    scopes: list[str] = Field(min_length=1, max_length=40)
    days: int = Field(default=30, ge=1, le=90)


@router.get("/tokens")
def my_tokens(p: Principal = Depends(require("admin.tokens")), db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    return [{"id": t.id, "name": t.name, "prefix": t.prefix, "scopes": t.scopes, "expires_at": iso(t.expires_at), "last_used_at": iso(t.last_used_at), "revoked": t.revoked}
            for t in db.execute(select(ApiToken).where(ApiToken.user_id == p.user.id).order_by(ApiToken.created_at.desc())).scalars()]


@router.post("/tokens", status_code=201)
def create_token(body: TokenIn, p: Principal = Depends(require("admin.tokens")), db: Session = Depends(get_db)) -> dict[str, Any]:
    if p.token is not None:
        raise HTTPException(403, "tokens can only be created from an interactive session")
    bad = [s for s in body.scopes if s not in CAPABILITIES or not p.can(s)]
    if bad:
        raise HTTPException(400, f"invalid or unavailable scopes: {bad}")
    active = [t for t in db.execute(select(ApiToken).where(ApiToken.user_id == p.user.id, ApiToken.revoked.is_(False), ApiToken.expires_at > utcnow())).scalars()]
    if len(active) >= 5:
        raise HTTPException(409, "token limit reached (5)")
    raw = "soc_" + new_token(32)
    t = ApiToken(user_id=p.user.id, name=body.name, token_hash=sha256_hex(raw), prefix=raw[:10], scopes=body.scopes, expires_at=utcnow() + timedelta(days=body.days))
    db.add(t)
    db.flush()
    audit.record(db, "token.create", actor=p.label, actor_id=p.user.id, resource_type="api_token", resource_id=t.id, ip=p.ip, meta={"scopes": body.scopes})
    return {"id": t.id, "token": raw, "expires_at": iso(t.expires_at), "note": "shown once"}


@router.delete("/tokens/{tid}")
def revoke_token(tid: str, p: Principal = Depends(require("admin.tokens")), db: Session = Depends(get_db)) -> dict[str, bool]:
    t = db.get(ApiToken, tid)
    if t is None or (t.user_id != p.user.id and not p.can("admin.users")):
        raise HTTPException(404, "not found")
    t.revoked = True
    audit.record(db, "token.revoke", actor=p.label, actor_id=p.user.id, resource_type="api_token", resource_id=tid, ip=p.ip)
    return {"ok": True}


# ------------------------------------------------------------------------ audit
@router.get("/admin/audit")
def list_audit(p: Principal = Depends(require("admin.audit")), db: Session = Depends(get_db), action: str | None = None, actor: str | None = None, outcome: str | None = None,
               since: datetime | None = None, until: datetime | None = None, page: int = 1, limit: int = 100) -> dict[str, Any]:
    q = select(AuditEvent)
    if action:
        q = q.where(AuditEvent.action.startswith(action, autoescape=True))
    if actor:
        q = q.where(AuditEvent.actor.contains(actor, autoescape=True))
    if outcome:
        q = q.where(AuditEvent.outcome == outcome)
    if since:
        q = q.where(AuditEvent.ts >= since)
    if until:
        q = q.where(AuditEvent.ts <= until)
    rows, total = paginate(db, q.order_by(AuditEvent.id.desc()), page, limit)
    return page_out([{"id": e.id, "ts": iso(e.ts), "actor": e.actor, "action": e.action, "resource_type": e.resource_type, "resource_id": e.resource_id, "outcome": e.outcome, "ip": e.ip, "meta": e.meta, "hash": e.hash} for e in rows], total, page, limit)


@router.get("/admin/audit/verify")
def verify_audit(p: Principal = Depends(require("admin.audit")), db: Session = Depends(get_db)) -> dict[str, Any]:
    return audit.verify_chain(db)


@router.get("/admin/audit/export")
def export_audit(p: Principal = Depends(require_admin_step_up("admin.audit")), db: Session = Depends(get_db), since: datetime | None = None) -> Response:
    q = select(AuditEvent).order_by(AuditEvent.id).limit(50000)
    if since:
        q = q.where(AuditEvent.ts >= since)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["id", "ts", "actor", "action", "resource_type", "resource_id", "outcome", "ip", "hash", "prev_hash"])
    from .. import audit as a
    from ..services.reports import _csv_safe

    for e in db.execute(q).scalars():
        w.writerow([e.id, iso(e.ts), _csv_safe(e.actor), e.action, e.resource_type, _csv_safe(e.resource_id), e.outcome, e.ip, e.hash, e.prev_hash])
    a.record(db, "audit.export", actor=p.label, actor_id=p.user.id, ip=p.ip)
    return Response(buf.getvalue(), media_type="text/csv", headers={"Content-Disposition": 'attachment; filename="audit.csv"'})


# ------------------------------------------------------------------------ SLA
@router.get("/admin/sla")
def get_sla(p: Principal = Depends(require("alerts.read")), db: Session = Depends(get_db)) -> dict[str, Any]:
    pol = active_policy(db)
    hist = [{"version": h.version, "active": h.active, "effective_from": iso(h.effective_from), "created_by": h.created_by, "note": h.note} for h in db.execute(select(SlaPolicy).order_by(SlaPolicy.version.desc()).limit(20)).scalars()]
    return {"version": pol.version, "targets": pol.targets, "pause_statuses": pol.pause_statuses, "history": hist}


class SlaIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    targets: dict[str, dict[str, int]]
    note: str = Field(default="", max_length=500)


@router.put("/admin/sla")
def put_sla(body: SlaIn, p: Principal = Depends(require_admin_step_up("admin.settings")), db: Session = Depends(get_db)) -> dict[str, Any]:
    if set(body.targets) != set(SEVERITIES):
        raise HTTPException(400, f"targets are required for every severity: {SEVERITIES}")
    for sev, t in body.targets.items():
        if set(t) != {"ack_minutes", "resolve_minutes"} or not (0 < t["ack_minutes"] <= t["resolve_minutes"] <= 60 * 24 * 90):
            raise HTTPException(400, f"invalid targets for {sev}: need 0 < ack_minutes <= resolve_minutes")
    cur = active_policy(db)
    cur.active = False
    new = SlaPolicy(version=cur.version + 1, active=True, targets=body.targets, pause_statuses=cur.pause_statuses, note=body.note, created_by=p.label)
    db.add(new)
    db.flush()
    audit.record(db, "sla.update", actor=p.label, actor_id=p.user.id, ip=p.ip, meta={"version": new.version})
    return {"version": new.version, "targets": new.targets}


# ------------------------------------------------------------------------ settings & retention
EDITABLE = {"alert_dedup_minutes": (1, 120), "approval_window_minutes": (5, 1440), "response_max_per_hour": (1, 500)}


@router.get("/admin/settings")
def get_settings_api(p: Principal = Depends(require("admin.settings")), db: Session = Depends(get_db)) -> dict[str, Any]:
    return {k: get_setting(db, k) for k in EDITABLE}


class SettingsIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    values: dict[str, int]


@router.put("/admin/settings")
def put_settings(body: SettingsIn, p: Principal = Depends(require_admin_step_up("admin.settings")), db: Session = Depends(get_db)) -> dict[str, Any]:
    for k, v in body.values.items():
        if k not in EDITABLE or not (EDITABLE[k][0] <= v <= EDITABLE[k][1]):
            raise HTTPException(400, f"invalid setting {k}")
    for k, v in body.values.items():
        set_setting(db, k, v)
    audit.record(db, "settings.update", actor=p.label, actor_id=p.user.id, ip=p.ip, meta=body.values)
    return {k: get_setting(db, k) for k in EDITABLE}


MIN_DAYS = {"alerts": 30, "cases": 180, "audit": 365, "raw_events": 7, "reports": 30}


@router.get("/admin/retention")
def get_retention(p: Principal = Depends(require("admin.settings")), db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    return [{"dataset": r.dataset, "days": r.days, "legal_hold": r.legal_hold, "min_days": MIN_DAYS.get(r.dataset, 1)} for r in db.execute(select(RetentionPolicy).order_by(RetentionPolicy.dataset)).scalars()]


class RetentionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    dataset: str
    days: int = Field(ge=1, le=3650)
    legal_hold: bool = False


@router.put("/admin/retention")
def put_retention(body: RetentionIn, p: Principal = Depends(require_admin_step_up("admin.settings")), db: Session = Depends(get_db)) -> dict[str, Any]:
    if body.dataset not in MIN_DAYS:
        raise HTTPException(400, "unknown dataset")
    if body.days < MIN_DAYS[body.dataset]:
        raise HTTPException(400, f"minimum retention for {body.dataset} is {MIN_DAYS[body.dataset]} days")
    cur = db.execute(select(RetentionPolicy).where(RetentionPolicy.dataset == body.dataset)).scalar_one_or_none()
    if cur is None or body.days < cur.days or (cur.legal_hold and not body.legal_hold):
        cr = create_change(db, "retention.update", body.model_dump(), p.user, f"Retention {body.dataset} -> {body.days}d")
        audit.record(db, "retention.requested", actor=p.label, actor_id=p.user.id, ip=p.ip, meta=body.model_dump())
        return {"pending_approval": cr.id}
    cur.days, cur.legal_hold = body.days, body.legal_hold
    audit.record(db, "retention.update", actor=p.label, actor_id=p.user.id, ip=p.ip, meta=body.model_dump())
    return {"dataset": cur.dataset, "days": cur.days, "legal_hold": cur.legal_hold}


# ------------------------------------------------------------------------ backups
@router.get("/admin/backups")
def backups(p: Principal = Depends(require("admin.backups")), db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    return [{"id": b.id, "name": b.name, "component": b.component, "last_status": b.last_status, "last_success_at": iso(b.last_success_at), "last_verified_at": iso(b.last_verified_at), "size_bytes": b.size_bytes} for b in db.execute(select(BackupJob).order_by(BackupJob.name)).scalars()]


class BackupIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=2, max_length=160)
    component: Literal["postgres", "vault", "config", "reports", "search"]


@router.post("/admin/backups", status_code=201)
def add_backup(body: BackupIn, p: Principal = Depends(require_admin_step_up("admin.backups")), db: Session = Depends(get_db)) -> dict[str, str]:
    b = BackupJob(name=body.name, component=body.component)
    db.add(b)
    db.flush()
    audit.record(db, "backup.register", actor=p.label, actor_id=p.user.id, resource_type="backup", resource_id=b.id, ip=p.ip)
    return {"id": b.id}


class BackupReport(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Literal["success", "failed"]
    size_bytes: int = Field(default=0, ge=0)
    verified: bool = False


@router.post("/admin/backups/{bid}/report")
def report_backup(bid: str, body: BackupReport, p: Principal = Depends(require("admin.backups")), db: Session = Depends(get_db)) -> dict[str, Any]:
    b = db.get(BackupJob, bid)
    if b is None:
        raise HTTPException(404, "not found")
    b.last_status, b.size_bytes = body.status, body.size_bytes
    if body.status == "success":
        b.last_success_at = utcnow()
        if body.verified:
            b.last_verified_at = utcnow()
    audit.record(db, "backup.report", actor=p.label, actor_id=p.user.id, resource_type="backup", resource_id=b.id, ip=p.ip, outcome="success" if body.status == "success" else "failure")
    return {"ok": True}


# ------------------------------------------------------------------------ misc
@router.get("/admin/roles")
def roles(p: Principal = Depends(require("admin.users"))) -> dict[str, Any]:
    return {"roles": ROLES, "capabilities": CAPABILITIES}


@router.get("/admin/permissions")
def get_permissions(p: Principal = Depends(require("admin.users"))) -> dict[str, Any]:
    all_caps = list(CAPABILITIES.keys())
    matrix: dict[str, list[str]] = {}
    for role in ROLES:
        matrix[role] = role_capabilities(role)
    return {"roles": ROLES, "capabilities": all_caps, "defaults": CAPABILITIES, "matrix": matrix}


class PermissionsIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    matrix: dict[str, list[str]]


@router.put("/admin/permissions")
def set_permissions(body: PermissionsIn, p: Principal = Depends(require_admin_step_up("users.provision")), db: Session = Depends(get_db)) -> dict[str, str]:
    all_caps = set(CAPABILITIES.keys())
    for role, caps in body.matrix.items():
        if role not in ROLES:
            raise HTTPException(400, f"unknown role: {role}")
        bad = [c for c in caps if c not in all_caps]
        if bad:
            raise HTTPException(400, f"unknown capabilities: {bad}")
    if "superadmin" in body.matrix:
        body.matrix["superadmin"] = list(all_caps)
    set_setting(db, "role_permissions", body.matrix)
    set_role_overrides(body.matrix)
    audit.record(db, "permissions.update", actor=p.label, actor_id=p.user.id, ip=p.ip, meta={"roles": list(body.matrix.keys())})
    return {"status": "ok"}


@router.get("/admin/sessions")
def active_sessions(p: Principal = Depends(require("admin.users")), db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    out = []
    for s in db.execute(select(SessionRecord).where(SessionRecord.revoked.is_(False), SessionRecord.expires_at > utcnow()).order_by(SessionRecord.last_seen_at.desc()).limit(200)).scalars():
        u = db.get(User, s.user_id)
        out.append({"id": s.id, "user": u.email if u else "", "ip": s.ip, "created_at": iso(s.created_at), "last_seen_at": iso(s.last_seen_at)})
    return out
