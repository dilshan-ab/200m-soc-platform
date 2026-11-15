"""MSSP tenant management: branding, membership, and the cross-tenant rollup dashboard.
The basic GET/POST /api/clients endpoints already live in assets.py; this module adds
the admin and MSSP-specific surface on the same prefix."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import audit
from ..db import get_db
from ..deps import Principal, require, require_admin_step_up
from ..models import Alert, Case, Client, ClientMembership, User
from .common import iso

router = APIRouter(prefix="/api/clients", tags=["clients"])


def _client_out(c: Client) -> dict[str, Any]:
    return {
        "id": c.id, "name": c.name, "code": c.code, "kind": c.kind, "parent_id": c.parent_id, "owner": c.owner,
        "report_recipients": c.report_recipients, "active": c.active, "logo_url": c.logo_url, "brand_color": c.brand_color,
        "timezone": c.timezone, "contact_email": c.contact_email, "tier": c.tier, "created_at": iso(c.created_at),
    }


@router.get("/{cid}")
def get_client(cid: str, p: Principal = Depends(require("clients.read")), db: Session = Depends(get_db)) -> dict[str, Any]:
    c = db.get(Client, cid)
    if c is None or not p.can_see_client(cid):
        raise HTTPException(404, "not found")
    return _client_out(c)


class ClientPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str | None = Field(default=None, min_length=1, max_length=120)
    owner: str | None = Field(default=None, max_length=120)
    logo_url: str | None = Field(default=None, max_length=500)
    brand_color: str | None = Field(default=None, max_length=10, pattern=r"^$|^#[0-9a-fA-F]{3,8}$")
    timezone: str | None = Field(default=None, max_length=60)
    contact_email: str | None = Field(default=None, max_length=255)
    tier: str | None = Field(default=None, pattern="^(standard|premium)$")
    active: bool | None = None
    report_recipients: list[str] | None = Field(default=None, max_length=20)


@router.patch("/{cid}")
def update_client(cid: str, body: ClientPatch, p: Principal = Depends(require_admin_step_up("clients.write")), db: Session = Depends(get_db)) -> dict[str, Any]:
    c = db.get(Client, cid)
    if c is None:
        raise HTTPException(404, "not found")
    changed = body.model_dump(exclude_unset=True)
    for k, v in changed.items():
        setattr(c, k, v)
    audit.record(db, "client.update", actor=p.label, actor_id=p.user.id, resource_type="client", resource_id=c.id, ip=p.ip, meta={"fields": sorted(changed)})
    return _client_out(c)


@router.get("/{cid}/members")
def list_members(cid: str, p: Principal = Depends(require("clients.read")), db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    if db.get(Client, cid) is None or not p.can_see_client(cid):
        raise HTTPException(404, "not found")
    rows = db.execute(select(ClientMembership, User).join(User, User.id == ClientMembership.user_id).where(ClientMembership.client_id == cid)).all()
    return [{"membership_id": m.id, "user_id": u.id, "name": u.name, "email": u.email, "role": u.role, "active": u.active} for m, u in rows]


class MemberIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    user_id: str


@router.post("/{cid}/members", status_code=201)
def add_member(cid: str, body: MemberIn, p: Principal = Depends(require_admin_step_up("clients.manage_members")), db: Session = Depends(get_db)) -> dict[str, Any]:
    if db.get(Client, cid) is None:
        raise HTTPException(404, "client not found")
    if db.get(User, body.user_id) is None:
        raise HTTPException(404, "user not found")
    if db.execute(select(ClientMembership.id).where(ClientMembership.client_id == cid, ClientMembership.user_id == body.user_id)).first():
        raise HTTPException(409, "already a member")
    m = ClientMembership(client_id=cid, user_id=body.user_id)
    db.add(m)
    db.flush()
    audit.record(db, "client.member_add", actor=p.label, actor_id=p.user.id, resource_type="client", resource_id=cid, ip=p.ip, meta={"user_id": body.user_id})
    return {"id": m.id}


@router.delete("/{cid}/members/{uid}", status_code=204)
def remove_member(cid: str, uid: str, p: Principal = Depends(require_admin_step_up("clients.manage_members")), db: Session = Depends(get_db)) -> None:
    m = db.execute(select(ClientMembership).where(ClientMembership.client_id == cid, ClientMembership.user_id == uid)).scalars().first()
    if m is None:
        raise HTTPException(404, "not found")
    db.delete(m)
    audit.record(db, "client.member_remove", actor=p.label, actor_id=p.user.id, resource_type="client", resource_id=cid, ip=p.ip, meta={"user_id": uid})


@router.get("/mssp/dashboard")
def mssp_dashboard(p: Principal = Depends(require("mssp.view")), db: Session = Depends(get_db)) -> dict[str, Any]:
    """Cross-tenant rollup. Only meaningful (and only permitted) for an all-clients MSSP operator."""
    if not p.user.all_clients:
        raise HTTPException(403, "MSSP dashboard requires access to all clients")
    clients = db.execute(select(Client).where(Client.active.is_(True)).order_by(Client.name)).scalars().all()
    open_statuses = ["new", "acknowledged", "investigating"]
    rows: list[dict[str, Any]] = []
    for c in clients:
        crit = db.execute(select(func.count()).where(Alert.client_id == c.id, Alert.status.in_(open_statuses), Alert.severity == "critical")).scalar_one()
        open_alerts = db.execute(select(func.count()).where(Alert.client_id == c.id, Alert.status.in_(open_statuses))).scalar_one()
        breached = db.execute(select(func.count()).where(Alert.client_id == c.id, Alert.status.in_(open_statuses), Alert.sla_breached.is_(True))).scalar_one()
        open_cases = db.execute(select(func.count()).where(Case.client_id == c.id, Case.status.in_(["open", "in_progress"]))).scalar_one()
        last_alert = db.execute(select(func.max(Alert.time)).where(Alert.client_id == c.id)).scalar_one()
        rows.append({
            "id": c.id, "name": c.name, "code": c.code, "tier": c.tier, "logo_url": c.logo_url, "brand_color": c.brand_color,
            "open_alerts": open_alerts, "critical_alerts": crit, "sla_breached": breached, "open_cases": open_cases, "last_activity": iso(last_alert),
            "health": "critical" if crit > 0 or breached > 0 else "warning" if open_alerts > 0 else "healthy",
        })
    rows.sort(key=lambda r: ({"critical": 0, "warning": 1, "healthy": 2}[r["health"]], -r["open_alerts"]))
    return {
        "total_clients": len(rows), "healthy": sum(1 for r in rows if r["health"] == "healthy"),
        "warning": sum(1 for r in rows if r["health"] == "warning"), "critical": sum(1 for r in rows if r["health"] == "critical"),
        "total_open_alerts": sum(r["open_alerts"] for r in rows), "total_sla_breached": sum(r["sla_breached"] for r in rows),
        "clients": rows,
    }
