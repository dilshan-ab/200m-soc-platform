from __future__ import annotations

import asyncio
import json
import re
from datetime import timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import PlainTextResponse, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from .. import audit
from ..config import get_settings
from ..connectors.base import get_connector_cls
from ..db import get_db, session_scope
from ..deps import Principal, get_principal, require
from ..models import Alert, AuditEvent, BootstrapState, Client, Outbox, Server, Tool, User, utcnow
from ..ratelimit import limiter
from ..security import constant_eq, hash_password, new_token, new_totp_secret, password_policy_ok
from ..seed import seed_defaults
from ..services import events
from ..services.metrics import soc_metrics
from ..services.settings_svc import get_setting, set_setting
from .alerts import alert_out
from .common import iso

router = APIRouter(prefix="/api", tags=["platform"])


@router.get("/dashboard")
def dashboard(p: Principal = Depends(require("alerts.read")), db: Session = Depends(get_db), days: int = 7, client_id: str | None = None) -> dict[str, Any]:
    if client_id and not p.can_see_client(client_id):
        raise HTTPException(404, "not found")
    days = max(1, min(days, 90))
    now = utcnow()
    cutoff = now - timedelta(days=days)
    m = soc_metrics(db, p, cutoff, client_id)
    scope = [p.scope(Alert.client_id)]
    if client_id:
        scope.append(Alert.client_id == client_id)
    top = db.execute(select(Alert).where(*scope, Alert.status.in_(["new", "acknowledged", "investigating"]), Alert.severity.in_(["critical", "high"])).order_by(Alert.time.desc(), Alert.id).limit(10)).scalars()
    categories = db.execute(select(Alert.category, func.count()).where(*scope, Alert.time >= cutoff).group_by(Alert.category).order_by(func.count().desc(), Alert.category)).all()
    srv = []
    if p.can("servers.read"):
        srv = [{"id": s.id, "name": s.name, "status": s.status, "criticality": s.criticality} for s in db.execute(select(Server).where(p.scope(Server.client_id)).order_by(Server.name)).scalars()]
    sources = []
    if p.can("integrations.read"):
        for t in db.execute(select(Tool).where(Tool.enabled.is_(True))).scalars():
            sources.append({"id": t.id, "name": t.name, "type": t.type, "last_success_at": iso(t.state.last_success_at) if t.state else None, "error_count": t.state.error_count if t.state else 0, "lag_seconds": t.state.lag_seconds if t.state else 0})
    hourly = days == 1
    interval = timedelta(hours=1) if hourly else timedelta(days=1)
    end = now.replace(minute=0, second=0, microsecond=0) if hourly else now.replace(hour=0, minute=0, second=0, microsecond=0)
    series = []
    for offset in range((25 if hourly else days + 1) - 1, -1, -1):
        start = end - offset * interval
        bucket = select(Alert.severity, func.count()).where(*scope, Alert.time >= max(start, cutoff), Alert.time < start + interval).group_by(Alert.severity)
        by_sev = dict(db.execute(bucket).all())
        series.append({"day": start.strftime("%H:%M") if hourly else start.date().isoformat(), "alerts": sum(by_sev.values()), "critical": by_sev.get("critical", 0), "high": by_sev.get("high", 0)})
    return {
        "metrics": m, "top_alerts": [alert_out(a) for a in top], "servers": srv, "sources": sources,
        "series": series, "categories": [{"name": name, "count": count} for name, count in categories],
    }


# ------------------------------------------------------------------- dashboard quick links
# Shared, team-wide shortcuts to external dashboards (Wazuh, Grafana, Uptime Kuma, TheHive, ...).
# These are plain outbound links opened by the viewer's own browser — nothing is fetched server-side.
class DashboardLinkIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=60)
    url: str = Field(min_length=4, max_length=500)


def _validate_link_url(url: str) -> str:
    url = url.strip()
    if not re.match(r"^https?://[^\s]+$", url, re.IGNORECASE):
        raise HTTPException(400, "URL must start with http:// or https://")
    return url


@router.get("/dashboard-links")
def list_dashboard_links(p: Principal = Depends(require("alerts.read")), db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    return get_setting(db, "dashboard_links", [])


@router.post("/dashboard-links", status_code=201)
def add_dashboard_link(body: DashboardLinkIn, p: Principal = Depends(require("admin.settings")), db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    link = {"id": new_token(8), "name": body.name.strip(), "url": _validate_link_url(body.url)}
    links = [*get_setting(db, "dashboard_links", []), link]
    set_setting(db, "dashboard_links", links)
    audit.record(db, "dashboard_link.add", actor=p.label, actor_id=p.user.id, ip=p.ip, meta={"name": link["name"]})
    return links


@router.delete("/dashboard-links/{lid}")
def remove_dashboard_link(lid: str, p: Principal = Depends(require("admin.settings")), db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    links = [link for link in get_setting(db, "dashboard_links", []) if link["id"] != lid]
    set_setting(db, "dashboard_links", links)
    audit.record(db, "dashboard_link.remove", actor=p.label, actor_id=p.user.id, ip=p.ip, meta={"id": lid})
    return links


@router.get("/stream")
async def stream(request: Request) -> StreamingResponse:
    def auth() -> tuple[frozenset[str] | None, bool]:
        with session_scope() as db:
            p = get_principal(request, db)
            if not p.can("alerts.read"):
                raise HTTPException(403, "forbidden")
            return p.client_ids, True

    try:
        client_ids, _ = await asyncio.to_thread(auth)
    except HTTPException:
        raise

    def allow(ev: dict[str, Any]) -> bool:
        return client_ids is None or (ev.get("client_id") in client_ids)

    q = events.hub.subscribe(allow, loop=asyncio.get_running_loop())

    async def gen():  # noqa: ANN202
        try:
            yield "retry: 5000\n\n"
            for _ in range(60 * 60 * 8 // 15):  # bounded to the absolute session lifetime
                if await request.is_disconnected():
                    break
                try:
                    ev = await asyncio.wait_for(q.get(), 15)
                    yield f"data: {json.dumps(ev)}\n\n"
                except TimeoutError:
                    yield ": keepalive\n\n"
        finally:
            events.hub.unsubscribe(q)

    return StreamingResponse(gen(), media_type="text/event-stream", headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})


@router.get("/admin/health")
def health(p: Principal = Depends(require("admin.settings")), db: Session = Depends(get_db)) -> dict[str, Any]:
    out: dict[str, Any] = {"api": "ok"}
    try:
        db.execute(text("SELECT 1"))
        out["database"] = "ok"
    except Exception:  # noqa: BLE001
        out["database"] = "down"
    r = events.get_redis()
    if r is not None:
        try:
            r.ping()
            out["redis"] = "ok"
        except Exception:  # noqa: BLE001
            out["redis"] = "down"
    else:
        out["redis"] = "not configured"
    pending = db.execute(select(func.count()).where(Outbox.status == "pending")).scalar_one()
    dead = db.execute(select(func.count()).where(Outbox.status == "dead")).scalar_one()
    oldest = db.execute(select(func.min(Outbox.run_after)).where(Outbox.status == "pending")).scalar_one()
    out["outbox"] = {"pending": pending, "dead": dead, "oldest_pending_seconds": int((utcnow() - oldest).total_seconds()) if oldest else 0}
    out["workers"] = "enabled" if get_settings().workers_enabled else "disabled"
    tools = db.execute(select(Tool).where(Tool.enabled.is_(True))).scalars().all()
    out["integrations"] = {"enabled": len(tools), "failing": sum(1 for t in tools if t.state and t.state.error_count > 0)}
    out["auth_mode"] = get_settings().auth_mode
    out["environment"] = get_settings().environment
    return out


@router.get("/metrics", response_class=PlainTextResponse, include_in_schema=False)
def prometheus(request: Request, db: Session = Depends(get_db)) -> PlainTextResponse:
    tok = get_settings().metrics_token
    auth = request.headers.get("authorization", "")
    if not tok or not auth.lower().startswith("bearer ") or not constant_eq(auth[7:].strip(), tok):
        raise HTTPException(404, "not found")
    lines = ["# TYPE soc_alerts_open gauge"]
    for sev, n in db.execute(select(Alert.severity, func.count()).where(Alert.status.in_(["new", "acknowledged", "investigating"])).group_by(Alert.severity)):
        lines.append(f'soc_alerts_open{{severity="{sev}"}} {n}')
    lines.append("# TYPE soc_outbox_pending gauge")
    lines.append(f"soc_outbox_pending {db.execute(select(func.count()).where(Outbox.status == 'pending')).scalar_one()}")
    lines.append(f"soc_outbox_dead {db.execute(select(func.count()).where(Outbox.status == 'dead')).scalar_one()}")
    lines.append(f"soc_servers_down {db.execute(select(func.count()).where(Server.status == 'down')).scalar_one()}")
    lines.append(f"soc_audit_events_total {db.execute(select(func.count()).select_from(AuditEvent)).scalar_one()}")
    lines.append(f"soc_tools_failing {sum(1 for t in db.execute(select(Tool).where(Tool.enabled.is_(True))).scalars() if t.state and t.state.error_count > 0)}")
    return PlainTextResponse("\n".join(lines) + "\n")


# ------------------------------------------------------------------ first-run setup
def _state(db: Session) -> BootstrapState:
    st = db.get(BootstrapState, 1)
    if st is None:
        st = BootstrapState(id=1)
        db.add(st)
        db.flush()
    return st


@router.get("/setup/status")
def setup_status(db: Session = Depends(get_db)) -> dict[str, Any]:
    st = _state(db)
    if st.completed:
        return {"completed": True}
    has_admin = db.execute(select(func.count()).select_from(User).where(User.role.in_(["admin", "superadmin"]))).scalar_one() > 0
    has = lambda t: db.execute(select(func.count()).select_from(Tool).where(Tool.type == t)).scalar_one() > 0  # noqa: E731
    return {"completed": False, "steps": {"admin": has_admin, "servers": db.execute(select(func.count()).select_from(Server)).scalar_one() >= 2, "wazuh": has("wazuh_indexer") or has("wazuh_manager"), "thehive": has("thehive")}, "auth_mode": get_settings().auth_mode}


class SetupIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    token: str = Field(max_length=200)
    email: str = Field(max_length=255, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    name: str = Field(default="Administrator", max_length=160)
    password: str | None = Field(default=None, max_length=256)


@router.post("/setup/admin", status_code=201)
def setup_admin(body: SetupIn, request: Request, db: Session = Depends(get_db)) -> dict[str, Any]:
    s = get_settings()
    ip = request.client.host if request.client else ""
    if not limiter.allow(f"setup:{ip}", 5):
        raise HTTPException(429, "too many attempts")
    st = _state(db)
    if st.completed or not s.bootstrap_token or not constant_eq(body.token, s.bootstrap_token):
        raise HTTPException(404, "not found")  # uniform: do not reveal state
    if db.execute(select(func.count()).select_from(User).where(User.role.in_(["admin", "superadmin"]))).scalar_one() > 0:
        raise HTTPException(409, "an administrator already exists")
    email = body.email.strip().lower()
    out: dict[str, Any] = {"email": email}
    if s.auth_mode == "dev":
        if not body.password or not password_policy_ok(body.password):
            raise HTTPException(400, "password must be 12+ chars with upper, lower and a digit")
        sec = new_totp_secret()
        u = User(subject=f"dev:{email}", email=email, name=body.name, role="admin", all_clients=True, password_hash=hash_password(body.password), totp_secret=sec)
        out["totp_secret"] = sec
    else:
        u = User(subject=f"pending:{email}", email=email, name=body.name, role="admin", all_clients=True)
    db.add(u)
    db.flush()
    seed_defaults(db)
    st.steps = {"admin": True}
    audit.record(db, "setup.admin_created", actor=email, actor_id=u.id, ip=ip)
    return out


@router.post("/setup/complete")
def setup_complete(p: Principal = Depends(require("admin.settings")), db: Session = Depends(get_db)) -> dict[str, bool]:
    st = _state(db)
    st.completed, st.completed_at = True, utcnow()
    audit.record(db, "setup.completed", actor=p.label, actor_id=p.user.id, ip=p.ip)
    return {"completed": True}


@router.get("/search")
def global_search(q: str, p: Principal = Depends(require("alerts.read")), db: Session = Depends(get_db)) -> dict[str, Any]:
    from ..models import Asset, Case

    q = q.strip()[:100]
    if len(q) < 2:
        return {"alerts": [], "cases": [], "assets": []}
    a = db.execute(select(Alert).where(p.scope(Alert.client_id), Alert.title.contains(q, autoescape=True) | Alert.host.contains(q, autoescape=True) | Alert.src_ip.contains(q, autoescape=True)).order_by(Alert.time.desc()).limit(8)).scalars()
    c = db.execute(select(Case).where(p.scope(Case.client_id), Case.title.contains(q, autoescape=True)).limit(8)).scalars()
    s = db.execute(select(Asset).where(p.scope(Asset.client_id), Asset.name.contains(q, autoescape=True)).limit(8)).scalars()
    return {"alerts": [{"id": x.id, "title": x.title, "severity": x.severity} for x in a], "cases": [{"id": x.id, "number": x.number, "title": x.title} for x in c], "assets": [{"id": x.id, "name": x.name} for x in s]}


_ = (Client, get_connector_cls)
