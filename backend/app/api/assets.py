from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from .. import audit
from ..db import get_db
from ..deps import Principal, require, require_admin_step_up, scoped_get
from ..models import Alert, Asset, Case, Client, Finding, Server, Tool
from .common import iso, page_out, paginate

router = APIRouter(prefix="/api", tags=["assets"])

CONTROLS = ["wazuh_agent", "uptime_kuma", "prometheus_exporter", "velociraptor_client", "bareos_job", "opsi_client", "suricata", "zeek", "fail2ban", "osquery"]


def asset_out(a: Asset, detail: bool = False) -> dict[str, Any]:
    d: dict[str, Any] = {"id": a.id, "name": a.name, "hostname": a.hostname, "ips": a.ips, "os": a.os, "kind": a.kind, "agent_status": a.agent_status, "last_seen": iso(a.last_seen),
         "client_id": a.client_id, "server_id": a.server_id, "department": a.department, "criticality": a.criticality, "sca_score": a.sca_score, "patch_status": a.patch_status, "owner": a.owner}
    if detail:
        d.update({"software": a.software, "ports": a.ports, "last_backup_at": iso(a.last_backup_at)})
    return d


@router.get("/assets")
def list_assets(p: Principal = Depends(require("assets.read")), db: Session = Depends(get_db), kind: str | None = None, client_id: str | None = None, department: str | None = None,
                agent_status: str | None = None, q: str | None = Query(default=None, max_length=200), page: int = 1, limit: int = 50) -> dict[str, Any]:
    qy = select(Asset).where(p.scope(Asset.client_id), Asset.decommissioned.is_(False))
    for col, v in ((Asset.kind, kind), (Asset.client_id, client_id), (Asset.department, department), (Asset.agent_status, agent_status)):
        if v:
            qy = qy.where(col == v)
    if q:
        qy = qy.where(Asset.name.contains(q, autoescape=True) | Asset.hostname.contains(q, autoescape=True))
    rows, total = paginate(db, qy.order_by(Asset.name), page, limit)
    return page_out([asset_out(a) for a in rows], total, page, limit)


@router.get("/assets/{aid}")
def get_asset(aid: str, p: Principal = Depends(require("assets.read")), db: Session = Depends(get_db)) -> dict[str, Any]:
    a = scoped_get(db, Asset, aid, p)
    d = asset_out(a, True)
    d["open_alerts"] = db.execute(select(func.count()).where(Alert.asset_id == a.id, Alert.status.in_(["new", "acknowledged", "investigating"]))).scalar_one()
    d["open_vulns"] = db.execute(select(func.count()).where(Finding.asset_id == a.id, Finding.status == "open")).scalar_one()
    return d


class AssetPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    department: str | None = Field(default=None, max_length=120)
    owner: str | None = Field(default=None, max_length=120)
    criticality: Literal["low", "medium", "high", "critical"] | None = None
    expected_criticality: Literal["low", "medium", "high", "critical"] | None = None
    client_id: str | None = None
    decommissioned: bool | None = None


@router.patch("/assets/{aid}")
def patch_asset(aid: str, body: AssetPatch, p: Principal = Depends(require("assets.write")), db: Session = Depends(get_db)) -> dict[str, Any]:
    a = scoped_get(db, Asset, aid, p)
    data = body.model_dump(exclude_unset=True, exclude={"expected_criticality"})
    if "client_id" in data and data["client_id"] and not p.can_see_client(data["client_id"]):
        raise HTTPException(403, "client not permitted")
    if body.expected_criticality is not None:
        if data.get("criticality") is None:
            raise HTTPException(400, "criticality is required with expected_criticality")
        result = db.execute(update(Asset).where(Asset.id == a.id, Asset.criticality == body.expected_criticality).values(**data).execution_options(synchronize_session=False))
        if result.rowcount != 1:
            raise HTTPException(409, "Asset criticality changed since your update. Reload before changing it again.")
        db.refresh(a)
    else:
        for k, v in data.items():
            setattr(a, k, v)
    audit.record(db, "asset.update", actor=p.label, actor_id=p.user.id, resource_type="asset", resource_id=a.id, client_id=a.client_id, ip=p.ip, meta=data)
    return asset_out(a, True)


# ----------------------------------------------------------------- servers
def coverage(s: Server) -> dict[str, Any]:
    expected = s.expected_controls or CONTROLS
    have = {k for k, v in (s.coverage or {}).items() if v}
    missing = [c for c in expected if c not in have]
    return {"score": round(100 * (len(expected) - len(missing)) / len(expected)) if expected else 100, "missing": missing, "expected": expected}


def server_out(db: Session, s: Server, detail: bool = False) -> dict[str, Any]:
    d: dict[str, Any] = {"id": s.id, "name": s.name, "host": s.host, "role": s.role, "environment": s.environment, "criticality": s.criticality, "os": s.os, "status": s.status,
         "client_id": s.client_id, "owner": s.owner, "coverage": coverage(s), "status_changed_at": iso(s.status_changed_at)}
    if detail:
        d["open_alerts"] = db.execute(select(func.count()).where(Alert.host.in_([s.host, s.name]), Alert.status.in_(["new", "acknowledged", "investigating"]))).scalar_one()
        d["tools"] = [{"id": t.id, "name": t.name, "type": t.type, "status": t.status} for t in db.execute(select(Tool).where(Tool.server_id == s.id)).scalars()]
        d["agents"] = db.execute(select(func.count()).where(Asset.server_id == s.id)).scalar_one()
    return d


@router.get("/servers")
def list_servers(p: Principal = Depends(require("servers.read")), db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    q = select(Server).where(p.scope(Server.client_id)).order_by(Server.name)
    return [server_out(db, s) for s in db.execute(q).scalars()]


@router.get("/servers/{sid}")
def get_server(sid: str, p: Principal = Depends(require("servers.read")), db: Session = Depends(get_db)) -> dict[str, Any]:
    return server_out(db, scoped_get(db, Server, sid, p), True)


class ServerIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=120)
    host: str = Field(min_length=1, max_length=255, pattern=r"^[A-Za-z0-9_.\-:]+$")
    role: Literal["soc_core", "monitored", "workstation_group", "proxy", "dns"] = "monitored"
    environment: Literal["production", "staging", "development"] = "production"
    owner: str = Field(default="", max_length=120)
    criticality: Literal["low", "medium", "high", "critical"] = "medium"
    os: str = Field(default="", max_length=80)
    client_id: str | None = None
    expected_controls: list[str] = Field(default_factory=list, max_length=20)


@router.post("/servers", status_code=201)
def create_server(body: ServerIn, p: Principal = Depends(require_admin_step_up("servers.write")), db: Session = Depends(get_db)) -> dict[str, Any]:
    if db.execute(select(Server.id).where(Server.name == body.name)).first():
        raise HTTPException(409, "a server with that name exists")
    bad = [c for c in body.expected_controls if c not in CONTROLS]
    if bad:
        raise HTTPException(400, f"unknown controls: {', '.join(bad)}")
    s = Server(**body.model_dump())
    db.add(s)
    db.flush()
    audit.record(db, "server.create", actor=p.label, actor_id=p.user.id, resource_type="server", resource_id=s.id, client_id=s.client_id, ip=p.ip, meta={"name": s.name})
    return server_out(db, s, True)


class ServerPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    owner: str | None = Field(default=None, max_length=120)
    criticality: Literal["low", "medium", "high", "critical"] | None = None
    environment: Literal["production", "staging", "development"] | None = None
    expected_controls: list[str] | None = None
    coverage: dict[str, bool] | None = None


@router.patch("/servers/{sid}")
def patch_server(sid: str, body: ServerPatch, p: Principal = Depends(require_admin_step_up("servers.write")), db: Session = Depends(get_db)) -> dict[str, Any]:
    s = scoped_get(db, Server, sid, p)
    data = body.model_dump(exclude_unset=True)
    if "coverage" in data and data["coverage"]:
        data["coverage"] = {k: v for k, v in data["coverage"].items() if k in CONTROLS}
    for k, v in data.items():
        setattr(s, k, v)
    audit.record(db, "server.update", actor=p.label, actor_id=p.user.id, resource_type="server", resource_id=s.id, client_id=s.client_id, ip=p.ip, meta={k: v for k, v in data.items() if k != "coverage"})
    return server_out(db, s, True)


# ----------------------------------------------------------------- clients
class ClientIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=120)
    code: str = Field(min_length=1, max_length=32, pattern=r"^[A-Za-z0-9_\-]+$")
    kind: Literal["client", "business_unit"] = "client"
    owner: str = Field(default="", max_length=120)
    report_recipients: list[str] = Field(default_factory=list, max_length=20)


@router.get("/clients")
def list_clients(p: Principal = Depends(require("alerts.read")), db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    q = select(Client).where(Client.active.is_(True)).order_by(Client.name)
    if p.client_ids is not None:
        q = q.where(Client.id.in_(p.client_ids))
    return [{"id": c.id, "name": c.name, "code": c.code, "kind": c.kind, "owner": c.owner} for c in db.execute(q).scalars()]


@router.post("/clients", status_code=201)
def create_client(body: ClientIn, p: Principal = Depends(require_admin_step_up("admin.users")), db: Session = Depends(get_db)) -> dict[str, Any]:
    if db.execute(select(Client.id).where((Client.name == body.name) | (Client.code == body.code))).first():
        raise HTTPException(409, "client name or code exists")
    c = Client(**body.model_dump())
    db.add(c)
    db.flush()
    audit.record(db, "client.create", actor=p.label, actor_id=p.user.id, resource_type="client", resource_id=c.id, ip=p.ip)
    return {"id": c.id, "name": c.name, "code": c.code}


@router.get("/clients/{cid}/summary")
def client_summary(cid: str, p: Principal = Depends(require("alerts.read")), db: Session = Depends(get_db)) -> dict[str, Any]:
    if not p.can_see_client(cid) or db.get(Client, cid) is None:
        raise HTTPException(404, "not found")
    return {
        "alerts_open": db.execute(select(func.count()).where(Alert.client_id == cid, Alert.status.in_(["new", "acknowledged", "investigating"]))).scalar_one(),
        "cases_open": db.execute(select(func.count()).where(Case.client_id == cid, Case.status.in_(["open", "in_progress"]))).scalar_one(),
        "assets": db.execute(select(func.count()).where(Asset.client_id == cid)).scalar_one(),
        "vulns_open": db.execute(select(func.count()).where(Finding.client_id == cid, Finding.status == "open")).scalar_one(),
    }
