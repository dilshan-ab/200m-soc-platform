from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit
from ..config import get_settings
from ..connectors.base import ConnectorError, all_manifests, get_connector_cls
from ..db import get_db
from ..deps import Principal, require, require_admin_step_up
from ..models import ApprovalRequest, Server, Tool, utcnow
from ..security import payload_hash
from ..services import tools_svc
from ..services.polling import POLLABLE, poll_tool
from .common import iso

router = APIRouter(prefix="/api/integrations", tags=["integrations"])
BEARER_DEFAULT = {"wazuh_manager", "thehive", "shuffle", "uptime_kuma", "clickup"}


def tool_out(db: Session, t: Tool) -> dict[str, Any]:
    m = get_connector_cls(t.type).manifest
    st = t.state
    return {
        "id": t.id, "type": t.type, "label": m.label, "name": t.name, "server_id": t.server_id, "status": t.status, "enabled": t.enabled, "poll_interval": t.poll_interval,
        "config": t.config, "secrets_set": sorted((t.secret_refs or {}).keys()), "severity_map": t.severity_map, "field_map": t.field_map, "config_version": t.config_version,
        "last_test": t.last_test, "webhook": {"enabled": m.webhook, "url": f"{get_settings().public_base_url.rstrip('/')}/api/webhooks/{t.id}" if m.webhook else None, "auth_mode": t.webhook_auth_mode, "secret_set": bool(t.webhook_secret_ref)},
        "health": None if st is None else {"last_success_at": iso(st.last_success_at), "last_attempt_at": iso(st.last_attempt_at), "last_error": st.last_error, "error_count": st.error_count,
                                           "items_today": st.items_today, "items_total": st.items_total, "lag_seconds": st.lag_seconds},
        "capabilities": m.capabilities, "setup_hint": m.setup_hint,
    }


def _get_tool(db: Session, tid: str) -> Tool:
    t = db.get(Tool, tid)
    if t is None:
        raise HTTPException(404, "not found")
    return t


@router.get("/catalogue")
def catalogue(p: Principal = Depends(require("integrations.read"))) -> list[dict[str, Any]]:
    return [m.public() for m in all_manifests()]


@router.get("/tools")
def list_tools(p: Principal = Depends(require("integrations.read")), db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    return [tool_out(db, t) for t in db.execute(select(Tool).order_by(Tool.name)).scalars()]


def _health_status(t: Tool, out: dict[str, Any]) -> str:
    if not t.enabled:
        return "paused" if t.status == "paused" else "disabled"
    h = out["health"] or {}
    if (h.get("error_count") or 0) >= 5 or t.status in ("error", "failed"):
        return "down"
    lag, interval = h.get("lag_seconds"), t.poll_interval
    if (h.get("error_count") or 0) >= 1 or (lag is not None and interval and lag > interval * 3):
        return "degraded"
    return "healthy"


@router.get("/health")
def health_dashboard(p: Principal = Depends(require("integrations.read")), db: Session = Depends(get_db)) -> dict[str, Any]:
    """Aggregate health across every linked tool: status breakdown, worst offenders first."""
    rows = []
    for t in db.execute(select(Tool).order_by(Tool.name)).scalars():
        out = tool_out(db, t)
        rows.append({**out, "health_status": _health_status(t, out)})
    order = {"down": 0, "degraded": 1, "disabled": 2, "paused": 3, "healthy": 4}
    rows.sort(key=lambda r: (order.get(r["health_status"], 5), -(r["health"]["error_count"] if r["health"] else 0)))
    counts = {k: sum(1 for r in rows if r["health_status"] == k) for k in order}
    lags = [r["health"]["lag_seconds"] for r in rows if r["health"] and r["health"].get("lag_seconds") is not None]
    errors_today = sum((r["health"]["error_count"] if r["health"] else 0) for r in rows)
    items_today = sum((r["health"]["items_today"] if r["health"] else 0) for r in rows)
    return {
        "total": len(rows), "counts": counts,
        "avg_lag_seconds": round(sum(lags) / len(lags), 1) if lags else None,
        "total_errors": errors_today, "total_items_today": items_today,
        "tools": rows,
    }


@router.get("/tools/{tid}")
def get_tool(tid: str, p: Principal = Depends(require("integrations.read")), db: Session = Depends(get_db)) -> dict[str, Any]:
    return tool_out(db, _get_tool(db, tid))


class ToolIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: str = Field(max_length=40)
    name: str = Field(min_length=2, max_length=120)
    server_id: str | None = None
    values: dict[str, Any] = Field(default_factory=dict)
    poll_interval: int = Field(default=30, ge=5, le=3600)
    webhook_auth_mode: str | None = Field(default=None, pattern="^(hmac|bearer)$")


@router.post("/tools", status_code=201)
def create_tool(body: ToolIn, p: Principal = Depends(require_admin_step_up("integrations.write")), db: Session = Depends(get_db)) -> dict[str, Any]:
    try:
        cls = get_connector_cls(body.type)
    except ConnectorError as e:
        raise HTTPException(400, str(e)) from e
    if db.execute(select(Tool.id).where(Tool.name == body.name)).first():
        raise HTTPException(409, "a tool with that name exists")
    if body.server_id and db.get(Server, body.server_id) is None:
        raise HTTPException(400, "unknown server")
    try:
        cfg, secrets = tools_svc.split_config(cls.manifest, body.values)
    except ValueError as e:
        raise HTTPException(400, str(e)) from e
    t = Tool(type=body.type, name=body.name, server_id=body.server_id, config=cfg, poll_interval=body.poll_interval,
             webhook_auth_mode=body.webhook_auth_mode or ("bearer" if body.type in BEARER_DEFAULT else "hmac"))
    db.add(t)
    db.flush()
    tools_svc.store_secrets(db, t, secrets)
    tools_svc.ensure_state(db, t)
    out = tool_out(db, t)
    if cls.manifest.webhook:
        out["webhook"]["secret"] = tools_svc.new_webhook_secret(db, t)  # shown exactly once
        out["webhook"]["secret_set"] = True
    audit.record(db, "tool.create", actor=p.label, actor_id=p.user.id, resource_type="tool", resource_id=t.id, ip=p.ip, meta={"type": t.type, "name": t.name})
    return out


class ToolConfigIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    values: dict[str, Any]


@router.put("/tools/{tid}/config")
def update_config(tid: str, body: ToolConfigIn, p: Principal = Depends(require_admin_step_up("integrations.write")), db: Session = Depends(get_db)) -> dict[str, Any]:
    t = _get_tool(db, tid)
    cls = get_connector_cls(t.type)
    merged = {**t.config, **{k: v for k, v in body.values.items() if v not in (None, "")}}
    try:
        cfg, secrets = tools_svc.split_config(cls.manifest, {**merged, **{f: "x" for f in cls.manifest.secret_fields if f in (t.secret_refs or {}) and f not in body.values}})
    except ValueError as e:
        raise HTTPException(400, str(e)) from e
    secrets = {k: v for k, v in secrets.items() if k in body.values}  # only replace secrets that were submitted
    t.config = cfg
    tools_svc.store_secrets(db, t, secrets)
    t.config_version += 1
    t.status, t.enabled, t.last_test = "draft", False, {}  # any change requires re-test and re-enable
    audit.record(db, "tool.update", actor=p.label, actor_id=p.user.id, resource_type="tool", resource_id=t.id, ip=p.ip, meta={"fields": sorted(body.values), "secrets_changed": sorted(secrets)})
    return tool_out(db, t)


@router.post("/tools/{tid}/test")
def test_tool(tid: str, p: Principal = Depends(require_admin_step_up("integrations.write")), db: Session = Depends(get_db)) -> dict[str, Any]:
    t = _get_tool(db, tid)
    checks: list[dict[str, Any]] = []
    try:
        c = tools_svc.build_connector(db, t)
        try:
            for r in c.test():
                checks.append({"name": r.name, "ok": r.ok, "detail": r.detail})
        finally:
            c.close()
        manifest_checks = get_connector_cls(t.type).manifest.test_checks
        done = {c_["name"] for c_ in checks}
        for name in manifest_checks:
            if name not in done and name.lower().startswith("test webhook"):
                got = bool((t.last_test or {}).get("webhook_at"))
                checks.append({"name": name, "ok": got, "detail": "" if got else "send a test event to the webhook URL, then re-run"})
    except ConnectorError as e:
        checks.append({"name": "connection", "ok": False, "detail": str(e)[:300]})
    ok = bool(checks) and all(c_["ok"] for c_ in checks)
    t.last_test = {**(t.last_test or {}), "at": utcnow().isoformat(), "ok": ok, "config_version": t.config_version, "checks": checks}
    t.status = "tested" if ok else "draft"
    audit.record(db, "tool.test", actor=p.label, actor_id=p.user.id, resource_type="tool", resource_id=t.id, outcome="success" if ok else "failure", ip=p.ip)
    return {"ok": ok, "checks": checks}


class MappingIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    severity_map: dict[str, str] = Field(default_factory=dict, max_length=64)
    field_map: dict[str, str] = Field(default_factory=dict, max_length=64)
    poll_interval: int | None = Field(default=None, ge=5, le=3600)


@router.put("/tools/{tid}/mapping")
def update_mapping(tid: str, body: MappingIn, p: Principal = Depends(require_admin_step_up("integrations.write")), db: Session = Depends(get_db)) -> dict[str, Any]:
    from ..policy import SEVERITIES

    t = _get_tool(db, tid)
    if any(v not in SEVERITIES for v in body.severity_map.values()):
        raise HTTPException(400, f"severity values must be one of {SEVERITIES}")
    t.severity_map = {str(k).lower(): v for k, v in body.severity_map.items()}
    t.field_map = body.field_map
    t.mapping_version += 1
    if body.poll_interval:
        t.poll_interval = body.poll_interval
    audit.record(db, "tool.mapping", actor=p.label, actor_id=p.user.id, resource_type="tool", resource_id=t.id, ip=p.ip, meta={"version": t.mapping_version})
    return tool_out(db, t)


def apply_enable(db: Session, t: Tool) -> None:
    t.enabled, t.status = True, "enabled"
    tools_svc.ensure_state(db, t)


@router.post("/tools/{tid}/enable")
def enable_tool(tid: str, p: Principal = Depends(require_admin_step_up("integrations.write")), db: Session = Depends(get_db)) -> dict[str, Any]:
    t = _get_tool(db, tid)
    lt = t.last_test or {}
    if not lt.get("ok") or lt.get("config_version") != t.config_version:
        raise HTTPException(409, "run a successful connection test on the current configuration first")
    caps = set(get_connector_cls(t.type).manifest.capabilities)
    if "action" in caps:  # integrations that can change systems need a second admin
        payload = {"tool_id": t.id, "config_version": t.config_version}
        existing = db.execute(select(ApprovalRequest).where(ApprovalRequest.kind == "tool.enable", ApprovalRequest.status == "pending", ApprovalRequest.payload_hash == payload_hash(payload))).scalars().first()
        if existing is None:
            from datetime import timedelta

            existing = ApprovalRequest(kind="tool.enable", payload=payload, payload_hash=payload_hash(payload), requester_id=p.user.id, reason=f"Enable {t.name}", expires_at=utcnow() + timedelta(hours=24))
            db.add(existing)
            db.flush()
        audit.record(db, "tool.enable_requested", actor=p.label, actor_id=p.user.id, resource_type="tool", resource_id=t.id, ip=p.ip)
        return {"pending_approval": True, "request_id": existing.id}
    apply_enable(db, t)
    audit.record(db, "tool.enable", actor=p.label, actor_id=p.user.id, resource_type="tool", resource_id=t.id, ip=p.ip)
    return tool_out(db, t)


@router.post("/tools/{tid}/pause")
def pause_tool(tid: str, p: Principal = Depends(require("integrations.write")), db: Session = Depends(get_db)) -> dict[str, Any]:
    t = _get_tool(db, tid)  # pausing is fail-safe: no step-up needed
    t.enabled, t.status = False, "paused"
    audit.record(db, "tool.pause", actor=p.label, actor_id=p.user.id, resource_type="tool", resource_id=t.id, ip=p.ip)
    return tool_out(db, t)


@router.post("/tools/{tid}/resume")
def resume_tool(tid: str, p: Principal = Depends(require_admin_step_up("integrations.write")), db: Session = Depends(get_db)) -> dict[str, Any]:
    t = _get_tool(db, tid)
    if t.status != "paused":
        raise HTTPException(409, "tool is not paused")
    apply_enable(db, t)
    audit.record(db, "tool.resume", actor=p.label, actor_id=p.user.id, resource_type="tool", resource_id=t.id, ip=p.ip)
    return tool_out(db, t)


@router.post("/tools/{tid}/resync")
def resync(tid: str, p: Principal = Depends(require_admin_step_up("integrations.write")), db: Session = Depends(get_db)) -> dict[str, Any]:
    t = _get_tool(db, tid)
    if not t.enabled:
        raise HTTPException(409, "enable the tool first")
    st = tools_svc.ensure_state(db, t)
    st.checkpoint = {}
    audit.record(db, "tool.resync", actor=p.label, actor_id=p.user.id, resource_type="tool", resource_id=t.id, ip=p.ip)
    if POLLABLE & set(get_connector_cls(t.type).manifest.capabilities):
        return poll_tool(db, t)
    return {"ok": True}


@router.post("/tools/{tid}/rotate-secret")
def rotate_secret(tid: str, p: Principal = Depends(require_admin_step_up("integrations.write")), db: Session = Depends(get_db)) -> dict[str, str]:
    t = _get_tool(db, tid)
    if not get_connector_cls(t.type).manifest.webhook:
        raise HTTPException(400, "tool has no webhook")
    s = tools_svc.new_webhook_secret(db, t)
    audit.record(db, "tool.rotate_secret", actor=p.label, actor_id=p.user.id, resource_type="tool", resource_id=t.id, ip=p.ip)
    return {"secret": s, "note": "shown once; update the sending system now"}


@router.delete("/tools/{tid}")
def disable_tool(tid: str, p: Principal = Depends(require_admin_step_up("integrations.write")), db: Session = Depends(get_db)) -> dict[str, Any]:
    t = _get_tool(db, tid)
    t.enabled, t.status = False, "disabled"  # history is kept
    audit.record(db, "tool.disable", actor=p.label, actor_id=p.user.id, resource_type="tool", resource_id=t.id, ip=p.ip)
    return tool_out(db, t)


@router.delete("/tools/{tid}/purge", status_code=204)
def purge_tool(tid: str, p: Principal = Depends(require_admin_step_up("integrations.write")), db: Session = Depends(get_db)) -> None:
    """Permanently remove a tool: config, secrets and sync state. Past alerts/cases already ingested are kept."""
    t = _get_tool(db, tid)
    name, ttype = t.name, t.type
    tools_svc.purge_secrets(db, t)
    db.delete(t)
    audit.record(db, "tool.purge", actor=p.label, actor_id=p.user.id, resource_type="tool", resource_id=tid, meta={"name": name, "type": ttype}, ip=p.ip)
