from __future__ import annotations

from datetime import timedelta
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import audit
from ..db import get_db
from ..deps import Principal, require, scoped_get
from ..models import UptimeCheck, UptimeMonitor, utcnow
from .common import iso, page_out, paginate

router = APIRouter(prefix="/api/uptime", tags=["uptime"])


def monitor_out(m: UptimeMonitor) -> dict[str, Any]:
    return {
        "id": m.id, "name": m.name, "url": m.url, "method": m.method,
        "interval_seconds": m.interval_seconds, "timeout_seconds": m.timeout_seconds,
        "expected_status": m.expected_status, "headers": m.headers,
        "tags": m.tags, "notify_channels": m.notify_channels,
        "enabled": m.enabled, "status": m.status,
        "last_checked_at": iso(m.last_checked_at), "last_status_change": iso(m.last_status_change),
        "consecutive_failures": m.consecutive_failures, "fail_threshold": m.fail_threshold,
        "client_id": m.client_id, "created_by": m.created_by,
        "created_at": iso(m.created_at), "updated_at": iso(m.updated_at),
    }


def check_out(c: UptimeCheck) -> dict[str, Any]:
    return {
        "id": c.id, "monitor_id": c.monitor_id, "status": c.status,
        "status_code": c.status_code, "response_time_ms": c.response_time_ms,
        "error": c.error, "checked_at": iso(c.checked_at),
    }


@router.get("/summary")
def summary(p: Principal = Depends(require("uptime.read")), db: Session = Depends(get_db)) -> dict[str, Any]:
    base = select(UptimeMonitor).where(p.scope(UptimeMonitor.client_id))
    total = db.execute(select(func.count()).select_from(base.subquery())).scalar_one()
    up = db.execute(select(func.count()).select_from(base.where(UptimeMonitor.status == "up").subquery())).scalar_one()
    down = db.execute(select(func.count()).select_from(base.where(UptimeMonitor.status == "down").subquery())).scalar_one()
    degraded = db.execute(select(func.count()).select_from(base.where(UptimeMonitor.status == "degraded").subquery())).scalar_one()
    since = utcnow() - timedelta(hours=1)
    avg_rt = db.execute(
        select(func.avg(UptimeCheck.response_time_ms)).where(
            UptimeCheck.checked_at >= since,
            UptimeCheck.response_time_ms.isnot(None),
            UptimeCheck.monitor_id.in_(select(UptimeMonitor.id).where(p.scope(UptimeMonitor.client_id))),
        )
    ).scalar_one()
    return {"total": total, "up": up, "down": down, "degraded": degraded, "unknown": total - up - down - degraded, "avg_response_time_ms": round(avg_rt) if avg_rt else None}


@router.get("/monitors")
def list_monitors(
    p: Principal = Depends(require("uptime.read")), db: Session = Depends(get_db),
    status: str | None = None, tag: str | None = None, client_id: str | None = None,
    q: str | None = Query(default=None, max_length=200), page: int = 1, limit: int = 50,
) -> dict[str, Any]:
    qy = select(UptimeMonitor).where(p.scope(UptimeMonitor.client_id))
    if status:
        qy = qy.where(UptimeMonitor.status == status)
    if tag:
        qy = qy.where(UptimeMonitor.tags.contains([tag]))
    if client_id:
        qy = qy.where(UptimeMonitor.client_id == client_id)
    if q:
        qy = qy.where(UptimeMonitor.name.icontains(q, autoescape=True) | UptimeMonitor.url.icontains(q, autoescape=True))
    rows, total = paginate(db, qy.order_by(UptimeMonitor.name, UptimeMonitor.id), page, limit)
    return page_out([monitor_out(m) for m in rows], total, page, limit)


class MonitorIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=200)
    url: str = Field(min_length=8, max_length=2000)
    method: Literal["HEAD", "GET"] = "HEAD"
    timeout_seconds: int = Field(default=10, ge=1, le=30)
    expected_status: int = Field(default=200, ge=100, le=599)
    headers: dict[str, str] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list, max_length=20)
    notify_channels: list[str] = Field(default_factory=list, max_length=10)
    enabled: bool = True
    fail_threshold: int = Field(default=2, ge=1, le=10)
    client_id: str | None = None


@router.post("/monitors", status_code=201)
def create_monitor(body: MonitorIn, p: Principal = Depends(require("uptime.write")), db: Session = Depends(get_db)) -> dict[str, Any]:
    if p.client_ids is not None and not p.can_see_client(body.client_id):
        raise HTTPException(403, "client not permitted")
    m = UptimeMonitor(
        name=body.name, url=body.url, method=body.method, timeout_seconds=body.timeout_seconds,
        expected_status=body.expected_status, headers=body.headers, tags=body.tags,
        notify_channels=body.notify_channels, enabled=body.enabled, fail_threshold=body.fail_threshold,
        client_id=body.client_id, created_by=p.label,
    )
    db.add(m)
    db.flush()
    audit.record(db, "uptime.create", actor=p.label, actor_id=p.user.id, resource_type="uptime_monitor", resource_id=m.id, client_id=m.client_id, ip=p.ip)
    return monitor_out(m)


@router.get("/monitors/{mid}")
def get_monitor(mid: str, p: Principal = Depends(require("uptime.read")), db: Session = Depends(get_db)) -> dict[str, Any]:
    m = scoped_get(db, UptimeMonitor, mid, p)
    d = monitor_out(m)
    since = utcnow() - timedelta(hours=24)
    checks = db.execute(
        select(UptimeCheck).where(UptimeCheck.monitor_id == m.id, UptimeCheck.checked_at >= since).order_by(UptimeCheck.checked_at.desc())
    ).scalars().all()
    d["checks"] = [check_out(c) for c in checks]
    return d


class MonitorPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str | None = Field(default=None, min_length=1, max_length=200)
    url: str | None = Field(default=None, min_length=8, max_length=2000)
    method: Literal["HEAD", "GET"] | None = None
    timeout_seconds: int | None = Field(default=None, ge=1, le=30)
    expected_status: int | None = Field(default=None, ge=100, le=599)
    headers: dict[str, str] | None = None
    tags: list[str] | None = Field(default=None, max_length=20)
    notify_channels: list[str] | None = Field(default=None, max_length=10)
    enabled: bool | None = None
    fail_threshold: int | None = Field(default=None, ge=1, le=10)


@router.patch("/monitors/{mid}")
def update_monitor(mid: str, body: MonitorPatch, p: Principal = Depends(require("uptime.write")), db: Session = Depends(get_db)) -> dict[str, Any]:
    m = scoped_get(db, UptimeMonitor, mid, p)
    for k, v in body.model_dump(exclude_unset=True).items():
        setattr(m, k, v)
    m.updated_at = utcnow()
    audit.record(db, "uptime.update", actor=p.label, actor_id=p.user.id, resource_type="uptime_monitor", resource_id=m.id, client_id=m.client_id, ip=p.ip)
    return monitor_out(m)


@router.delete("/monitors/{mid}", status_code=204)
def delete_monitor(mid: str, p: Principal = Depends(require("uptime.write")), db: Session = Depends(get_db)) -> None:
    m = scoped_get(db, UptimeMonitor, mid, p)
    audit.record(db, "uptime.delete", actor=p.label, actor_id=p.user.id, resource_type="uptime_monitor", resource_id=m.id, client_id=m.client_id, ip=p.ip)
    db.delete(m)


@router.get("/monitors/{mid}/checks")
def list_checks(mid: str, p: Principal = Depends(require("uptime.read")), db: Session = Depends(get_db), page: int = 1, limit: int = 50) -> dict[str, Any]:
    m = scoped_get(db, UptimeMonitor, mid, p)
    qy = select(UptimeCheck).where(UptimeCheck.monitor_id == m.id).order_by(UptimeCheck.checked_at.desc())
    rows, total = paginate(db, qy, page, limit)
    return page_out([check_out(c) for c in rows], total, page, limit)
