from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit
from ..db import get_db
from ..deps import Principal, require, scoped_get
from ..models import ShiftHandoff, User, utcnow
from .common import iso, user_label

router = APIRouter(prefix="/api/handoffs", tags=["handoffs"])


def _out(db: Session, h: ShiftHandoff) -> dict[str, Any]:
    return {
        "id": h.id, "shift_name": h.shift_name, "status": h.status, "summary": h.summary, "open_items": h.open_items, "watch_items": h.watch_items,
        "handoff_notes": h.handoff_notes, "case_ids": h.case_ids, "alert_ids": h.alert_ids,
        "from_analyst": user_label(db, h.from_analyst_id), "to_analyst": user_label(db, h.to_analyst_id),
        "submitted_at": iso(h.submitted_at), "acknowledged_at": iso(h.acknowledged_at), "acknowledged_by": user_label(db, h.acknowledged_by),
        "client_id": h.client_id, "created_by": user_label(db, h.created_by), "created_at": iso(h.created_at), "updated_at": iso(h.updated_at),
    }


@router.get("")
def list_handoffs(p: Principal = Depends(require("handoff.read")), db: Session = Depends(get_db), status: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
    qy = select(ShiftHandoff).where(p.scope(ShiftHandoff.client_id) | ShiftHandoff.client_id.is_(None)).order_by(ShiftHandoff.created_at.desc())
    if status:
        qy = qy.where(ShiftHandoff.status == status)
    return [_out(db, h) for h in db.execute(qy.limit(min(limit, 200))).scalars()]


@router.get("/pending")
def pending_for_me(p: Principal = Depends(require("handoff.read")), db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    """Handoffs submitted (not yet acknowledged) that are either addressed to me or unassigned."""
    qy = select(ShiftHandoff).where(
        p.scope(ShiftHandoff.client_id) | ShiftHandoff.client_id.is_(None),
        ShiftHandoff.status == "submitted",
        (ShiftHandoff.to_analyst_id == p.user.id) | (ShiftHandoff.to_analyst_id.is_(None)),
    ).order_by(ShiftHandoff.submitted_at.desc())
    return [_out(db, h) for h in db.execute(qy).scalars()]


class HandoffIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    shift_name: str = Field(default="", max_length=80)
    summary: str = Field(default="", max_length=8000)
    open_items: list[dict[str, Any]] = Field(default_factory=list, max_length=100)
    watch_items: list[dict[str, Any]] = Field(default_factory=list, max_length=100)
    handoff_notes: str = Field(default="", max_length=8000)
    case_ids: list[str] = Field(default_factory=list, max_length=50)
    alert_ids: list[str] = Field(default_factory=list, max_length=50)
    to_analyst_id: str | None = None
    client_id: str | None = None


@router.post("", status_code=201)
def create_handoff(body: HandoffIn, p: Principal = Depends(require("handoff.write")), db: Session = Depends(get_db)) -> dict[str, Any]:
    if body.client_id and not p.can_see_client(body.client_id):
        raise HTTPException(404, "not found")
    if body.to_analyst_id and db.get(User, body.to_analyst_id) is None:
        raise HTTPException(400, "unknown analyst")
    h = ShiftHandoff(**body.model_dump(), from_analyst_id=p.user.id, created_by=p.user.id)
    db.add(h)
    db.flush()
    audit.record(db, "handoff.create", actor=p.label, actor_id=p.user.id, resource_type="shift_handoff", resource_id=h.id, client_id=h.client_id, ip=p.ip)
    return _out(db, h)


@router.get("/{hid}")
def get_handoff(hid: str, p: Principal = Depends(require("handoff.read")), db: Session = Depends(get_db)) -> dict[str, Any]:
    return _out(db, scoped_get(db, ShiftHandoff, hid, p))


class HandoffPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    shift_name: str | None = Field(default=None, max_length=80)
    summary: str | None = Field(default=None, max_length=8000)
    open_items: list[dict[str, Any]] | None = Field(default=None, max_length=100)
    watch_items: list[dict[str, Any]] | None = Field(default=None, max_length=100)
    handoff_notes: str | None = Field(default=None, max_length=8000)
    to_analyst_id: str | None = None


@router.patch("/{hid}")
def patch_handoff(hid: str, body: HandoffPatch, p: Principal = Depends(require("handoff.write")), db: Session = Depends(get_db)) -> dict[str, Any]:
    h = scoped_get(db, ShiftHandoff, hid, p)
    if h.status != "draft":
        raise HTTPException(409, "only a draft handoff can be edited")
    for k, v in body.model_dump(exclude_unset=True).items():
        setattr(h, k, v)
    audit.record(db, "handoff.update", actor=p.label, actor_id=p.user.id, resource_type="shift_handoff", resource_id=h.id, ip=p.ip)
    return _out(db, h)


@router.post("/{hid}/submit")
def submit_handoff(hid: str, p: Principal = Depends(require("handoff.write")), db: Session = Depends(get_db)) -> dict[str, Any]:
    h = scoped_get(db, ShiftHandoff, hid, p)
    if h.status != "draft":
        raise HTTPException(409, "already submitted")
    h.status, h.submitted_at = "submitted", utcnow()
    audit.record(db, "handoff.submit", actor=p.label, actor_id=p.user.id, resource_type="shift_handoff", resource_id=h.id, ip=p.ip)
    return _out(db, h)


@router.post("/{hid}/acknowledge")
def acknowledge_handoff(hid: str, p: Principal = Depends(require("handoff.write")), db: Session = Depends(get_db)) -> dict[str, Any]:
    h = scoped_get(db, ShiftHandoff, hid, p)
    if h.status != "submitted":
        raise HTTPException(409, "handoff is not awaiting acknowledgement")
    h.status, h.acknowledged_at, h.acknowledged_by = "acknowledged", utcnow(), p.user.id
    audit.record(db, "handoff.acknowledge", actor=p.label, actor_id=p.user.id, resource_type="shift_handoff", resource_id=h.id, ip=p.ip)
    return _out(db, h)
