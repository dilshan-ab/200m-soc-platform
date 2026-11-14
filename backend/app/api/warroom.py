from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit
from ..db import get_db
from ..deps import Principal, require, scoped_get
from ..models import Case, Incident, WarRoom, WarRoomMessage, utcnow
from ..services import events
from .common import iso

router = APIRouter(prefix="/api/warrooms", tags=["warrooms"])


def _out(w: WarRoom, *, message_count: int = 0) -> dict[str, Any]:
    return {
        "id": w.id, "title": w.title, "status": w.status, "severity": w.severity, "case_id": w.case_id, "incident_id": w.incident_id,
        "participants": w.participants, "summary": w.summary, "client_id": w.client_id, "created_by": w.created_by,
        "created_at": iso(w.created_at), "closed_at": iso(w.closed_at), "message_count": message_count,
    }


def _msg_out(m: WarRoomMessage) -> dict[str, Any]:
    return {"id": m.id, "war_room_id": m.war_room_id, "author_id": m.author_id, "author_label": m.author_label, "kind": m.kind, "content": m.content, "pinned": m.pinned, "created_at": iso(m.created_at)}


@router.get("")
def list_warrooms(p: Principal = Depends(require("warroom.read")), db: Session = Depends(get_db), status: str | None = None) -> list[dict[str, Any]]:
    from sqlalchemy import func

    qy = select(WarRoom).where(p.scope(WarRoom.client_id) | WarRoom.client_id.is_(None)).order_by(WarRoom.created_at.desc())
    if status:
        qy = qy.where(WarRoom.status == status)
    rooms = db.execute(qy.limit(100)).scalars().all()
    counts = dict(db.execute(select(WarRoomMessage.war_room_id, func.count()).where(WarRoomMessage.war_room_id.in_([r.id for r in rooms])).group_by(WarRoomMessage.war_room_id)).all()) if rooms else {}
    return [_out(r, message_count=counts.get(r.id, 0)) for r in rooms]


class WarRoomIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: str = Field(min_length=2, max_length=300)
    severity: str = Field(default="high", max_length=10)
    case_id: str | None = None
    incident_id: str | None = None
    client_id: str | None = None


@router.post("", status_code=201)
def create_warroom(body: WarRoomIn, p: Principal = Depends(require("warroom.write")), db: Session = Depends(get_db)) -> dict[str, Any]:
    client_id = body.client_id
    if body.case_id:
        case = scoped_get(db, Case, body.case_id, p)
        client_id = client_id or case.client_id
    if body.incident_id:
        inc = scoped_get(db, Incident, body.incident_id, p)
        client_id = client_id or inc.client_id
    w = WarRoom(title=body.title, severity=body.severity, case_id=body.case_id, incident_id=body.incident_id, client_id=client_id,
                participants=[{"user_id": p.user.id, "label": p.label, "role": "lead"}], created_by=p.user.id)
    db.add(w)
    db.flush()
    db.add(WarRoomMessage(war_room_id=w.id, kind="system", author_label="system", content=f"{p.label} opened this war room."))
    audit.record(db, "warroom.create", actor=p.label, actor_id=p.user.id, resource_type="war_room", resource_id=w.id, client_id=w.client_id, ip=p.ip)
    events.publish(db, "warroom.created", id=w.id, client_id=w.client_id)
    return _out(w)


@router.get("/{wid}")
def get_warroom(wid: str, p: Principal = Depends(require("warroom.read")), db: Session = Depends(get_db)) -> dict[str, Any]:
    w = scoped_get(db, WarRoom, wid, p)
    msgs = db.execute(select(WarRoomMessage).where(WarRoomMessage.war_room_id == wid).order_by(WarRoomMessage.created_at)).scalars().all()
    out = _out(w, message_count=len(msgs))
    out["messages"] = [_msg_out(m) for m in msgs]
    return out


@router.post("/{wid}/join")
def join_warroom(wid: str, p: Principal = Depends(require("warroom.write")), db: Session = Depends(get_db)) -> dict[str, Any]:
    w = scoped_get(db, WarRoom, wid, p)
    if not any(part.get("user_id") == p.user.id for part in w.participants):
        w.participants = [*w.participants, {"user_id": p.user.id, "label": p.label, "role": "member"}]
        db.add(WarRoomMessage(war_room_id=w.id, kind="system", author_label="system", content=f"{p.label} joined."))
    return _out(w)


class MessageIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    content: str = Field(min_length=1, max_length=10000)


@router.post("/{wid}/messages", status_code=201)
def post_message(wid: str, body: MessageIn, p: Principal = Depends(require("warroom.write")), db: Session = Depends(get_db)) -> dict[str, Any]:
    w = scoped_get(db, WarRoom, wid, p)
    if w.status != "active":
        raise HTTPException(409, "this war room has been stood down")
    m = WarRoomMessage(war_room_id=w.id, author_id=p.user.id, author_label=p.label, content=body.content)
    db.add(m)
    db.flush()
    events.publish(db, "warroom.message", id=w.id, client_id=w.client_id)
    return _msg_out(m)


@router.post("/{wid}/messages/{mid}/pin")
def pin_message(wid: str, mid: str, p: Principal = Depends(require("warroom.write")), db: Session = Depends(get_db)) -> dict[str, Any]:
    w = scoped_get(db, WarRoom, wid, p)
    m = db.get(WarRoomMessage, mid)
    if m is None or m.war_room_id != w.id:
        raise HTTPException(404, "not found")
    m.pinned = not m.pinned
    return _msg_out(m)


class StandDownIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    summary: str = Field(default="", max_length=8000)


@router.post("/{wid}/stand-down")
def stand_down(wid: str, body: StandDownIn, p: Principal = Depends(require("warroom.manage")), db: Session = Depends(get_db)) -> dict[str, Any]:
    w = scoped_get(db, WarRoom, wid, p)
    if w.status != "active":
        raise HTTPException(409, "already stood down")
    w.status, w.closed_at, w.summary = "stood_down", utcnow(), body.summary
    db.add(WarRoomMessage(war_room_id=w.id, kind="system", author_label="system", content=f"{p.label} stood this war room down."))
    audit.record(db, "warroom.stand_down", actor=p.label, actor_id=p.user.id, resource_type="war_room", resource_id=w.id, ip=p.ip)
    events.publish(db, "warroom.message", id=w.id, client_id=w.client_id)
    return _out(w)
