"""Approvals inbox: action requests + configuration/change requests."""
from __future__ import annotations

from datetime import timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit
from ..db import get_db
from ..deps import Principal, get_principal, require_step_up
from ..models import ActionRequest, ApprovalRequest, RetentionPolicy, Tool, User, utcnow
from ..security import payload_hash
from ..sessions import revoke_all
from .common import iso
from .response import req_out

router = APIRouter(prefix="/api/approvals", tags=["approvals"])


def create_change(db: Session, kind: str, payload: dict[str, Any], requester: User, reason: str, required: int = 1) -> ApprovalRequest:
    cr = ApprovalRequest(kind=kind, payload=payload, payload_hash=payload_hash(payload), requester_id=requester.id, reason=reason, approvals_required=required, expires_at=utcnow() + timedelta(hours=24))
    db.add(cr)
    db.flush()
    return cr


def supersede_changes(db: Session, kind: str, resource_key: str, resource_id: str, p: Principal) -> None:
    """An owner's direct change replaces older pending intentions for that resource."""
    if not p.is_superadmin:
        return
    for pending in db.execute(select(ApprovalRequest).where(ApprovalRequest.kind == kind, ApprovalRequest.status == "pending")).scalars():
        if pending.payload.get(resource_key) != resource_id:
            continue
        pending.status, pending.decided_at = "superseded", utcnow()
        pending.decision_reason = "Superseded by a direct super-admin change"
        audit.record(db, "change.supersede", actor=p.label, actor_id=p.user.id, resource_type="change_request", resource_id=pending.id, ip=p.ip, meta={"kind": kind, "superadmin_override": True})


def apply_change(db: Session, cr: ApprovalRequest) -> None:
    from .integrations import apply_enable

    pl = cr.payload
    if cr.kind == "tool.enable":
        t = db.get(Tool, pl["tool_id"])
        if t is None or t.config_version != pl["config_version"]:
            raise ValueError("tool changed after the request; re-test and re-request")
        apply_enable(db, t)
    elif cr.kind == "user.role":
        u = db.get(User, pl["user_id"])
        if u is None:
            raise ValueError("user missing")
        if u.role == "superadmin":
            raise ValueError("the super admin account cannot be demoted")
        u.role = pl["role"]
        revoke_all(db, u.id)
    elif cr.kind == "retention.update":
        pol = db.execute(select(RetentionPolicy).where(RetentionPolicy.dataset == pl["dataset"])).scalar_one_or_none()
        if pol is None:
            pol = RetentionPolicy(dataset=pl["dataset"])
            db.add(pol)
        pol.days, pol.legal_hold = pl["days"], pl["legal_hold"]
    elif cr.kind == "backup.restore_test":
        pass  # recorded in audit; the restore is performed by the backup tooling
    else:
        raise ValueError(f"unknown change kind {cr.kind}")


def cr_out(db: Session, c: ApprovalRequest) -> dict[str, Any]:
    r = db.get(User, c.requester_id)
    return {"id": c.id, "kind": c.kind, "payload": c.payload, "status": c.status, "reason": c.reason, "requester": (r.name or r.email) if r else "", "requester_id": c.requester_id,
            "approvals_required": c.approvals_required, "approvers": c.approvers, "expires_at": iso(c.expires_at), "created_at": iso(c.created_at)}


@router.get("")
def inbox(p: Principal = Depends(get_principal), db: Session = Depends(get_db)) -> dict[str, Any]:
    acts = []
    if p.can("response.approve"):
        for r in db.execute(select(ActionRequest).where(ActionRequest.status == "pending_approval", p.scope(ActionRequest.client_id)).order_by(ActionRequest.created_at)).scalars():
            acts.append(req_out(db, r))
    changes = []
    if p.can("admin.settings"):
        for c in db.execute(select(ApprovalRequest).where(ApprovalRequest.status == "pending").order_by(ApprovalRequest.created_at)).scalars():
            changes.append(cr_out(db, c))
    return {"actions": acts, "changes": changes}


class ChangeDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")
    decision: str = Field(pattern="^(approve|reject)$")
    reason: str = Field(min_length=3, max_length=1000)


@router.post("/changes/{cid}/decision")
def decide_change(cid: str, body: ChangeDecision, p: Principal = Depends(require_step_up), db: Session = Depends(get_db)) -> dict[str, Any]:
    if not p.can("admin.settings"):
        raise HTTPException(403, "admin required")
    c = db.get(ApprovalRequest, cid)
    if c is None:
        raise HTTPException(404, "not found")
    if c.status != "pending":
        raise HTTPException(409, f"request is {c.status}")
    if c.expires_at <= utcnow():
        c.status = "expired"
        db.commit()
        raise HTTPException(409, "request expired")
    if c.requester_id == p.user.id and not p.is_superadmin:
        raise HTTPException(403, "you cannot approve your own request")
    if payload_hash(c.payload) != c.payload_hash:
        raise HTTPException(409, "payload changed since submission")
    if p.user.id in c.approvers and not p.is_superadmin:
        raise HTTPException(409, "already decided")
    audit.record(db, f"change.{body.decision}", actor=p.label, actor_id=p.user.id, resource_type="change_request", resource_id=c.id, ip=p.ip, meta={"kind": c.kind, "reason": body.reason, "superadmin_override": p.is_superadmin})
    c.decision_reason = body.reason
    if body.decision == "reject":
        c.status, c.decided_at = "rejected", utcnow()
        return cr_out(db, c)
    if p.user.id not in c.approvers:
        c.approvers = [*c.approvers, p.user.id]
    if p.is_superadmin or len(c.approvers) >= c.approvals_required:
        try:
            apply_change(db, c)
            c.status = "applied"
        except ValueError as e:
            c.status, c.decision_reason = "failed", str(e)
        c.decided_at = utcnow()
        audit.record(db, "change.apply", actor=p.label, actor_id=p.user.id, resource_type="change_request", resource_id=c.id, outcome="success" if c.status == "applied" else "failure", meta={"kind": c.kind})
    return cr_out(db, c)
