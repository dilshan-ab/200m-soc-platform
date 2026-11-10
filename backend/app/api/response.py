from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit
from ..db import get_db
from ..deps import Principal, require, require_step_up
from ..models import ActionRequest, Approval, User
from ..policy import ACTIONS
from ..services import response as svc
from ..services.settings_svc import get_setting, set_setting
from .common import iso, page_out, paginate

router = APIRouter(prefix="/api/response", tags=["response"])


def req_out(db: Session, r: ActionRequest, detail: bool = False) -> dict[str, Any]:
    spec = ACTIONS.get(r.action_key)
    requester = db.get(User, r.requester_id)
    d: dict[str, Any] = {"id": r.id, "action_key": r.action_key, "label": spec.label if spec else r.action_key, "risk": spec.risk if spec else "", "targets": r.targets, "status": r.status,
         "requester": (requester.name or requester.email) if requester else "", "requester_id": r.requester_id, "reason": r.reason, "client_id": r.client_id,
         "case_id": r.case_id, "alert_id": r.alert_id, "approvals_required": r.approvals_required, "expires_at": iso(r.expires_at), "created_at": iso(r.created_at),
         "finished_at": iso(r.finished_at), "revert_at": iso(r.revert_at)}
    if detail:
        d["params"] = r.params
        d["result"] = r.result
        d["approvals"] = [{"approver_id": a.approver_id, "decision": a.decision, "reason": a.reason, "at": iso(a.decided_at)} for a in db.execute(select(Approval).where(Approval.request_id == r.id)).scalars()]
    return d


@router.get("/catalogue")
def catalogue(p: Principal = Depends(require("response.read"))) -> list[dict[str, Any]]:
    return [{"key": a.key, "label": a.label, "system": a.system, "risk": a.risk, "reversible": a.reversible, "approvals": a.approvals, "target_kind": a.target_kind, "params": a.params, "capability": a.capability} for a in ACTIONS.values()]


@router.get("/requests")
def list_requests(p: Principal = Depends(require("response.read")), db: Session = Depends(get_db), status: list[str] = Query(default=[]), page: int = 1, limit: int = 50) -> dict[str, Any]:
    qy = select(ActionRequest).where(p.scope(ActionRequest.client_id))
    if status:
        qy = qy.where(ActionRequest.status.in_(status))
    rows, total = paginate(db, qy.order_by(ActionRequest.created_at.desc()), page, limit)
    return page_out([req_out(db, r) for r in rows], total, page, limit)


@router.get("/requests/{rid}")
def get_request(rid: str, p: Principal = Depends(require("response.read")), db: Session = Depends(get_db)) -> dict[str, Any]:
    r = db.get(ActionRequest, rid)
    if r is None or not p.can_see_client(r.client_id):
        raise HTTPException(404, "not found")
    return req_out(db, r, True)


class RequestIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action_key: str = Field(max_length=60)
    targets: list[str] = Field(min_length=1, max_length=50)
    params: dict[str, Any] = Field(default_factory=dict)
    reason: str = Field(min_length=5, max_length=2000)
    alert_id: str | None = None
    case_id: str | None = None
    idempotency_key: str | None = Field(default=None, max_length=80)


@router.post("/requests", status_code=201)
def create(body: RequestIn, p: Principal = Depends(require("response.request")), db: Session = Depends(get_db)) -> dict[str, Any]:
    spec = ACTIONS.get(body.action_key)
    if spec is None:
        raise HTTPException(400, "unknown action")
    if not p.can(spec.capability):
        raise HTTPException(403, f"missing capability {spec.capability}")
    try:
        r = svc.create_request(db, requester=p.user, action_key=body.action_key, targets=body.targets, params=body.params, reason=body.reason, alert_id=body.alert_id, case_id=body.case_id, scope=p, idempotency_key=body.idempotency_key)
    except svc.ResponseError as e:
        raise HTTPException(e.status, str(e)) from e
    return req_out(db, r, True)


class DecisionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    decision: str = Field(pattern="^(approve|reject)$")
    reason: str = Field(min_length=3, max_length=1000)


@router.post("/requests/{rid}/decision")
def decide(rid: str, body: DecisionIn, p: Principal = Depends(require_step_up), db: Session = Depends(get_db)) -> dict[str, Any]:
    r = db.get(ActionRequest, rid)
    if r is None or not p.can_see_client(r.client_id):
        raise HTTPException(404, "not found")
    try:
        svc.decide(db, p, r, body.decision, body.reason)
    except svc.ResponseError as e:
        if r.status == "expired":
            db.commit()
        raise HTTPException(e.status, str(e)) from e
    return req_out(db, r, True)


@router.post("/requests/{rid}/cancel")
def cancel(rid: str, p: Principal = Depends(require("response.request")), db: Session = Depends(get_db)) -> dict[str, Any]:
    r = db.get(ActionRequest, rid)
    if r is None or not p.can_see_client(r.client_id):
        raise HTTPException(404, "not found")
    try:
        svc.cancel(db, p, r)
    except svc.ResponseError as e:
        raise HTTPException(e.status, str(e)) from e
    return req_out(db, r)


@router.post("/requests/{rid}/resolve-unknown")
def resolve_unknown(rid: str, body: DecisionIn, p: Principal = Depends(require("response.approve")), db: Session = Depends(get_db)) -> dict[str, Any]:
    """Operator reconciles an 'outcome_unknown' request after checking the target system."""
    r = db.get(ActionRequest, rid)
    if r is None or not p.can_see_client(r.client_id):
        raise HTTPException(404, "not found")
    if r.status != "outcome_unknown":
        raise HTTPException(409, f"request is {r.status}")
    r.status = "succeeded" if body.decision == "approve" else "failed"
    r.result = {**r.result, "reconciled_by": p.label, "note": body.reason}
    audit.record(db, "response.reconcile", actor=p.label, actor_id=p.user.id, resource_type="action_request", resource_id=r.id, client_id=r.client_id, meta={"to": r.status})
    return req_out(db, r)


class KillIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    engaged: bool
    reason: str = Field(min_length=5, max_length=500)


@router.get("/guardrails")
def guardrails(p: Principal = Depends(require("response.read")), db: Session = Depends(get_db)) -> dict[str, Any]:
    return {"kill_switch": get_setting(db, "response_kill_switch"), "protected_targets": sorted(svc.protected_targets(db)), "max_per_hour": get_setting(db, "response_max_per_hour"), "policy_version": get_setting(db, "response_policy_version")}


@router.post("/kill-switch")
def kill_switch(body: KillIn, p: Principal = Depends(require("admin.settings")), db: Session = Depends(get_db)) -> dict[str, Any]:
    # Engaging is allowed without step-up (fail safe); disengaging needs recent MFA.
    if not body.engaged:
        require_step_up(p)
    set_setting(db, "response_kill_switch", body.engaged)
    audit.record(db, "response.kill_switch", actor=p.label, actor_id=p.user.id, ip=p.ip, meta={"engaged": body.engaged, "reason": body.reason})
    return {"kill_switch": body.engaged}


class ProtectedIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    targets: list[str] = Field(max_length=500)


@router.put("/protected-targets")
def set_protected(body: ProtectedIn, p: Principal = Depends(require("admin.settings")), db: Session = Depends(get_db)) -> dict[str, Any]:
    require_step_up(p)
    clean = sorted({t.strip().lower() for t in body.targets if t.strip() and len(t) <= 255})
    set_setting(db, "protected_targets", clean)
    set_setting(db, "response_policy_version", int(get_setting(db, "response_policy_version", 1)) + 1)
    audit.record(db, "response.protected_targets", actor=p.label, actor_id=p.user.id, ip=p.ip, meta={"count": len(clean)})
    return {"protected_targets": clean}
