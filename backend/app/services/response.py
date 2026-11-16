"""Response actions: request -> approval -> controlled execution, with guardrails."""
from __future__ import annotations

import ipaddress
import re
from datetime import timedelta
from typing import TYPE_CHECKING, Any

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import audit
from ..connectors.base import ConnectorError
from ..models import ActionRequest, Alert, Approval, Asset, Case, Server, Tool, User, utcnow
from ..policy import ACTIONS, DEFAULT_PROTECTED, MAX_TARGETS_PER_ACTION, has_capability
from ..security import payload_hash
from . import events, tools_svc
from .settings_svc import get_setting

if TYPE_CHECKING:
    from ..deps import Principal

_HOST = re.compile(r"^[A-Za-z0-9_.\-]{1,255}$")
_USER = re.compile(r"^[A-Za-z0-9_.@\\\-]{1,160}$")
ACTIVE = ("pending_approval", "approved", "running")


class ResponseError(ValueError):
    def __init__(self, msg: str, status: int = 400) -> None:
        super().__init__(msg)
        self.status = status


def protected_targets(db: Session) -> set[str]:
    p = {str(x).lower() for x in DEFAULT_PROTECTED} | {str(x).lower() for x in get_setting(db, "protected_targets", [])}
    for s in db.execute(select(Server).where(Server.role == "soc_core")).scalars():
        p.add(s.host.lower())
        p.add(s.name.lower())
    return p


def _validate_target(kind: str, t: str) -> str:
    t = t.strip()
    if kind == "ip":
        try:
            ip = ipaddress.ip_address(t)
        except ValueError as e:
            raise ResponseError(f"invalid IP: {t[:50]}") from e
        if ip.is_loopback or ip.is_multicast or ip.is_unspecified or ip.is_link_local:
            raise ResponseError("target address is not allowed")
        return str(ip)
    if kind == "user":
        if not _USER.match(t):
            raise ResponseError("invalid user name")
        return t
    if not _HOST.match(t):
        raise ResponseError("invalid host name")
    return t.lower()


def _client_for(db: Session, alert: Alert | None, case: Case | None, targets: list[str]) -> str | None:
    if alert is not None and alert.client_id:
        return alert.client_id
    if case is not None and case.client_id:
        return case.client_id
    for t in targets:
        a = db.execute(select(Asset).where((Asset.name == t) | (Asset.hostname == t)).limit(1)).scalars().first()
        if a and a.client_id:
            return a.client_id
    return None


def create_request(
    db: Session, *, requester: User, action_key: str, targets: list[str], params: dict[str, Any], reason: str,
    alert_id: str | None = None, case_id: str | None = None, client_id: str | None = None, automation_rule_id: str | None = None,
    scope: Principal | None = None, idempotency_key: str | None = None,
) -> ActionRequest:
    spec = ACTIONS.get(action_key)
    if spec is None:
        raise ResponseError("unknown action")
    if get_setting(db, "response_kill_switch", False):
        raise ResponseError("response actions are currently disabled (kill switch)", 423)
    if not reason or len(reason.strip()) < 5:
        raise ResponseError("a reason is required")
    if not targets or len(targets) > MAX_TARGETS_PER_ACTION[spec.risk]:
        raise ResponseError(f"between 1 and {MAX_TARGETS_PER_ACTION[spec.risk]} targets are allowed for this action")
    if idempotency_key:
        ex = db.execute(select(ActionRequest).where(ActionRequest.requester_id == requester.id, ActionRequest.idempotency_key == idempotency_key)).scalar_one_or_none()
        if ex is not None:
            return ex
    clean = [_validate_target(spec.target_kind, t) for t in targets]
    prot = protected_targets(db)
    for t in clean:
        if t.lower() in prot:
            raise ResponseError(f"target {t} is protected", 403)
    for p in spec.params:
        if p not in params or not str(params[p]).strip():
            raise ResponseError(f"parameter '{p}' is required")
    alert = db.get(Alert, alert_id) if alert_id else None
    case = db.get(Case, case_id) if case_id else None
    if (alert_id and alert is None) or (case_id and case is None):
        raise ResponseError("alert or case not found", 404)
    cid = client_id or _client_for(db, alert, case, clean)
    if scope is not None:
        if cid is None and scope.client_ids is not None:
            raise ResponseError("cannot determine client scope for target", 403)
        if not scope.can_see_client(cid):
            raise ResponseError("not found", 404)
    owner_override = bool(spec.approvals and scope is not None and scope.is_superadmin and scope.user.id == requester.id and automation_rule_id is None)
    if owner_override:
        from ..deps import require_step_up

        require_step_up(scope)
    window = int(get_setting(db, "approval_window_minutes", 240))
    req = ActionRequest(
        action_key=action_key, targets=clean, params=params, payload_hash=payload_hash({"a": action_key, "t": clean, "p": params, "c": cid}), requester_id=requester.id,
        reason=reason.strip(), case_id=case_id, alert_id=alert_id, client_id=cid, idempotency_key=idempotency_key,
        approvals_required=0 if owner_override else spec.approvals, policy_version=int(get_setting(db, "response_policy_version", 1)),
        expires_at=utcnow() + timedelta(minutes=window), automation_rule_id=automation_rule_id,
    )
    rm = params.get("revert_minutes")
    if spec.reversible and rm:
        req.revert_at = None  # set when the action succeeds
    try:
        with db.begin_nested():
            db.add(req)
            db.flush()
    except IntegrityError:
        ex2 = db.execute(select(ActionRequest).where(ActionRequest.requester_id == requester.id, ActionRequest.idempotency_key == idempotency_key)).scalar_one()
        return ex2
    audit.record(db, "response.request", actor=requester.email, actor_id=requester.id, resource_type="action_request", resource_id=req.id, client_id=cid, meta={"action": action_key, "targets": clean, "superadmin_override": owner_override})
    if req.approvals_required == 0:
        req.status = "approved"
        events.enqueue(db, "action.execute", {"request_id": req.id})
    else:
        events.publish(db, "approval.pending", id=req.id, severity=spec.risk if spec.risk != "low" else "medium", client_id=cid)
    events.publish(db, "action.updated", id=req.id, client_id=cid)
    return req


def decide(db: Session, p: Principal, req: ActionRequest, decision: str, reason: str) -> ActionRequest:
    spec = ACTIONS[req.action_key]
    if decision not in ("approve", "reject"):
        raise ResponseError("invalid decision")
    if req.status != "pending_approval":
        raise ResponseError(f"request is {req.status}", 409)
    if req.expires_at <= utcnow():
        req.status = "expired"
        raise ResponseError("approval window expired", 409)
    if req.requester_id == p.user.id and not p.is_superadmin:
        raise ResponseError("you cannot approve your own request", 403)
    cap = "response.approve_critical" if spec.risk == "critical" else "response.approve"
    if not p.can(cap):
        raise ResponseError("insufficient role to approve this action", 403)
    if not p.can_see_client(req.client_id):
        raise ResponseError("not found", 404)
    if not reason.strip():
        raise ResponseError("a reason is required")
    if payload_hash({"a": req.action_key, "t": req.targets, "p": req.params, "c": req.client_id}) != req.payload_hash:
        raise ResponseError("request payload changed since submission", 409)
    if req.policy_version != int(get_setting(db, "response_policy_version", 1)):
        req.status = "expired"
        raise ResponseError("policy changed; request must be re-submitted", 409)
    previous = db.execute(select(Approval).where(Approval.request_id == req.id, Approval.approver_id == p.user.id)).scalar_one_or_none() if p.is_superadmin else None
    if previous is None:
        try:
            with db.begin_nested():
                db.add(Approval(request_id=req.id, approver_id=p.user.id, decision=decision, reason=reason.strip(), payload_hash=req.payload_hash))
                db.flush()
        except IntegrityError as e:
            raise ResponseError("you have already decided on this request", 409) from e
    audit.record(db, f"response.{decision}", actor=p.label, actor_id=p.user.id, resource_type="action_request", resource_id=req.id, client_id=req.client_id, ip=p.ip, meta={"reason": reason[:200], "superadmin_override": p.is_superadmin})
    if decision == "reject":
        req.status = "rejected"
    else:
        n = db.execute(select(func.count(Approval.id)).where(Approval.request_id == req.id, Approval.decision == "approve")).scalar_one()
        if p.is_superadmin or n >= req.approvals_required:
            req.status = "approved"
            events.enqueue(db, "action.execute", {"request_id": req.id})
    events.publish(db, "action.updated", id=req.id, client_id=req.client_id)
    return req


def cancel(db: Session, p: Principal, req: ActionRequest) -> None:
    if req.status != "pending_approval":
        raise ResponseError(f"request is {req.status}", 409)
    if req.requester_id != p.user.id and not p.can("response.approve"):
        raise ResponseError("not allowed", 403)
    req.status = "cancelled"
    audit.record(db, "response.cancel", actor=p.label, actor_id=p.user.id, resource_type="action_request", resource_id=req.id, client_id=req.client_id)


def _find_tool(db: Session, system: str, client_id: str | None) -> Tool | None:
    tools = db.execute(select(Tool).where(Tool.type == system, Tool.enabled.is_(True))).scalars().all()
    for t in tools:
        if t.config.get("client_id") in (None, client_id):
            return t
    return None


@events.handler("action.execute")
def execute(db: Session, payload: dict[str, Any]) -> None:
    req = db.get(ActionRequest, payload["request_id"])
    if req is None or req.status != "approved":
        return  # idempotent: already running/finished
    spec = ACTIONS[req.action_key]
    req.status, req.started_at = "running", utcnow()
    db.commit()
    req = db.get(ActionRequest, payload["request_id"])
    assert req is not None

    def finish(status: str, result: dict[str, Any]) -> None:
        req.status, req.result, req.finished_at = status, result, utcnow()
        audit.record(db, "response.execute", actor="system", resource_type="action_request", resource_id=req.id, client_id=req.client_id, outcome="success" if status == "succeeded" else "failure", meta={"status": status, "action": req.action_key})
        events.publish(db, "action.updated", id=req.id, client_id=req.client_id)

    if get_setting(db, "response_kill_switch", False):
        return finish("failed", {"error": "kill switch engaged"})
    prot = protected_targets(db)
    if any(str(t).lower() in prot for t in req.targets):
        return finish("failed", {"error": "protected target"})
    hour_ago = utcnow() - timedelta(hours=1)
    n = db.execute(select(func.count(ActionRequest.id)).where(ActionRequest.action_key == req.action_key, ActionRequest.status == "succeeded", ActionRequest.finished_at >= hour_ago, ActionRequest.client_id == req.client_id)).scalar_one()
    if n >= int(get_setting(db, "response_max_per_hour", 20)):
        return finish("failed", {"error": "hourly blast-radius limit reached"})
    tool = _find_tool(db, spec.system, req.client_id)
    if tool is None:
        return finish("failed", {"error": f"no enabled {spec.system} integration"})
    try:
        c = tools_svc.build_connector(db, tool)
        try:
            result = c.execute(req.action_key, list(req.targets), dict(req.params))
        finally:
            c.close()
    except ConnectorError as e:
        msg = str(e)
        # a transport failure after a mutating call may or may not have reached the target
        if msg.startswith("request failed"):
            return finish("outcome_unknown", {"error": msg, "note": "verify on the target system, then mark resolved"})
        return finish("failed", {"error": msg[:300]})
    rm = req.params.get("revert_minutes")
    if spec.reversible and rm:
        req.revert_at = utcnow() + timedelta(minutes=min(int(rm), 7 * 24 * 60))
    finish("succeeded", result)


REVERSE = {"block_ip": "unblock_ip", "isolate_host": "release_host"}


def revert_due(db: Session) -> int:
    """Auto-expire temporary blocks/isolations by raising a follow-up (auto-approved, low-risk) request."""
    from .settings_svc import system_user

    n = 0
    for r in db.execute(select(ActionRequest).where(ActionRequest.status == "succeeded", ActionRequest.revert_at.is_not(None), ActionRequest.revert_at <= utcnow())).scalars():
        r.revert_at = None
        rev = REVERSE.get(r.action_key)
        if not rev:
            continue
        sys_u = system_user(db)
        spec = ACTIONS[rev]
        nr = ActionRequest(
            action_key=rev, targets=r.targets, params={"reverts": r.id}, payload_hash=payload_hash({"a": rev, "t": r.targets, "p": {"reverts": r.id}, "c": r.client_id}),
            requester_id=sys_u.id, reason=f"Automatic expiry of {r.action_key} {r.id}", client_id=r.client_id, approvals_required=0,
            policy_version=r.policy_version, expires_at=utcnow() + timedelta(hours=1), status="approved" if spec.risk in ("low", "medium") else "pending_approval",
        )
        db.add(nr)
        db.flush()
        events.enqueue(db, "action.execute", {"request_id": nr.id})
        n += 1
    return n


def reconcile_stale(db: Session) -> int:
    """Requests stuck in 'running' for >15 minutes become outcome_unknown (never silently retried)."""
    n = 0
    for r in db.execute(select(ActionRequest).where(ActionRequest.status == "running", ActionRequest.started_at <= utcnow() - timedelta(minutes=15))).scalars():
        r.status, r.result = "outcome_unknown", {"error": "execution did not report back"}
        n += 1
    for r in db.execute(select(ActionRequest).where(ActionRequest.status == "pending_approval", ActionRequest.expires_at <= utcnow())).scalars():
        r.status = "expired"
        n += 1
    return n


def can_manage(p: Principal) -> bool:
    return has_capability(p.user.role, p.user.grants, "response.read", p.user.denied)
