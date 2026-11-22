"""Playbook (SOAR) execution engine: walks a playbook's node/edge graph for real,
dispatching action nodes to the same action vocabulary as automation rules and to the
response-action system (with its approvals/guardrails intact), branching on condition
nodes, and pausing/resuming the run across async approval + execution."""
from __future__ import annotations

import re
from datetime import timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import ActionRequest, Alert, Case, Playbook, PlaybookRun, utcnow
from ..policy import sev_rank
from . import events
from .automation import FIELDS, OPS

ACTION_TYPES = {"set_status", "add_note", "create_case", "enrich", "request_action"}
TERMINAL_REQUEST_STATUSES = {"succeeded", "failed", "rejected", "cancelled", "outcome_unknown", "expired"}
_ALERT_STATUSES = {"acknowledged", "investigating", "false_positive", "resolved"}


# Variables: a node's result is addressable by later nodes as "<node_id>.<key>" (dotted paths reach into nested
# results); the triggering alert and case are "alert.<field>" and "case.<field>". Conditions can test them
# (field = "enrich-1.verdict") and notification/note text can embed them ("{{enrich-1.score}}").
VAR_REF = re.compile(r"^[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)+$")
VAR_TEMPLATE = re.compile(r"\{\{\s*([A-Za-z0-9_.-]+)\s*\}\}")
VAR_OPS = OPS | {"gt", "lt", "lte"}
ALERT_VARS = FIELDS | {"id", "dst_ip", "file_hash"}
CASE_VARS = {"id", "number", "title", "severity", "status"}


class EngineError(ValueError):
    pass


def _ancestors(edges: list[dict[str, Any]], node_id: str) -> set[str]:
    """All nodes that can run before node_id (upstream along edges)."""
    parents: dict[str, list[str]] = {}
    for e in edges:
        parents.setdefault(e.get("target", ""), []).append(e.get("source", ""))
    seen: set[str] = set()
    stack = list(parents.get(node_id, []))
    while stack:
        n = stack.pop()
        if n not in seen:
            seen.add(n)
            stack.extend(parents.get(n, []))
    return seen


def _check_var_refs(refs: list[str], nodes: list[dict[str, Any]], edges: list[dict[str, Any]], node_id: Any, where: str) -> None:
    by_id = {n.get("id"): n for n in nodes}
    up = _ancestors(edges, str(node_id))
    for ref in refs:
        head = ref.split(".", 1)[0]
        if head in ("alert", "case"):
            key = ref.split(".", 1)[1]
            if key not in (ALERT_VARS if head == "alert" else CASE_VARS):
                raise EngineError(f"{where} {node_id}: unknown {head} field in variable {ref!r}")
            continue
        if head not in by_id:
            raise EngineError(f"{where} {node_id}: variable {ref!r} refers to unknown node {head!r}")
        if head not in up:
            raise EngineError(f"{where} {node_id}: variable {ref!r} refers to node {head!r}, which does not run before this node")


def _lookup_var(ref: str, variables: dict[str, Any]) -> Any:
    cur: Any = variables
    for part in ref.split("."):
        if not isinstance(cur, dict) or part not in cur:
            raise EngineError(f"unknown variable {ref!r} (the node has not run or has no such output)")
        cur = cur[part]
    return cur


def _vars_for(run: PlaybookRun, alert: Alert | None, case: Case | None) -> dict[str, Any]:
    """Variable namespace: results of completed nodes in this run (survives pause/resume) plus alert/case fields."""
    out: dict[str, Any] = {}
    for entry in run.execution_log or []:
        if entry.get("status") == "completed" and isinstance(entry.get("result"), dict):
            out[entry["node_id"]] = entry["result"]
    if alert is not None:
        out["alert"] = {k: getattr(alert, k, None) for k in ALERT_VARS}
    if case is not None:
        out["case"] = {k: getattr(case, k, None) for k in CASE_VARS}
    return out


def _render(text: str, variables: dict[str, Any]) -> str:
    def sub(m: re.Match[str]) -> str:
        return str(_lookup_var(m.group(1), variables))

    return VAR_TEMPLATE.sub(sub, text)


def validate_graph(nodes: list[dict[str, Any]], edges: list[dict[str, Any]]) -> None:
    ids = {n.get("id") for n in nodes}
    if not any(n.get("type") == "trigger" for n in nodes):
        raise EngineError("a playbook needs at least one trigger node")
    for e in edges:
        if e.get("source") not in ids or e.get("target") not in ids:
            raise EngineError(f"edge {e.get('id')} references a node that does not exist")
    for n in nodes:
        data = n.get("data") or {}
        t = n.get("type")
        if t == "action":
            atype = data.get("action_type")
            if atype not in ACTION_TYPES:
                raise EngineError(f"action node {n.get('id')}: invalid action_type {atype!r}")
            if atype == "request_action" and not data.get("action_key"):
                raise EngineError(f"action node {n.get('id')}: request_action needs an action_key")
            if atype == "set_status" and data.get("status") not in _ALERT_STATUSES:
                raise EngineError(f"action node {n.get('id')}: invalid status {data.get('status')!r}")
            for key in ("text", "title"):
                if isinstance(data.get(key), str):
                    _check_var_refs(VAR_TEMPLATE.findall(data[key]), nodes, edges, n.get("id"), "action node")
        elif t == "condition":
            field = data.get("field")
            if isinstance(field, str) and VAR_REF.match(field) and field not in FIELDS:
                if data.get("op") not in VAR_OPS:
                    raise EngineError(f"condition node {n.get('id')}: invalid op {data.get('op')!r}")
                _check_var_refs([field], nodes, edges, n.get("id"), "condition node")
            elif field not in FIELDS or data.get("op") not in OPS:
                raise EngineError(f"condition node {n.get('id')}: invalid field/op")
        elif t == "notification":
            if not data.get("destination_id"):
                raise EngineError(f"notification node {n.get('id')}: destination_id is required")
            if isinstance(data.get("message"), str):
                _check_var_refs(VAR_TEMPLATE.findall(data["message"]), nodes, edges, n.get("id"), "notification node")


def _find_node(pb: Playbook, node_id: str) -> dict[str, Any] | None:
    return next((n for n in (pb.nodes or []) if n.get("id") == node_id), None)


def _outgoing(pb: Playbook, node_id: str, branch: str | None = None) -> list[str]:
    out = [e for e in (pb.edges or []) if e.get("source") == node_id]
    if branch is not None:
        labelled = [e for e in out if str(e.get("label", "")).strip().lower() in ("yes", "no")]
        matching = [e for e in labelled if str(e.get("label", "")).strip().lower() == branch]
        if labelled:
            out = matching
    return [e["target"] for e in out]


def _append_log(run: PlaybookRun, node_id: str, ntype: str, status: str, result: dict[str, Any], started_at: Any = None) -> None:
    run.execution_log = [*(run.execution_log or []), {
        "node_id": node_id, "type": ntype, "status": status,
        "started_at": (started_at or utcnow()).isoformat(), "finished_at": utcnow().isoformat(), "result": result,
    }]


def _ctx_alert(db: Session, run: PlaybookRun) -> Alert | None:
    if run.trigger_ref.startswith("alert:"):
        return db.get(Alert, run.trigger_ref.split(":", 1)[1])
    return None


def _ctx_case(db: Session, run: PlaybookRun) -> Case | None:
    if run.trigger_ref.startswith("case:"):
        return db.get(Case, run.trigger_ref.split(":", 1)[1])
    return None


def _num(x: Any) -> float | None:
    if isinstance(x, bool):
        return None
    try:
        return float(x)
    except (TypeError, ValueError):
        return None


def _eval_condition(data: dict[str, Any], alert: Alert | None, variables: dict[str, Any] | None = None) -> bool:
    field = str(data.get("field", ""))
    val, op = data.get("value"), data.get("op")
    if field not in FIELDS and VAR_REF.match(field):
        actual = _lookup_var(field, variables or {})
        a, b = _num(actual), _num(val)
        if op in ("gt", "lt", "gte", "lte") and a is not None and b is not None:
            return {"gt": a > b, "lt": a < b, "gte": a >= b, "lte": a <= b}[str(op)]
        if op in ("gt", "lt", "lte"):
            return False
        if op in ("eq", "ne") and a is not None and b is not None:
            return (a == b) == (op == "eq")
    else:
        if alert is None:
            return False
        actual = getattr(alert, field, None)
    if op == "eq":
        return actual == val
    if op == "ne":
        return actual != val
    if op == "in":
        return actual in (val if isinstance(val, list) else [val])
    if op == "gte":
        return sev_rank(str(actual)) >= sev_rank(str(val))
    if op == "contains":
        return str(val).lower() in str(actual or "").lower()
    if op == "startswith":
        return str(actual or "").lower().startswith(str(val).lower())
    return False


def _send_notification(db: Session, pb: Playbook, run: PlaybookRun, node: dict[str, Any], alert: Alert | None, case: Case | None) -> dict[str, Any]:
    from ..models import NotificationDelivery

    data = node.get("data") or {}
    dest_id = data["destination_id"]
    subject = f"[Playbook] {pb.name}: {node.get('data', {}).get('label', node['id'])}"
    body = f"Alert: {alert.title}\n" if alert else (f"Case #{case.number}: {case.title}\n" if case else "")
    body += _render(str(data.get("message", "")), _vars_for(run, alert, case))
    key = f"playbook:{run.id}:{node['id']}"
    d = NotificationDelivery(rule_id=None, destination_id=dest_id, event_ref=key, dedupe_key=key, subject=subject[:300], body=body, alert_id=(alert.id if alert else None))
    db.add(d)
    db.flush()
    events.enqueue(db, "notify.deliver", {"delivery_id": d.id})
    return {"delivery_id": d.id}


def _run_action(db: Session, pb: Playbook, run: PlaybookRun, node: dict[str, Any], alert: Alert | None, case: Case | None) -> tuple[dict[str, Any], bool]:
    from . import cases as cases_svc
    from . import enrichment_engine, response
    from .intel import queue_enrichment
    from .settings_svc import system_user

    data = node.get("data") or {}
    atype = data.get("action_type")
    if atype == "set_status":
        if alert is None:
            raise EngineError("no alert in context")
        status = data.get("status")
        if status not in _ALERT_STATUSES:
            raise EngineError(f"invalid status {status!r}")
        alert.status = status
        if status == "acknowledged" and alert.acknowledged_at is None:
            alert.acknowledged_at = utcnow()
        return {"status": alert.status}, False
    if atype == "add_note":
        if alert is None:
            raise EngineError("no alert in context")
        alert.tuning_note = (alert.tuning_note + "\n" if alert.tuning_note else "") + f"[playbook:{pb.name}] {_render(str(data.get('text', '')), _vars_for(run, alert, case))[:500]}"
        return {"noted": True}, False
    if atype == "create_case":
        if alert is None:
            raise EngineError("no alert in context")
        c = cases_svc.create_case_from_alerts(db, [alert], actor=f"playbook:{pb.name}", template=data.get("template"), title=data.get("title"))
        return {"case_id": c.id, "number": c.number}, False
    if atype == "enrich":
        if alert is None:
            raise EngineError("no alert in context")
        ind = alert.src_ip or alert.file_hash
        if not ind:
            return {"skipped": "no indicator on alert"}, False
        itype = "ip" if alert.src_ip else "hash"
        j = queue_enrichment(db, ind, itype, system_user(db).id, alert_id=alert.id, client_id=alert.client_id)
        # Local reputation is computed now so later nodes can branch on it; connector results still arrive via the job.
        local = enrichment_engine.local_lookup(db, ind, itype)
        rules = enrichment_engine.rule_match(db, ind, itype)
        rep = enrichment_engine.compute_reputation(local, rules, {})
        return {"job_id": j.id, "indicator": ind, "indicator_type": itype, "verdict": rep["verdict"], "score": rep["score"], "confidence": rep["confidence"], "sources": rep["sources"]}, False
    if atype == "request_action":
        target_field = data.get("target_field", "src_ip")
        target = (getattr(alert, target_field, "") if alert and target_field in ("src_ip", "host", "username") else "") or data.get("target", "")
        if not target:
            return {"skipped": "no target available"}, False
        cid = (alert.client_id if alert else None) or (case.client_id if case else None)
        try:
            req = response.create_request(
                db, requester=system_user(db), action_key=data["action_key"], targets=[target], params=data.get("params", {}),
                reason=f"Playbook '{pb.name}'", alert_id=(alert.id if alert else None), case_id=(case.id if case else None), client_id=cid,
                playbook_run_id=run.id, playbook_node_id=node["id"], scope=None, idempotency_key=f"playbook:{run.id}:{node['id']}",
            )
        except response.ResponseError as e:
            raise EngineError(str(e)) from e
        return {"request_id": req.id, "status": req.status}, req.status not in TERMINAL_REQUEST_STATUSES
    raise EngineError(f"unknown action_type {atype!r}")


def _advance(db: Session, pb: Playbook, run: PlaybookRun, frontier: list[str], *, alert: Alert | None, case: Case | None) -> None:
    seen: set[str] = set()
    while frontier:
        node_id = frontier.pop(0)
        if node_id in seen:  # guard against accidental cycles
            continue
        seen.add(node_id)
        node = _find_node(pb, node_id)
        if node is None:
            _append_log(run, node_id, "unknown", "failed", {"error": "node not found"})
            continue
        ntype = node.get("type")
        started = utcnow()
        run.current_node = node_id
        if ntype == "end":
            _append_log(run, node_id, ntype, "completed", {}, started)
            run.status, run.finished_at = "completed", utcnow()
            return
        if ntype == "trigger":
            _append_log(run, node_id, ntype, "completed", {"started": True}, started)
            frontier.extend(_outgoing(pb, node_id))
            continue
        if ntype == "condition":
            try:
                ok = _eval_condition(node.get("data") or {}, alert, _vars_for(run, alert, case))
            except EngineError as e:
                _append_log(run, node_id, ntype, "failed", {"error": str(e)[:300]}, started)
                run.status, run.error, run.finished_at = "failed", str(e)[:500], utcnow()
                return
            _append_log(run, node_id, ntype, "completed", {"matched": ok}, started)
            frontier.extend(_outgoing(pb, node_id, "yes" if ok else "no"))
            continue
        if ntype == "notification":
            try:
                result = _send_notification(db, pb, run, node, alert, case)
                _append_log(run, node_id, ntype, "completed", result, started)
            except Exception as e:  # noqa: BLE001 - don't let a notification failure kill the run
                _append_log(run, node_id, ntype, "failed", {"error": str(e)[:300]}, started)
            frontier.extend(_outgoing(pb, node_id))
            continue
        if ntype == "approval":
            _append_log(run, node_id, ntype, "paused", {"awaiting": "manual approval"}, started)
            run.status = "paused"
            return
        if ntype == "action":
            try:
                result, paused = _run_action(db, pb, run, node, alert, case)
            except Exception as e:  # noqa: BLE001
                _append_log(run, node_id, ntype, "failed", {"error": str(e)[:300]}, started)
                run.status, run.error, run.finished_at = "failed", str(e)[:500], utcnow()
                return
            if paused:
                _append_log(run, node_id, ntype, "paused", result, started)
                run.status = "paused"
                return
            _append_log(run, node_id, ntype, "completed", result, started)
            frontier.extend(_outgoing(pb, node_id))
            continue
        _append_log(run, node_id, str(ntype), "skipped", {"error": "unknown node type"}, started)
        frontier.extend(_outgoing(pb, node_id))
    if run.status == "running":
        run.status, run.finished_at = "completed", utcnow()


def start_run(db: Session, pb: Playbook, trigger_ref: str, *, alert: Alert | None = None, case: Case | None = None) -> PlaybookRun:
    run = PlaybookRun(playbook_id=pb.id, trigger_ref=trigger_ref, status="running")
    db.add(run)
    db.flush()
    triggers = [n["id"] for n in (pb.nodes or []) if n.get("type") == "trigger"]
    if not triggers:
        run.status, run.error, run.finished_at = "failed", "no trigger node", utcnow()
        return run
    _advance(db, pb, run, triggers, alert=alert, case=case)
    return run


def resume_run(db: Session, run: PlaybookRun, *, approved: bool, actor_label: str) -> None:
    if run.status != "paused":
        raise EngineError(f"run is {run.status}, not paused")
    pb = run.playbook
    node = _find_node(pb, run.current_node)
    if node is None or node.get("type") != "approval":
        raise EngineError("run is not paused on an approval node")
    if not approved:
        _append_log(run, run.current_node, "approval", "failed", {"rejected_by": actor_label})
        run.status, run.error, run.finished_at = "failed", f"rejected by {actor_label}", utcnow()
        return
    _append_log(run, run.current_node, "approval", "completed", {"approved_by": actor_label})
    run.status = "running"
    _advance(db, pb, run, _outgoing(pb, run.current_node), alert=_ctx_alert(db, run), case=_ctx_case(db, run))


def on_action_request_resolved(db: Session, req: ActionRequest) -> None:
    if not req.playbook_run_id or req.status not in TERMINAL_REQUEST_STATUSES:
        return
    run = db.get(PlaybookRun, req.playbook_run_id)
    if run is None or run.status != "paused" or run.current_node != req.playbook_node_id:
        return
    pb = run.playbook
    if req.status == "succeeded":
        _append_log(run, req.playbook_node_id or "", "action", "completed", {"request_id": req.id, "status": req.status})
        run.status = "running"
        _advance(db, pb, run, _outgoing(pb, req.playbook_node_id or ""), alert=_ctx_alert(db, run), case=_ctx_case(db, run))
    else:
        _append_log(run, req.playbook_node_id or "", "action", "failed", {"request_id": req.id, "status": req.status})
        run.status, run.error, run.finished_at = "failed", f"response action {req.status}", utcnow()


def on_event(db: Session, ev: dict[str, Any]) -> None:
    t = ev.get("type")
    if t == "action.updated":
        req = db.get(ActionRequest, ev.get("id", ""))
        if req is not None:
            on_action_request_resolved(db, req)
        return
    if t not in ("alert.created", "case.created"):
        return
    model = Alert if t == "alert.created" else Case
    obj = db.get(model, ev.get("id", ""))
    if obj is None:
        return
    for pb in db.execute(select(Playbook).where(Playbook.enabled.is_(True), Playbook.status == "published", Playbook.trigger == t)).scalars():
        if pb.client_id and pb.client_id != obj.client_id:
            continue
        ref = f"{'alert' if t == 'alert.created' else 'case'}:{obj.id}"
        start_run(db, pb, ref, alert=obj if t == "alert.created" else None, case=obj if t == "case.created" else None)


MIN_SCHEDULE_MINUTES = 5
MAX_SCHEDULE_MINUTES = 10080  # one week


def sync_schedule(pb: Playbook, *, reset: bool = False) -> None:
    """Keep next_run_at consistent with trigger/interval. Raises EngineError on an invalid schedule."""
    if pb.trigger != "scheduled":
        pb.schedule_interval_minutes, pb.next_run_at = None, None
        return
    iv = pb.schedule_interval_minutes
    if iv is None or not (MIN_SCHEDULE_MINUTES <= iv <= MAX_SCHEDULE_MINUTES):
        raise EngineError(f"scheduled playbooks need schedule_interval_minutes between {MIN_SCHEDULE_MINUTES} and {MAX_SCHEDULE_MINUTES}")
    if reset or pb.next_run_at is None:
        pb.next_run_at = utcnow() + timedelta(minutes=iv)


def run_due_scheduled(db: Session) -> int:
    """Start a run for each enabled, published scheduled playbook whose next_run_at has passed.

    Missed intervals are not replayed: next_run_at moves to now + interval, so a long outage causes one run, not a burst.
    """
    now = utcnow()
    n = 0
    due = db.execute(
        select(Playbook).where(
            Playbook.enabled.is_(True),
            Playbook.status == "published",
            Playbook.trigger == "scheduled",
            Playbook.next_run_at.is_not(None),
            Playbook.next_run_at <= now,
        )
    ).scalars().all()
    for pb in due:
        occurrence = pb.next_run_at.isoformat() if pb.next_run_at else ""
        pb.last_run_at = now
        pb.next_run_at = now + timedelta(minutes=pb.schedule_interval_minutes or MAX_SCHEDULE_MINUTES)
        start_run(db, pb, f"scheduled:{occurrence}")
        events.publish(db, "playbook.executed", id=pb.id)
        n += 1
    return n
