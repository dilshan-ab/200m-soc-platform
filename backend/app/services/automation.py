"""Automation rules: 'when alert matches X -> do Y'. Dry-run, rate limits, circuit breaker."""
from __future__ import annotations

from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models import Alert, AutomationRule, AutomationRun, utcnow
from ..policy import sev_rank

FIELDS = {"severity", "source", "rule_id", "host", "category", "title", "client_id", "src_ip", "username", "status"}
OPS = {"eq", "ne", "in", "gte", "contains", "startswith"}
ACTION_TYPES = {"set_status", "create_case", "enrich", "request_action", "add_note"}
MAX_CONSECUTIVE_FAILURES = 5


def validate_rule(conditions: list[dict[str, Any]], actions: list[dict[str, Any]]) -> None:
    for c in conditions:
        if c.get("field") not in FIELDS or c.get("op") not in OPS or "value" not in c:
            raise ValueError(f"invalid condition: {c}")
        if c["op"] == "gte" and c["field"] != "severity":
            raise ValueError("gte is only valid on severity")
    if not actions:
        raise ValueError("at least one action is required")
    for a in actions:
        if a.get("type") not in ACTION_TYPES:
            raise ValueError(f"invalid action type: {a.get('type')}")


def matches(alert: Alert, conditions: list[dict[str, Any]]) -> bool:
    for c in conditions:
        actual = getattr(alert, c["field"], None)
        val = c["value"]
        op = c["op"]
        if op == "eq" and actual != val:
            return False
        if op == "ne" and actual == val:
            return False
        if op == "in" and actual not in (val if isinstance(val, list) else [val]):
            return False
        if op == "gte" and sev_rank(str(actual)) < sev_rank(str(val)):
            return False
        if op == "contains" and str(val).lower() not in str(actual or "").lower():
            return False
        if op == "startswith" and not str(actual or "").lower().startswith(str(val).lower()):
            return False
    return True


def on_event(db: Session, ev: dict[str, Any]) -> None:
    if ev.get("type") != "alert.created":
        return
    alert = db.get(Alert, ev.get("id", ""))
    if alert is None:
        return
    for rule in db.execute(select(AutomationRule).where(AutomationRule.enabled.is_(True), AutomationRule.trigger == "alert.created")).scalars():
        if rule.client_id and rule.client_id != alert.client_id:
            continue
        run_rule(db, rule, alert, dry_run=False)


def run_rule(db: Session, rule: AutomationRule, alert: Alert, *, dry_run: bool) -> AutomationRun:
    ref = f"alert:{alert.id}"
    if not dry_run:
        recent = db.execute(
            select(func.count(AutomationRun.id)).where(AutomationRun.rule_id == rule.id, AutomationRun.dry_run.is_(False), AutomationRun.matched.is_(True),
                                                       AutomationRun.created_at >= utcnow().replace(minute=0, second=0, microsecond=0))
        ).scalar_one()
        if recent >= rule.max_per_hour:
            run = AutomationRun(rule_id=rule.id, event_ref=ref, dry_run=False, matched=False, status="rate_limited", outcome=[])
            db.add(run)
            return run
    ok = matches(alert, rule.conditions)
    outcome: list[dict[str, Any]] = []
    status = "done"
    if ok:
        for act in rule.actions:
            if dry_run:
                outcome.append({"action": act["type"], "dry_run": True, "params": {k: v for k, v in act.items() if k != "type"}})
                continue
            try:
                outcome.append({"action": act["type"], **_apply(db, rule, alert, act)})
            except Exception as e:  # noqa: BLE001 - record and trip the breaker
                outcome.append({"action": act["type"], "error": str(e)[:200]})
                status = "failed"
                break
        if not dry_run:
            if status == "failed":
                rule.consecutive_failures += 1
                if rule.consecutive_failures >= MAX_CONSECUTIVE_FAILURES:
                    rule.enabled = False
            else:
                rule.consecutive_failures = 0
    run = AutomationRun(rule_id=rule.id, event_ref=ref, dry_run=dry_run, matched=ok, outcome=outcome, status=status)
    db.add(run)
    db.flush()
    return run


def _apply(db: Session, rule: AutomationRule, alert: Alert, act: dict[str, Any]) -> dict[str, Any]:
    from . import cases, response
    from .settings_svc import system_user

    t = act["type"]
    if t == "set_status":
        if act.get("status") not in ("acknowledged", "investigating", "false_positive", "resolved"):
            raise ValueError("invalid status")
        alert.status = act["status"]
        if act["status"] == "acknowledged" and alert.acknowledged_at is None:
            alert.acknowledged_at = utcnow()
        return {"status": alert.status}
    if t == "add_note":
        alert.tuning_note = (alert.tuning_note + "\n" if alert.tuning_note else "") + f"[automation:{rule.name}] {str(act.get('text', ''))[:500]}"
        return {"noted": True}
    if t == "create_case":
        c = cases.create_case_from_alerts(db, [alert], actor="automation", template=act.get("template"), title=act.get("title"))
        return {"case_id": c.id, "number": c.number}
    if t == "enrich":
        from .intel import queue_enrichment

        ind = alert.src_ip or alert.file_hash
        if not ind:
            return {"skipped": "no indicator"}
        j = queue_enrichment(db, ind, "ip" if alert.src_ip else "hash", system_user(db).id, alert_id=alert.id, client_id=alert.client_id)
        return {"job_id": j.id}
    if t == "request_action":
        target_field = act.get("target_field", "src_ip")
        target = getattr(alert, target_field, "") if target_field in ("src_ip", "host", "username") else ""
        if not target:
            return {"skipped": "no target"}
        req = response.create_request(
            db, requester=system_user(db), action_key=act["action_key"], targets=[target], params=act.get("params", {}), reason=f"Automation rule '{rule.name}'",
            alert_id=alert.id, client_id=alert.client_id, automation_rule_id=rule.id, scope=None, idempotency_key=f"auto:{rule.id}:{alert.id}",
        )
        return {"request_id": req.id, "status": req.status}
    raise ValueError(t)
