from __future__ import annotations

from datetime import timedelta
from typing import Any
from zoneinfo import ZoneInfo

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..config import get_settings
from ..connectors.base import ConnectorError
from ..models import Alert, Case, NotificationDelivery, NotificationDestination, NotificationRule, Server, Tool, utcnow
from ..policy import sev_rank
from . import events, tools_svc

SUPPORTED_EVENTS = {"alert.created", "server.down", "case.created", "sla.breached", "approval.pending", "uptime.down", "uptime.recovered"}


def _in_quiet_hours(rule: NotificationRule) -> bool:
    q = rule.quiet_hours or {}
    if not q.get("start") or not q.get("end"):
        return False
    now = utcnow().astimezone(ZoneInfo(q.get("tz") or get_settings().default_timezone))
    cur = now.hour * 60 + now.minute
    sh, sm = map(int, q["start"].split(":"))
    eh, em = map(int, q["end"].split(":"))
    s, e = sh * 60 + sm, eh * 60 + em
    return (s <= cur < e) if s <= e else (cur >= s or cur < e)


def _describe(db: Session, ev: dict[str, Any]) -> tuple[str, str, str, str | None, str, str | None]:
    """returns (subject, body, severity, client_id, category, alert_id)"""
    t, base = ev["type"], get_settings().public_base_url.rstrip("/")
    if t in ("alert.created", "sla.breached"):
        a = db.get(Alert, ev["id"])
        if a is None:
            raise LookupError("alert gone")
        pre = "SLA BREACH: " if t == "sla.breached" else ""
        return (f"{pre}[{a.severity.upper()}] {a.title}", f"Host: {a.host or '-'}\nSource: {a.source}\n{base}/alerts/{a.id}", a.severity, a.client_id, a.category, a.id)
    if t == "server.down":
        s = db.get(Server, ev["id"])
        if s is None:
            raise LookupError("server gone")
        return (f"[CRITICAL] Server down: {s.name}", f"Host: {s.host}\n{base}/servers/{s.id}", "critical", s.client_id, "infrastructure", None)
    if t == "case.created":
        c = db.get(Case, ev["id"])
        if c is None:
            raise LookupError("case gone")
        return (f"[{c.severity.upper()}] New case #{c.number}: {c.title}", f"{base}/cases/{c.id}", c.severity, c.client_id, "security", None)
    if t == "approval.pending":
        return ("Approval pending", f"{base}/approvals", ev.get("severity") or "medium", ev.get("client_id"), "security", None)
    if t == "uptime.down":
        return (f"[DOWN] {ev.get('name', 'Site')} is down", f"URL: {ev.get('url', '-')}\nError: {ev.get('error', '-')}\n{base}/app/uptime", "critical", ev.get("client_id"), "infrastructure", None)
    if t == "uptime.recovered":
        return (f"[RECOVERED] {ev.get('name', 'Site')} is back up", f"URL: {ev.get('url', '-')}\n{base}/app/uptime", "info", ev.get("client_id"), "infrastructure", None)
    raise LookupError(t)


def on_event(db: Session, ev: dict[str, Any]) -> None:
    if ev.get("type") not in SUPPORTED_EVENTS:
        return
    try:
        subject, body, sev, client_id, category, alert_id = _describe(db, ev)
    except LookupError:
        return
    ref = f"{ev['type']}:{ev.get('id')}"
    for rule in db.execute(select(NotificationRule).where(NotificationRule.enabled.is_(True))).scalars():
        if ev["type"] not in (rule.event_types or []) or sev_rank(sev) < sev_rank(rule.min_severity):
            continue
        if rule.categories and category not in rule.categories:
            continue
        if rule.client_id and rule.client_id != client_id:
            continue
        if _in_quiet_hours(rule) and sev_rank(sev) < sev_rank((rule.quiet_hours or {}).get("allow_min_severity", "critical")):
            continue
        for dest_id in rule.destinations or []:
            _queue(db, rule, dest_id, ref, subject, body if rule.detail_level == "full" else body.split("\n")[-1], alert_id, 0)


def _queue(db: Session, rule: NotificationRule, dest_id: str, ref: str, subject: str, body: str, alert_id: str | None, level: int) -> bool:
    key = f"{rule.id}:{dest_id}:{ref}:{level}"
    try:
        with db.begin_nested():
            d = NotificationDelivery(rule_id=rule.id, destination_id=dest_id, event_ref=ref, dedupe_key=key, subject=subject[:300], body=body, alert_id=alert_id, escalation_level=level)
            db.add(d)
            db.flush()
    except IntegrityError:
        return False
    events.enqueue(db, "notify.deliver", {"delivery_id": d.id})
    return True


@events.handler("notify.deliver")
def deliver(db: Session, payload: dict[str, Any]) -> None:
    d = db.get(NotificationDelivery, payload["delivery_id"])
    if d is None or d.status == "sent":
        return
    dest = db.get(NotificationDestination, d.destination_id)
    if dest is None or not dest.enabled:
        d.status, d.error = "dead", "destination unavailable"
        return
    tool = db.get(Tool, dest.tool_id) if dest.tool_id else None
    d.attempts += 1
    if tool is None or not tool.enabled:
        d.status, d.error = "dead", "tool not enabled"
        return
    try:
        c = tools_svc.build_connector(db, tool)
        try:
            c.notify(d.subject, d.body, dest.address)
        finally:
            c.close()
    except ConnectorError as e:
        d.status, d.error = "failed", str(e)[:300]
        db.commit()  # persist attempt, then let the outbox retry
        raise
    d.status, d.sent_at, d.error = "sent", utcnow(), ""


def escalate_pending(db: Session) -> int:
    """Escalate rules whose alert is still unacknowledged after escalate_after_minutes."""
    n = 0
    for rule in db.execute(select(NotificationRule).where(NotificationRule.enabled.is_(True), NotificationRule.escalate_after_minutes > 0)).scalars():
        cutoff = utcnow() - timedelta(minutes=rule.escalate_after_minutes)
        rows = db.execute(select(NotificationDelivery).where(NotificationDelivery.rule_id == rule.id, NotificationDelivery.escalation_level == 0, NotificationDelivery.status == "sent", NotificationDelivery.sent_at <= cutoff, NotificationDelivery.alert_id.is_not(None))).scalars().all()
        for d in rows:
            a = db.get(Alert, d.alert_id) if d.alert_id else None
            if a is None or a.acknowledged_at is not None or a.status in ("resolved", "false_positive"):
                continue
            for dest_id in rule.escalation_destinations or []:
                if _queue(db, rule, dest_id, d.event_ref, f"ESCALATION: {d.subject}", d.body, d.alert_id, 1):
                    n += 1
    return n
