from __future__ import annotations

from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models import Alert, Case, CaseEvent, CaseObservable, CaseTask, CaseTemplate, utcnow
from ..policy import SEVERITIES, sev_rank
from ..sla import active_policy, due_dates
from . import events

CASE_STATUSES = ["open", "in_progress", "resolved", "closed"]
TRANSITIONS = {"open": {"in_progress", "resolved"}, "in_progress": {"open", "resolved"}, "resolved": {"in_progress", "closed"}, "closed": set()}


def next_number(db: Session) -> int:
    return int(db.execute(select(func.coalesce(func.max(Case.number), 0))).scalar_one()) + 1


def add_event(db: Session, case: Case, actor: str, kind: str, message: str, meta: dict[str, Any] | None = None) -> None:
    case.timeline.append(CaseEvent(actor=actor, kind=kind, message=message[:5000], meta=meta or {}))


def apply_template(db: Session, case: Case, name: str) -> None:
    t = db.execute(select(CaseTemplate).where(CaseTemplate.name == name)).scalar_one_or_none()
    if t is None:
        raise ValueError(f"unknown template {name}")
    case.template = t.name
    for i, task in enumerate(t.tasks or []):
        case.tasks.append(CaseTask(title=str(task.get("title", ""))[:300], description=str(task.get("description", "")), required=bool(task.get("required", True)), position=i))


def create_case_from_alerts(db: Session, alerts: list[Alert], *, actor: str, template: str | None = None, title: str | None = None, owner_id: str | None = None) -> Case:
    if not alerts:
        raise ValueError("no alerts")
    client_ids = {a.client_id for a in alerts}
    if len(client_ids) > 1:
        raise ValueError("alerts belong to different clients")
    sev = max((a.severity for a in alerts), key=sev_rank)
    now = utcnow()
    c = Case(number=next_number(db), title=(title or alerts[0].title)[:300], description="\n".join(a.title for a in alerts[:20]), severity=sev, client_id=alerts[0].client_id, owner_id=owner_id)
    c.ack_due, c.resolve_due = due_dates(active_policy(db), sev, now)
    db.add(c)
    db.flush()
    for a in alerts:
        a.case_id = c.id
        if a.status == "new":
            a.status = "investigating"
        for typ, val in (("ip", a.src_ip), ("host", a.host), ("user", a.username), ("hash", a.file_hash)):
            if val and not any(o.type == typ and o.value == val for o in c.observables):
                c.observables.append(CaseObservable(type=typ, value=val))
    if template:
        apply_template(db, c, template)
    add_event(db, c, actor, "created", f"Case created from {len(alerts)} alert(s)")
    db.flush()
    events.publish(db, "case.created", id=c.id, severity=c.severity, client_id=c.client_id)
    events.enqueue(db, "case.sync", {"case_id": c.id})
    return c


def change_status(db: Session, case: Case, new: str, actor: str, resolution: str = "") -> None:
    if new not in CASE_STATUSES:
        raise ValueError("invalid status")
    if new == case.status:
        return
    if new not in TRANSITIONS[case.status]:
        raise ValueError(f"cannot move from {case.status} to {new}")
    if new == "resolved":
        open_req = [t for t in case.tasks if t.required and t.status != "done"]
        if open_req:
            raise ValueError(f"{len(open_req)} required task(s) are not done")
        if not resolution:
            raise ValueError("a resolution is required")
        case.resolution = resolution
    if new == "closed":
        case.closed_at = utcnow()
    add_event(db, case, actor, "status", f"{case.status} -> {new}")
    case.status = new
    case.version += 1
    events.publish(db, "case.updated", id=case.id, client_id=case.client_id, severity=case.severity)
    if new == "resolved" and resolution in ("true_positive", "false_positive"):
        from . import enrichment_engine
        enrichment_engine.learn_from_case(db, case.id, resolution, case.owner_id or "")


def valid_severity(s: str) -> str:
    if s not in SEVERITIES:
        raise ValueError("invalid severity")
    return s


@events.handler("case.sync")
def sync_case(db: Session, payload: dict[str, Any]) -> None:
    """Project the case to TheHive (system of record). No enabled TheHive => stays 'pending' (no retry storm)."""
    from ..connectors.base import ConnectorError
    from ..models import Tool
    from . import tools_svc

    c = db.get(Case, payload["case_id"])
    if c is None:
        return
    tool = db.execute(select(Tool).where(Tool.type == "thehive", Tool.enabled.is_(True))).scalars().first()
    if tool is None:
        c.sync_status = "pending"
        return
    if c.external_id:
        c.sync_status = "synced"
        return
    try:
        conn = tools_svc.build_connector(db, tool)
        try:
            c.external_id = conn.create_case({"title": c.title, "description": c.description, "severity": c.severity})
        finally:
            conn.close()
    except ConnectorError as e:
        c.sync_status, c.sync_error = "failed", str(e)[:500]
        db.commit()
        raise
    c.sync_status, c.sync_error = "synced", ""
