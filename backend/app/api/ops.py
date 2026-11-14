"""Reports, automation, notifications, runbooks and case templates."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import audit
from ..config import get_settings
from ..connectors.base import ConnectorError
from ..db import get_db
from ..deps import Principal, require, require_admin_step_up
from ..models import (
    Alert,
    AutomationRule,
    AutomationRun,
    CaseTemplate,
    Client,
    NotificationDelivery,
    NotificationDestination,
    NotificationRule,
    ReportJob,
    ReportSchedule,
    ReportTemplate,
    Runbook,
    Tool,
    utcnow,
)
from ..policy import SEVERITIES
from ..services import automation as auto
from ..services import events, reports, tools_svc
from ..services.notifications import SUPPORTED_EVENTS
from .common import iso, page_out, paginate

router = APIRouter(prefix="/api", tags=["operations"])


# ------------------------------------------------------------------------ reports
class ReportIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Literal["soc_metrics", "compliance", "vulnerabilities", "client", "case"]
    fmt: Literal["html", "csv", "json", "pdf"] = "html"
    client_id: str | None = None
    params: dict[str, Any] = Field(default_factory=dict)


def job_out(j: ReportJob) -> dict[str, Any]:
    return {"id": j.id, "kind": j.kind, "fmt": j.fmt, "status": j.status, "error": j.error, "created_at": iso(j.created_at), "finished_at": iso(j.finished_at), "client_id": j.client_id, "checksum": j.checksum}


@router.post("/reports", status_code=202)
def create_report(body: ReportIn, p: Principal = Depends(require("reports.generate")), db: Session = Depends(get_db)) -> dict[str, Any]:
    if body.client_id and not p.can_see_client(body.client_id):
        raise HTTPException(404, "not found")
    if p.client_ids is not None and not body.client_id:
        raise HTTPException(400, "client_id is required for scoped users")
    if any(k not in ("days", "framework", "case_id") for k in body.params):
        raise HTTPException(400, "unknown parameters")
    j = ReportJob(kind=body.kind, fmt=body.fmt, params=body.params, requester_id=p.user.id, client_id=body.client_id)
    db.add(j)
    db.flush()
    events.enqueue(db, "report.run", {"job_id": j.id})
    audit.record(db, "report.create", actor=p.label, actor_id=p.user.id, resource_type="report", resource_id=j.id, client_id=body.client_id, ip=p.ip, meta={"kind": body.kind})
    return job_out(j)


@router.get("/reports")
def list_reports(p: Principal = Depends(require("reports.read")), db: Session = Depends(get_db), page: int = 1, limit: int = 50) -> dict[str, Any]:
    q = select(ReportJob).where(p.scope(ReportJob.client_id) | (ReportJob.requester_id == p.user.id)).order_by(ReportJob.created_at.desc())
    rows, total = paginate(db, q, page, limit)
    return page_out([job_out(j) for j in rows], total, page, limit)


@router.get("/reports/{jid}/download")
def download(jid: str, p: Principal = Depends(require("reports.read")), db: Session = Depends(get_db)) -> FileResponse:
    j = db.get(ReportJob, jid)
    if j is None or j.status != "done" or not (p.can_see_client(j.client_id) or j.requester_id == p.user.id):
        raise HTTPException(404, "not found")
    path = (Path(get_settings().report_dir) / j.artifact_path).resolve()
    if not path.is_file() or Path(get_settings().report_dir).resolve() not in path.parents:
        raise HTTPException(404, "not found")
    mt = {"html": "text/html", "csv": "text/csv", "json": "application/json", "pdf": "application/pdf"}[j.fmt]
    audit.record(db, "report.download", actor=p.label, actor_id=p.user.id, resource_type="report", resource_id=j.id, client_id=j.client_id, ip=p.ip)
    return FileResponse(path, media_type=mt, filename=f"{j.kind}-{j.id[:8]}.{j.fmt}", headers={"Content-Security-Policy": "sandbox", "X-Report-SHA256": j.checksum})


class ScheduleIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=2, max_length=160)
    kind: Literal["soc_metrics", "compliance", "vulnerabilities", "client"]
    cadence: Literal["daily", "weekly", "monthly", "quarterly"]
    hour: int = Field(default=7, ge=0, le=23)
    fmt: Literal["html", "csv", "json", "pdf"] = "html"
    timezone: str = Field(default="Asia/Colombo", max_length=60)
    client_id: str | None = None
    recipients: list[str] = Field(default_factory=list, max_length=20)


@router.get("/reports/schedules")
def list_schedules(p: Principal = Depends(require("reports.read")), db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    return [{"id": s.id, "name": s.name, "kind": s.kind, "cadence": s.cadence, "hour": s.hour, "fmt": s.fmt, "timezone": s.timezone, "paused": s.paused, "next_run_at": iso(s.next_run_at), "last_run_at": iso(s.last_run_at), "client_id": s.client_id}
            for s in db.execute(select(ReportSchedule).where(p.scope(ReportSchedule.client_id) | ReportSchedule.client_id.is_(None))).scalars()]


@router.post("/reports/schedules", status_code=201)
def create_schedule(body: ScheduleIn, p: Principal = Depends(require("reports.schedule")), db: Session = Depends(get_db)) -> dict[str, Any]:
    from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

    try:
        ZoneInfo(body.timezone)
    except (ZoneInfoNotFoundError, ValueError) as e:
        raise HTTPException(400, "unknown timezone") from e
    if body.client_id and db.get(Client, body.client_id) is None:
        raise HTTPException(400, "unknown client")
    s = ReportSchedule(**body.model_dump(), owner_id=p.user.id)
    s.next_run_at = reports.next_run(s)
    db.add(s)
    db.flush()
    audit.record(db, "report.schedule", actor=p.label, actor_id=p.user.id, resource_type="report_schedule", resource_id=s.id, ip=p.ip)
    return {"id": s.id, "next_run_at": iso(s.next_run_at)}


@router.post("/reports/schedules/{sid}/pause")
def pause_schedule(sid: str, p: Principal = Depends(require("reports.schedule")), db: Session = Depends(get_db)) -> dict[str, bool]:
    s = db.get(ReportSchedule, sid)
    if s is None:
        raise HTTPException(404, "not found")
    s.paused = not s.paused
    if not s.paused:
        s.next_run_at = reports.next_run(s)
    return {"paused": s.paused}


@router.post("/reports/schedules/{sid}/run-now", status_code=202)
def run_schedule_now(sid: str, p: Principal = Depends(require("reports.schedule")), db: Session = Depends(get_db)) -> dict[str, Any]:
    s = db.get(ReportSchedule, sid)
    if s is None or not p.can_see_client(s.client_id):
        raise HTTPException(404, "not found")
    j = ReportJob(kind=s.kind, fmt=s.fmt, requester_id=p.user.id, client_id=s.client_id, schedule_id=s.id, params={})
    db.add(j)
    db.flush()
    events.enqueue(db, "report.run", {"job_id": j.id})
    audit.record(db, "report.schedule.run_now", actor=p.label, actor_id=p.user.id, resource_type="report_schedule", resource_id=s.id, ip=p.ip)
    return job_out(j)


@router.delete("/reports/schedules/{sid}", status_code=204)
def delete_schedule(sid: str, p: Principal = Depends(require("reports.schedule")), db: Session = Depends(get_db)) -> None:
    s = db.get(ReportSchedule, sid)
    if s is None or not p.can_see_client(s.client_id):
        raise HTTPException(404, "not found")
    audit.record(db, "report.schedule.delete", actor=p.label, actor_id=p.user.id, resource_type="report_schedule", resource_id=s.id, ip=p.ip, meta={"name": s.name})
    db.delete(s)


# ------------------------------------------------------------------------ report templates
class ReportTemplateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=2, max_length=160)
    description: str = Field(default="", max_length=2000)
    kind: Literal["soc_metrics", "compliance", "vulnerabilities", "client", "case"]
    fmt: Literal["html", "csv", "json", "pdf"] = "html"
    params: dict[str, Any] = Field(default_factory=dict)
    client_id: str | None = None


def template_out(t: ReportTemplate) -> dict[str, Any]:
    return {"id": t.id, "name": t.name, "description": t.description, "kind": t.kind, "fmt": t.fmt, "params": t.params, "client_id": t.client_id, "created_at": iso(t.created_at)}


@router.get("/report-templates")
def list_templates(p: Principal = Depends(require("reports.generate")), db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    return [template_out(t) for t in db.execute(select(ReportTemplate).where(p.scope(ReportTemplate.client_id) | ReportTemplate.client_id.is_(None)).order_by(ReportTemplate.name)).scalars()]


@router.post("/report-templates", status_code=201)
def create_template(body: ReportTemplateIn, p: Principal = Depends(require("reports.generate")), db: Session = Depends(get_db)) -> dict[str, Any]:
    if any(k not in ("days", "framework", "case_id") for k in body.params):
        raise HTTPException(400, "unknown parameters")
    if body.client_id and db.get(Client, body.client_id) is None:
        raise HTTPException(400, "unknown client")
    t = ReportTemplate(**body.model_dump(), created_by=p.user.id)
    db.add(t)
    db.flush()
    audit.record(db, "report_template.create", actor=p.label, actor_id=p.user.id, resource_type="report_template", resource_id=t.id, ip=p.ip)
    return template_out(t)


@router.delete("/report-templates/{tid}", status_code=204)
def delete_template(tid: str, p: Principal = Depends(require("reports.generate")), db: Session = Depends(get_db)) -> None:
    t = db.get(ReportTemplate, tid)
    if t is None or not p.can_see_client(t.client_id):
        raise HTTPException(404, "not found")
    if t.created_by != p.user.id and not p.can("reports.schedule"):
        raise HTTPException(403, "only the template's creator or a scheduling admin can delete it")
    audit.record(db, "report_template.delete", actor=p.label, actor_id=p.user.id, resource_type="report_template", resource_id=t.id, ip=p.ip, meta={"name": t.name})
    db.delete(t)


# ------------------------------------------------------------------------ automation
class RuleIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=3, max_length=160)
    description: str = Field(default="", max_length=2000)
    conditions: list[dict[str, Any]] = Field(default_factory=list, max_length=20)
    actions: list[dict[str, Any]] = Field(min_length=1, max_length=10)
    client_id: str | None = None
    max_per_hour: int = Field(default=30, ge=1, le=1000)


def rule_out(r: AutomationRule) -> dict[str, Any]:
    return {"id": r.id, "name": r.name, "description": r.description, "trigger": r.trigger, "conditions": r.conditions, "actions": r.actions, "enabled": r.enabled, "version": r.version,
            "max_per_hour": r.max_per_hour, "client_id": r.client_id, "consecutive_failures": r.consecutive_failures}


@router.get("/automation/rules")
def list_rules(p: Principal = Depends(require("automation.read")), db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    return [rule_out(r) for r in db.execute(select(AutomationRule).order_by(AutomationRule.name)).scalars()]


@router.post("/automation/rules", status_code=201)
def create_rule(body: RuleIn, p: Principal = Depends(require_admin_step_up("automation.write")), db: Session = Depends(get_db)) -> dict[str, Any]:
    try:
        auto.validate_rule(body.conditions, body.actions)
    except ValueError as e:
        raise HTTPException(400, str(e)) from e
    if db.execute(select(AutomationRule.id).where(AutomationRule.name == body.name)).first():
        raise HTTPException(409, "rule name exists")
    r = AutomationRule(**body.model_dump(), created_by=p.label)  # created disabled: dry-run first
    db.add(r)
    db.flush()
    audit.record(db, "automation.create", actor=p.label, actor_id=p.user.id, resource_type="automation_rule", resource_id=r.id, ip=p.ip)
    return rule_out(r)


@router.put("/automation/rules/{rid}")
def update_rule(rid: str, body: RuleIn, p: Principal = Depends(require_admin_step_up("automation.write")), db: Session = Depends(get_db)) -> dict[str, Any]:
    r = db.get(AutomationRule, rid)
    if r is None:
        raise HTTPException(404, "not found")
    try:
        auto.validate_rule(body.conditions, body.actions)
    except ValueError as e:
        raise HTTPException(400, str(e)) from e
    for k, v in body.model_dump().items():
        setattr(r, k, v)
    r.version += 1
    r.enabled = False  # edits require an explicit re-enable after dry run
    audit.record(db, "automation.update", actor=p.label, actor_id=p.user.id, resource_type="automation_rule", resource_id=r.id, ip=p.ip, meta={"version": r.version})
    return rule_out(r)


class ToggleIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool


@router.post("/automation/rules/{rid}/toggle")
def toggle_rule(rid: str, body: ToggleIn, p: Principal = Depends(require_admin_step_up("automation.write")), db: Session = Depends(get_db)) -> dict[str, Any]:
    r = db.get(AutomationRule, rid)
    if r is None:
        raise HTTPException(404, "not found")
    if body.enabled:
        dry = db.execute(select(func.count()).where(AutomationRun.rule_id == r.id, AutomationRun.dry_run.is_(True))).scalar_one()
        if not dry:
            raise HTTPException(409, "run a dry-run before enabling")
        r.consecutive_failures = 0
    r.enabled = body.enabled
    audit.record(db, "automation.toggle", actor=p.label, actor_id=p.user.id, resource_type="automation_rule", resource_id=r.id, ip=p.ip, meta={"enabled": body.enabled})
    return rule_out(r)


@router.post("/automation/rules/{rid}/dry-run")
def dry_run(rid: str, p: Principal = Depends(require("automation.read")), db: Session = Depends(get_db)) -> dict[str, Any]:
    r = db.get(AutomationRule, rid)
    if r is None:
        raise HTTPException(404, "not found")
    alerts = db.execute(select(Alert).where(p.scope(Alert.client_id)).order_by(Alert.time.desc()).limit(50)).scalars().all()
    matched = []
    for a in alerts:
        run = auto.run_rule(db, r, a, dry_run=True)
        if run.matched:
            matched.append({"alert_id": a.id, "title": a.title, "would_do": run.outcome})
    return {"evaluated": len(alerts), "matched": len(matched), "samples": matched[:10]}


@router.get("/automation/rules/{rid}/runs")
def runs(rid: str, p: Principal = Depends(require("automation.read")), db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    return [{"id": r.id, "event_ref": r.event_ref, "dry_run": r.dry_run, "matched": r.matched, "status": r.status, "outcome": r.outcome, "created_at": iso(r.created_at)}
            for r in db.execute(select(AutomationRun).where(AutomationRun.rule_id == rid).order_by(AutomationRun.created_at.desc()).limit(100)).scalars()]


# ------------------------------------------------------------------------ notifications
class DestIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=2, max_length=160)
    channel: Literal["slack", "telegram", "email", "clickup"]
    tool_id: str
    address: str = Field(default="", max_length=300)


@router.get("/notifications/destinations")
def list_dest(p: Principal = Depends(require("integrations.read")), db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    return [{"id": d.id, "name": d.name, "channel": d.channel, "tool_id": d.tool_id, "address": d.address, "enabled": d.enabled} for d in db.execute(select(NotificationDestination)).scalars()]


@router.post("/notifications/destinations", status_code=201)
def create_dest(body: DestIn, p: Principal = Depends(require_admin_step_up("notifications.write")), db: Session = Depends(get_db)) -> dict[str, str]:
    t = db.get(Tool, body.tool_id)
    if t is None or t.type != body.channel:
        raise HTTPException(400, "tool does not match channel")
    d = NotificationDestination(**body.model_dump())
    db.add(d)
    db.flush()
    audit.record(db, "notify.destination", actor=p.label, actor_id=p.user.id, resource_type="destination", resource_id=d.id, ip=p.ip)
    return {"id": d.id}


@router.post("/notifications/destinations/{did}/test")
def test_dest(did: str, p: Principal = Depends(require("notifications.write")), db: Session = Depends(get_db)) -> dict[str, Any]:
    d = db.get(NotificationDestination, did)
    t = db.get(Tool, d.tool_id) if d and d.tool_id else None
    if d is None or t is None:
        raise HTTPException(404, "not found")
    try:
        c = tools_svc.build_connector(db, t)
        try:
            c.notify("SOC platform test", "This is a test notification.", d.address)
        finally:
            c.close()
    except ConnectorError as e:
        return {"ok": False, "error": str(e)[:300]}
    return {"ok": True}


class NotifRuleIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=2, max_length=160)
    event_types: list[str] = Field(min_length=1, max_length=10)
    min_severity: Literal["info", "low", "medium", "high", "critical"] = "high"
    categories: list[Literal["security", "infrastructure"]] = Field(default_factory=list)
    client_id: str | None = None
    destinations: list[str] = Field(min_length=1, max_length=10)
    escalate_after_minutes: int = Field(default=0, ge=0, le=1440)
    escalation_destinations: list[str] = Field(default_factory=list, max_length=10)
    quiet_hours: dict[str, Any] = Field(default_factory=dict)
    detail_level: Literal["summary", "full"] = "summary"


def _check_rule(db: Session, body: NotifRuleIn) -> None:
    if any(e not in SUPPORTED_EVENTS for e in body.event_types):
        raise HTTPException(400, f"event types must be in {sorted(SUPPORTED_EVENTS)}")
    for did in [*body.destinations, *body.escalation_destinations]:
        if db.get(NotificationDestination, did) is None:
            raise HTTPException(400, "unknown destination")
    if body.escalate_after_minutes and not body.escalation_destinations:
        raise HTTPException(400, "escalation destinations required")


@router.get("/notifications/rules")
def list_nrules(p: Principal = Depends(require("integrations.read")), db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    return [{"id": r.id, "name": r.name, "event_types": r.event_types, "min_severity": r.min_severity, "categories": r.categories, "destinations": r.destinations, "enabled": r.enabled,
             "escalate_after_minutes": r.escalate_after_minutes, "detail_level": r.detail_level, "client_id": r.client_id, "quiet_hours": r.quiet_hours} for r in db.execute(select(NotificationRule)).scalars()]


@router.post("/notifications/rules", status_code=201)
def create_nrule(body: NotifRuleIn, p: Principal = Depends(require_admin_step_up("notifications.write")), db: Session = Depends(get_db)) -> dict[str, str]:
    _check_rule(db, body)
    r = NotificationRule(**body.model_dump())
    db.add(r)
    db.flush()
    audit.record(db, "notify.rule", actor=p.label, actor_id=p.user.id, resource_type="notification_rule", resource_id=r.id, ip=p.ip)
    return {"id": r.id}


@router.post("/notifications/rules/{rid}/toggle")
def toggle_nrule(rid: str, body: ToggleIn, p: Principal = Depends(require("notifications.write")), db: Session = Depends(get_db)) -> dict[str, bool]:
    r = db.get(NotificationRule, rid)
    if r is None:
        raise HTTPException(404, "not found")
    r.enabled = body.enabled
    return {"enabled": r.enabled}


@router.get("/notifications/deliveries")
def deliveries(p: Principal = Depends(require("integrations.read")), db: Session = Depends(get_db), status: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
    q = select(NotificationDelivery).order_by(NotificationDelivery.created_at.desc()).limit(max(1, min(limit, 500)))
    if status:
        q = q.where(NotificationDelivery.status == status)
    return [{"id": d.id, "subject": d.subject, "status": d.status, "attempts": d.attempts, "error": d.error, "escalation_level": d.escalation_level, "created_at": iso(d.created_at), "sent_at": iso(d.sent_at)} for d in db.execute(q).scalars()]


# ------------------------------------------------------------------------ runbooks & templates
class RunbookIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    slug: str = Field(min_length=2, max_length=80, pattern=r"^[a-z0-9\-]+$")
    title: str = Field(min_length=2, max_length=200)
    kind: Literal["guide", "template"] = "guide"
    body: str = Field(max_length=100000)


@router.get("/runbooks")
def list_runbooks(p: Principal = Depends(require("runbooks.read")), db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    latest = {}
    for r in db.execute(select(Runbook).where(Runbook.status != "archived").order_by(Runbook.version)).scalars():
        if r.status == "published" or r.slug not in latest:
            latest[r.slug] = r
    return [{"id": r.id, "slug": r.slug, "title": r.title, "kind": r.kind, "version": r.version, "status": r.status} for r in sorted(latest.values(), key=lambda x: x.title)]


@router.get("/runbooks/{slug}")
def get_runbook(slug: str, p: Principal = Depends(require("runbooks.read")), db: Session = Depends(get_db)) -> dict[str, Any]:
    r = db.execute(select(Runbook).where(Runbook.slug == slug).order_by(Runbook.version.desc())).scalars().first()
    pub = db.execute(select(Runbook).where(Runbook.slug == slug, Runbook.status == "published").order_by(Runbook.version.desc())).scalars().first()
    r = pub or r
    if r is None:
        raise HTTPException(404, "not found")
    return {"id": r.id, "slug": r.slug, "title": r.title, "kind": r.kind, "version": r.version, "status": r.status, "body": r.body}


@router.post("/runbooks", status_code=201)
def save_runbook(body: RunbookIn, p: Principal = Depends(require("runbooks.write")), db: Session = Depends(get_db)) -> dict[str, Any]:
    cur = db.execute(select(func.max(Runbook.version)).where(Runbook.slug == body.slug)).scalar_one()
    r = Runbook(slug=body.slug, title=body.title, kind=body.kind, body=body.body, version=(cur or 0) + 1, created_by=p.label)
    db.add(r)
    db.flush()
    audit.record(db, "runbook.save", actor=p.label, actor_id=p.user.id, resource_type="runbook", resource_id=r.id, ip=p.ip, meta={"slug": r.slug, "version": r.version})
    return {"id": r.id, "version": r.version, "status": r.status}


@router.post("/runbooks/{rid}/publish")
def publish_runbook(rid: str, p: Principal = Depends(require("runbooks.write")), db: Session = Depends(get_db)) -> dict[str, Any]:
    r = db.get(Runbook, rid)
    if r is None:
        raise HTTPException(404, "not found")
    if r.created_by == p.label and not p.can("admin.settings"):
        raise HTTPException(403, "a different reviewer must publish this runbook")
    for old in db.execute(select(Runbook).where(Runbook.slug == r.slug, Runbook.status == "published")).scalars():
        old.status = "archived"
    r.status = "published"
    audit.record(db, "runbook.publish", actor=p.label, actor_id=p.user.id, resource_type="runbook", resource_id=r.id, ip=p.ip)
    return {"id": r.id, "status": r.status}


class TemplateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=2, max_length=80)
    description: str = Field(default="", max_length=2000)
    severity: Literal["low", "medium", "high", "critical"] = "medium"
    tasks: list[dict[str, Any]] = Field(max_length=50)


@router.post("/case-templates", status_code=201)
def save_template(body: TemplateIn, p: Principal = Depends(require("runbooks.write")), db: Session = Depends(get_db)) -> dict[str, str]:
    if any("title" not in t for t in body.tasks):
        raise HTTPException(400, "every task needs a title")
    t = db.execute(select(CaseTemplate).where(CaseTemplate.name == body.name)).scalar_one_or_none()
    if t is None:
        t = CaseTemplate(name=body.name)
        db.add(t)
    t.description, t.severity, t.tasks = body.description, body.severity, [{"title": str(x["title"])[:300], "description": str(x.get("description", ""))[:2000], "required": bool(x.get("required", True))} for x in body.tasks]
    db.flush()
    audit.record(db, "template.save", actor=p.label, actor_id=p.user.id, resource_type="case_template", resource_id=t.id, ip=p.ip)
    return {"id": t.id}


_ = (SEVERITIES, utcnow)
