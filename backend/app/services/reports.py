from __future__ import annotations

import csv
import hashlib
import html
import io
import json
from datetime import timedelta
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..models import Alert, Case, ControlResult, Finding, ReportJob, ReportSchedule, User, utcnow
from . import events
from .metrics import soc_metrics

KINDS = {"soc_metrics", "compliance", "vulnerabilities", "client", "case"}
FORMATS = {"html", "csv", "json", "pdf"}


def _principal_for(db: Session, user: User, client_id: str | None):  # noqa: ANN202
    from ..deps import Principal, visible_clients

    return Principal(user, None, None, visible_clients(db, user), "", "")


def build_data(db: Session, job: ReportJob, user: User) -> dict[str, Any]:
    p = _principal_for(db, user, job.client_id)
    days = int(job.params.get("days", 7))
    since = utcnow() - timedelta(days=days)
    cid = job.client_id
    if job.kind in ("soc_metrics", "client"):
        return {"title": "SOC metrics" if job.kind == "soc_metrics" else "Client security report", "metrics": soc_metrics(db, p, since, cid)}
    if job.kind == "vulnerabilities":
        fq = select(Finding).where(p.scope(Finding.client_id), Finding.status == "open")
        if cid:
            fq = fq.where(Finding.client_id == cid)
        rows = [{"vuln_id": f.vuln_id, "title": f.title, "severity": f.severity, "cvss": f.cvss, "component": f.component, "asset_id": f.asset_id} for f in db.execute(fq).scalars()]
        return {"title": "Open vulnerabilities", "rows": rows}
    if job.kind == "compliance":
        cq = select(ControlResult).where(p.scope(ControlResult.client_id))
        if job.params.get("framework"):
            cq = cq.where(ControlResult.framework == job.params["framework"])
        rows = [{"framework": r.framework, "control": r.control_id, "title": r.title, "status": r.status, "checked_at": r.checked_at.isoformat()} for r in db.execute(cq).scalars()]
        passed = sum(1 for r in rows if r["status"] == "pass")
        return {"title": "Compliance posture", "rows": rows, "score_pct": round(100 * passed / len(rows), 1) if rows else None}
    if job.kind == "case":
        c = db.get(Case, job.params.get("case_id", ""))
        if c is None or not p.can_see_client(c.client_id):
            raise ValueError("case not found")
        al = [{"time": a.time.isoformat(), "severity": a.severity, "title": a.title} for a in db.execute(select(Alert).where(Alert.case_id == c.id)).scalars()]
        return {"title": f"Case #{c.number}: {c.title}", "case": {"status": c.status, "severity": c.severity, "resolution": c.resolution}, "rows": al}
    raise ValueError("unknown report kind")


def render(data: dict[str, Any], fmt: str) -> bytes:
    if fmt == "json":
        return json.dumps(data, indent=2, default=str).encode()
    if fmt == "csv":
        rows = data.get("rows")
        buf = io.StringIO()
        w = csv.writer(buf)
        if rows:
            w.writerow(rows[0].keys())
            for r in rows:
                w.writerow([_csv_safe(v) for v in r.values()])
        else:
            for k, v in _flatten(data.get("metrics", {})):
                w.writerow([k, _csv_safe(v)])
        return buf.getvalue().encode()
    body = [f"<h1>{html.escape(str(data.get('title', 'Report')))}</h1>", f"<p>Generated {utcnow().isoformat()}</p>"]
    if "metrics" in data:
        body.append("<table border=1 cellpadding=4>" + "".join(f"<tr><td>{html.escape(k)}</td><td>{html.escape(str(v))}</td></tr>" for k, v in _flatten(data["metrics"])) + "</table>")
    if data.get("rows"):
        keys = list(data["rows"][0].keys())
        body.append("<table border=1 cellpadding=4><tr>" + "".join(f"<th>{html.escape(k)}</th>" for k in keys) + "</tr>" + "".join("<tr>" + "".join(f"<td>{html.escape(str(r[k]))}</td>" for k in keys) + "</tr>" for r in data["rows"]) + "</table>")
    doc = "<!doctype html><meta charset=utf-8><body style='font-family:sans-serif'>" + "".join(body)
    if fmt == "pdf":
        try:
            from weasyprint import HTML  # type: ignore[import-not-found]

            return bytes(HTML(string=doc).write_pdf())
        except ImportError as e:
            raise ValueError("PDF rendering requires WeasyPrint on the worker") from e
    return doc.encode()


def _csv_safe(v: Any) -> Any:
    """Neutralise spreadsheet formula injection."""
    if isinstance(v, str) and v[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + v
    return v


def _flatten(d: dict[str, Any], prefix: str = "") -> list[tuple[str, Any]]:
    out: list[tuple[str, Any]] = []
    for k, v in d.items():
        if isinstance(v, dict):
            out += _flatten(v, f"{prefix}{k}.")
        else:
            out.append((f"{prefix}{k}", v))
    return out


def run_job(db: Session, job: ReportJob) -> None:
    user = db.get(User, job.requester_id)
    if user is None:
        job.status, job.error = "failed", "requester missing"
        return
    job.status = "running"
    try:
        data = build_data(db, job, user)
        blob = render(data, job.fmt)
    except (ValueError, KeyError) as e:
        job.status, job.error, job.finished_at = "failed", str(e)[:400], utcnow()
        return
    d = Path(get_settings().report_dir)
    d.mkdir(parents=True, exist_ok=True)
    path = d / f"{job.id}.{job.fmt}"
    path.write_bytes(blob)
    job.artifact_path, job.checksum = str(path.name), hashlib.sha256(blob).hexdigest()
    job.status, job.finished_at = "done", utcnow()
    job.expires_at = utcnow() + timedelta(days=30)


@events.handler("report.run")
def _run(db: Session, payload: dict[str, Any]) -> None:
    job = db.get(ReportJob, payload["job_id"])
    if job is not None and job.status in ("queued", "running"):
        run_job(db, job)


def next_run(s: ReportSchedule, after=None):  # noqa: ANN001, ANN201
    tz = ZoneInfo(s.timezone)
    now = (after or utcnow()).astimezone(tz)
    cand = now.replace(hour=s.hour, minute=0, second=0, microsecond=0)
    step = {"daily": timedelta(days=1), "weekly": timedelta(days=7), "monthly": timedelta(days=30), "quarterly": timedelta(days=91)}[s.cadence]
    while cand <= now:
        cand += step
    return cand.astimezone(ZoneInfo("UTC"))


def run_due_schedules(db: Session) -> int:
    n = 0
    for s in db.execute(select(ReportSchedule).where(ReportSchedule.paused.is_(False), ReportSchedule.next_run_at <= utcnow())).scalars():
        occ = s.next_run_at.isoformat() if s.next_run_at else ""
        exists = db.execute(select(ReportJob.id).where(ReportJob.schedule_id == s.id, ReportJob.occurrence == occ)).first()
        if not exists:
            job = ReportJob(kind=s.kind, fmt=s.fmt, requester_id=s.owner_id, client_id=s.client_id, schedule_id=s.id, occurrence=occ, params={})
            db.add(job)
            db.flush()
            events.enqueue(db, "report.run", {"job_id": job.id})
            n += 1
        s.last_run_at, s.last_status = utcnow(), "queued"
        s.next_run_at = next_run(s)
    return n
