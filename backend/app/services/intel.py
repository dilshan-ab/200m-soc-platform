from __future__ import annotations

import ipaddress
import re
from datetime import timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..connectors.base import ConnectorError
from ..models import EnrichmentJob, Tool, utcnow
from . import events, tools_svc

_HASH = re.compile(r"^[A-Fa-f0-9]{32}$|^[A-Fa-f0-9]{40}$|^[A-Fa-f0-9]{64}$")
_DOMAIN = re.compile(r"^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$", re.I)
VERDICT_ORDER = ["unknown", "benign", "suspicious", "malicious"]


def detect_type(value: str) -> str:
    v = value.strip()
    try:
        ipaddress.ip_address(v)
        return "ip"
    except ValueError:
        pass
    if _HASH.match(v):
        return "hash"
    if v.lower().startswith(("http://", "https://")):
        return "url"
    if _DOMAIN.match(v):
        return "domain"
    raise ValueError("unrecognised indicator")


def queue_enrichment(db: Session, indicator: str, itype: str, requester_id: str, *, alert_id: str | None = None, case_id: str | None = None, client_id: str | None = None, tlp: str = "AMBER") -> EnrichmentJob:
    indicator = indicator.strip()[:500]
    cached = db.execute(
        select(EnrichmentJob).where(EnrichmentJob.indicator == indicator, EnrichmentJob.status == "done", EnrichmentJob.created_at >= utcnow() - timedelta(hours=1), EnrichmentJob.client_id == client_id).limit(1)
    ).scalars().first()
    if cached is not None:
        return cached
    j = EnrichmentJob(indicator=indicator, indicator_type=itype, requester_id=requester_id, alert_id=alert_id, case_id=case_id, client_id=client_id, tlp=tlp, expires_at=utcnow() + timedelta(days=30))
    db.add(j)
    db.flush()
    events.enqueue(db, "intel.enrich", {"job_id": j.id})
    return j


@events.handler("intel.enrich")
def run_enrichment(db: Session, payload: dict[str, Any]) -> None:
    j = db.get(EnrichmentJob, payload["job_id"])
    if j is None or j.status == "done":
        return
    j.status = "running"
    results: dict[str, Any] = {}
    verdict = "unknown"
    tools = db.execute(select(Tool).where(Tool.enabled.is_(True), Tool.type.in_(["misp", "cortex"]))).scalars().all()
    errors = 0
    for t in tools:
        try:
            c = tools_svc.build_connector(db, t)
            try:
                r = c.enrich(j.indicator, j.indicator_type)
            finally:
                c.close()
            results[t.name] = r
            v = r.get("verdict", "unknown")
            if VERDICT_ORDER.index(v if v in VERDICT_ORDER else "unknown") > VERDICT_ORDER.index(verdict):
                verdict = v
        except ConnectorError as e:
            errors += 1
            results[t.name] = {"error": str(e)[:200]}
    j.results, j.verdict = results, verdict
    j.status = "failed" if tools and errors == len(tools) else "done"
