from __future__ import annotations

import ipaddress
import re
from datetime import timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..connectors.base import ConnectorError
from ..models import Alert, EnrichmentJob, Tool, utcnow
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
    from ..connectors.base import all_manifests

    enrichable_types = [m.type for m in all_manifests() if "enrich" in m.capabilities]
    tools = db.execute(select(Tool).where(Tool.enabled.is_(True), Tool.type.in_(enrichable_types))).scalars().all() if enrichable_types else []
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
    _write_back_enrichment(db, j)


def _write_back_enrichment(db: Session, j: EnrichmentJob) -> None:
    """Stamp enrichment results back onto the originating Alert or CaseObservable."""
    from ..models import Alert, CaseObservable

    summary = {"verdict": j.verdict, "sources": list(j.results.keys()), "results": j.results}
    if j.alert_id:
        alert = db.get(Alert, j.alert_id)
        if alert is not None:
            merged = {**(alert.enrichment or {}), j.indicator: summary}
            alert.enrichment = merged
    if j.case_id:
        obs = db.execute(
            select(CaseObservable).where(CaseObservable.case_id == j.case_id, CaseObservable.value == j.indicator)
        ).scalars().first()
        if obs is not None:
            obs.enrichment = summary
            obs.verdict = j.verdict


def auto_enrich_alert(db: Session, alert_id: str) -> list[str]:
    """Extract IOCs from an alert and queue enrichment for each. Returns job IDs."""
    alert = db.get(Alert, alert_id)
    if alert is None:
        return []
    indicators: list[tuple[str, str]] = []
    if alert.src_ip and alert.src_ip not in ("", "0.0.0.0", "127.0.0.1", "::1"):
        indicators.append((alert.src_ip, "ip"))
    if alert.dst_ip and alert.dst_ip not in ("", "0.0.0.0", "127.0.0.1", "::1"):
        indicators.append((alert.dst_ip, "ip"))
    if alert.file_hash:
        indicators.append((alert.file_hash, "hash"))
    job_ids: list[str] = []
    for value, itype in indicators:
        j = queue_enrichment(db, value, itype, "system", alert_id=alert_id, client_id=alert.client_id)
        job_ids.append(j.id)
    return job_ids
