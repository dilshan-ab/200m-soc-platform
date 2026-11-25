from __future__ import annotations

import ipaddress
import re
import threading
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..connectors.base import ConnectorError, RateLimited
from ..models import Alert, EnrichmentJob, Tool, utcnow
from . import events, tools_svc
from .settings_svc import get_setting

_HASH = re.compile(r"^[A-Fa-f0-9]{32}$|^[A-Fa-f0-9]{40}$|^[A-Fa-f0-9]{64}$")
_DOMAIN = re.compile(r"^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$", re.I)
VERDICT_ORDER = ["unknown", "benign", "suspicious", "malicious"]
# Free threat-intel tiers are small (VirusTotal 4/min and 500/day, AbuseIPDB 1,000/day). A provider that answers 429 is
# left alone until it should have recovered, instead of being called (and failing) for every new alert.
RATE_LIMIT_BACKOFF = timedelta(minutes=15)
MAX_BACKOFF = timedelta(hours=6)
MAX_DEFERRALS = 4
_cooldown: dict[str, datetime] = {}
_cooldown_lock = threading.Lock()


def _cooling_until(tool_id: str) -> datetime | None:
    with _cooldown_lock:
        until = _cooldown.get(tool_id)
        if until is not None and until <= utcnow():
            _cooldown.pop(tool_id, None)
            return None
        return until


def _start_cooldown(tool_id: str, retry_after: int | None) -> datetime:
    wait = timedelta(seconds=retry_after) if retry_after else RATE_LIMIT_BACKOFF
    until = utcnow() + min(wait, MAX_BACKOFF)
    with _cooldown_lock:
        _cooldown[tool_id] = until
    return until


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
    # Address and file reputation changes slowly, and every lookup spends provider quota: reuse a good result for a day.
    cache_hours = int(get_setting(db, "enrichment_cache_hours", 24))
    cached = db.execute(
        select(EnrichmentJob).where(EnrichmentJob.indicator == indicator, EnrichmentJob.status == "done", EnrichmentJob.created_at >= utcnow() - timedelta(hours=cache_hours), EnrichmentJob.client_id == client_id)
        .order_by(EnrichmentJob.created_at.desc()).limit(1)
    ).scalars().first()
    if cached is not None:
        _write_back_enrichment(db, cached, alert_id=alert_id, case_id=case_id)
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

    from . import enrichment_engine

    local = enrichment_engine.enrich_local(db, j.indicator, j.indicator_type)
    if local["local_intel"].get("matched"):
        results["Local Intel"] = local["local_intel"]
        v = local["local_intel"].get("verdict", "unknown")
        if VERDICT_ORDER.index(v if v in VERDICT_ORDER else "unknown") > VERDICT_ORDER.index(verdict):
            verdict = v
    if local["rule_matches"]:
        results["Custom Rules"] = {
            "matches": local["rule_matches"],
            "verdict": max((h["verdict"] for h in local["rule_matches"]), key=lambda v: VERDICT_ORDER.index(v if v in VERDICT_ORDER else "unknown")),
            "tags": local["tags"],
        }
        v = results["Custom Rules"]["verdict"]
        if VERDICT_ORDER.index(v if v in VERDICT_ORDER else "unknown") > VERDICT_ORDER.index(verdict):
            verdict = v

    from ..connectors.base import all_manifests

    enrichable_types = [m.type for m in all_manifests() if "enrich" in m.capabilities]
    tools = db.execute(select(Tool).where(Tool.enabled.is_(True), Tool.type.in_(enrichable_types))).scalars().all() if enrichable_types else []
    errors = answered = 0
    limited: list[datetime] = []
    for t in tools:
        until = _cooling_until(t.id)
        if until is not None:
            limited.append(until)
            results[t.name] = {"skipped": f"rate limited until {until:%H:%M} UTC"}
            continue
        try:
            c = tools_svc.build_connector(db, t)
            try:
                r = c.enrich(j.indicator, j.indicator_type)
            finally:
                c.close()
            results[t.name] = r
            answered += 1
            v = r.get("verdict", "unknown")
            if VERDICT_ORDER.index(v if v in VERDICT_ORDER else "unknown") > VERDICT_ORDER.index(verdict):
                verdict = v
        except RateLimited as e:
            until = _start_cooldown(t.id, e.retry_after)
            limited.append(until)
            results[t.name] = {"skipped": f"rate limited until {until:%H:%M} UTC"}
        except ConnectorError as e:
            errors += 1
            results[t.name] = {"error": str(e)[:200]}

    # Nothing answered only because providers are rate limited: try again once the earliest one has recovered.
    attempt = int(payload.get("attempt", 0))
    local_hit = bool(local["local_intel"].get("matched") or local["rule_matches"])
    if limited and not answered and not local_hit and attempt < MAX_DEFERRALS:
        j.status = "queued"
        j.results = results
        delay = max(int((min(limited) - utcnow()).total_seconds()) + 5, 30)
        events.enqueue(db, "intel.enrich", {"job_id": j.id, "attempt": attempt + 1}, delay_seconds=delay)
        return

    reputation = enrichment_engine.compute_reputation(
        local.get("local_intel", {}),
        local.get("rule_matches", []),
        {k: v for k, v in results.items() if k not in ("Local Intel", "Custom Rules")},
    )
    results["_reputation"] = reputation

    j.results, j.verdict = results, verdict
    j.status = "failed" if tools and not answered and not local["local_intel"].get("matched") else "done"
    _write_back_enrichment(db, j)


def _write_back_enrichment(db: Session, j: EnrichmentJob, *, alert_id: str | None = None, case_id: str | None = None) -> None:
    """Stamp enrichment results back onto the originating Alert or CaseObservable (or, for a cached result, the new one)."""
    from ..models import Alert, CaseObservable

    summary = {"verdict": j.verdict, "sources": list(j.results.keys()), "results": j.results}
    alert_id = alert_id or j.alert_id
    case_id = case_id or j.case_id
    if alert_id:
        alert = db.get(Alert, alert_id)
        if alert is not None:
            merged = {**(alert.enrichment or {}), j.indicator: summary}
            alert.enrichment = merged
    if case_id:
        obs = db.execute(
            select(CaseObservable).where(CaseObservable.case_id == case_id, CaseObservable.value == j.indicator)
        ).scalars().first()
        if obs is not None:
            obs.enrichment = summary
            obs.verdict = j.verdict


def _public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value.strip()).is_global
    except ValueError:
        return False


def auto_enrich_alert(db: Session, alert_id: str) -> list[str]:
    """Extract IOCs from an alert and queue enrichment for each. Returns job IDs."""
    alert = db.get(Alert, alert_id)
    if alert is None:
        return []
    if (alert.raw or {}).get("reputation"):
        # Raised because the address is already on a block list: a provider lookup adds little and would spend most of the
        # daily quota on scanners. Analysts can still enrich these by hand.
        return []
    indicators: list[tuple[str, str]] = []
    for ip in (alert.src_ip, alert.dst_ip):
        if ip and _public_ip(ip) and (ip, "ip") not in indicators:
            indicators.append((ip, "ip"))
    if alert.file_hash:
        indicators.append((alert.file_hash, "hash"))
    from .settings_svc import system_user

    job_ids: list[str] = []
    for value, itype in indicators:
        j = queue_enrichment(db, value, itype, system_user(db).id, alert_id=alert_id, client_id=alert.client_id)
        job_ids.append(j.id)
    return job_ids
