from __future__ import annotations

from datetime import timedelta

import httpx
import pytest
from sqlalchemy import select

from app import db as dbmod
from app.models import Alert, EnrichmentJob, Outbox, utcnow
from app.services import intel
from app.services.settings_svc import system_user
from tests.helpers import jresp, mk_alert, mk_tool, mock_http

PUBLIC_IP = "8.8.4.4"


@pytest.fixture(autouse=True)
def _clear_cooldowns():
    intel._cooldown.clear()
    yield
    intel._cooldown.clear()


def _abuse(status_by_call, calls):
    def handler(r: httpx.Request):
        calls.append(r.url.params.get("ipAddress"))
        status, headers = status_by_call(len(calls))
        if status == 429:
            return httpx.Response(429, headers=headers)
        return jresp({"data": {"abuseConfidenceScore": 90, "totalReports": 5, "isp": "x"}})
    return handler


def _queue(ip=PUBLIC_IP, alert_id=None):
    with dbmod.session_scope() as db:
        j = intel.queue_enrichment(db, ip, "ip", system_user(db).id, alert_id=alert_id)
        return j.id


def _run(job_id, attempt=0):
    with dbmod.session_scope() as db:
        intel.run_enrichment(db, {"job_id": job_id, "attempt": attempt})
        j = db.get(EnrichmentJob, job_id)
        retry = db.execute(select(Outbox).where(Outbox.kind == "intel.enrich").order_by(Outbox.id.desc())).scalars().first()
        return j.status, j.verdict, dict(j.results), (retry.payload, retry.run_after) if retry else None


def test_rate_limited_provider_is_skipped_and_job_retried_after_cooldown():
    mk_tool("abuseipdb", "AbuseIPDB", {"url": "https://abuse.corp.local/api/v2"}, {"api_key": "k"})
    calls: list = []
    mock_http(_abuse(lambda n: (429, {"Retry-After": "600"}) if n == 1 else (200, {}), calls))
    first = _queue()
    status, _, results, retry = _run(first)
    assert status == "queued" and "rate limited until" in results["AbuseIPDB"]["skipped"]
    payload, run_after = retry
    assert payload == {"job_id": first, "attempt": 1} and run_after > utcnow() + timedelta(minutes=9)
    # While cooling down, other lookups do not call the provider at all.
    second = _queue("8.8.8.9")
    status, _, results, _ = _run(second)
    assert status == "queued" and len(calls) == 1 and "skipped" in results["AbuseIPDB"]
    # After the cooldown the retry succeeds.
    intel._cooldown.clear()
    status, verdict, results, _ = _run(first, attempt=1)
    assert (status, verdict) == ("done", "malicious") and results["AbuseIPDB"]["abuse_score"] == 90


def test_job_fails_after_too_many_deferrals():
    mk_tool("abuseipdb", "AbuseIPDB", {"url": "https://abuse.corp.local/api/v2"}, {"api_key": "k"})
    mock_http(_abuse(lambda n: (429, {}), []))
    status, _, results, _ = _run(_queue(), attempt=intel.MAX_DEFERRALS)
    assert status == "failed" and "skipped" in results["AbuseIPDB"]


def test_cached_result_is_reused_and_stamped_on_the_new_alert():
    mk_tool("abuseipdb", "AbuseIPDB", {"url": "https://abuse.corp.local/api/v2"}, {"api_key": "k"})
    calls: list = []
    mock_http(_abuse(lambda n: (200, {}), calls))
    a1, a2 = mk_alert(src_ip=""), mk_alert(src_ip="", title="Other")
    first = _queue(alert_id=a1)
    _run(first)
    with dbmod.session_scope() as db:
        old = db.get(EnrichmentJob, first)
        old.created_at = utcnow() - timedelta(hours=20)  # older than the previous one-hour cache, inside the new day
    assert _queue(alert_id=a2) == first and len(calls) == 1
    with dbmod.session_scope() as db:
        assert db.get(Alert, a2).enrichment[PUBLIC_IP]["verdict"] == "malicious"


def test_auto_enrich_skips_blocklist_alerts_and_private_addresses():
    with dbmod.session_scope() as db:
        rep = Alert(source="wazuh_indexer", title="Suricata Alert - ET CINS", severity="low", src_ip=PUBLIC_IP, raw={"reputation": True}, dedup_key="r1")
        lan = Alert(source="wazuh_indexer", title="scan", severity="medium", src_ip=PUBLIC_IP, dst_ip="10.0.0.5", dedup_key="r2")
        db.add_all([rep, lan])
        db.flush()
        assert intel.auto_enrich_alert(db, rep.id) == []
        jobs = intel.auto_enrich_alert(db, lan.id)
        assert [db.get(EnrichmentJob, j).indicator for j in jobs] == [PUBLIC_IP]
