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
    # Background lookups use the quota-limited providers only for high/critical alerts.
    alert_id = alert_id or mk_alert(src_ip="", severity="high", title=f"for {ip}")
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


def _job(ip, severity, requester=None, itype="ip"):
    aid = mk_alert(src_ip="", severity=severity, title=f"{severity} {ip}")
    with dbmod.session_scope() as db:
        return intel.queue_enrichment(db, ip, itype, requester or system_user(db).id, alert_id=aid).id


def test_tiers_stop_at_first_malicious_and_save_limited_quota():
    mk_tool("misp", "MISP", {"url": "https://misp.corp.local"}, {"auth_key": "mk"})
    mk_tool("abuseipdb", "AbuseIPDB", {"url": "https://abuse.corp.local/api/v2"}, {"api_key": "k"})
    hits = {"misp": [], "abuse": []}
    misp_events = {"8.8.4.4": [{"event_id": "7"}], "8.8.8.8": []}

    def handler(r: httpx.Request):
        if r.url.host == "misp.corp.local":
            ip = r.read().decode()
            value = next(v for v in misp_events if v in ip)
            hits["misp"].append(value)
            return jresp({"response": {"Attribute": misp_events[value]}})
        hits["abuse"].append(r.url.params.get("ipAddress"))
        return jresp({"data": {"abuseConfidenceScore": 0, "totalReports": 0}})
    mock_http(handler)

    # MISP already says malicious: AbuseIPDB is not asked, even for a high alert.
    status, verdict, results, _ = _run(_job("8.8.4.4", "high"))
    assert (status, verdict) == ("done", "malicious") and "not needed: MISP" in results["AbuseIPDB"]["skipped"] and hits["abuse"] == []
    # Unknown to MISP on a medium alert: the limited quota is saved, and the job is still done, not failed.
    status, verdict, results, _ = _run(_job("8.8.8.8", "medium"))
    assert (status, verdict) == ("done", "unknown") and results["AbuseIPDB"]["skipped"] == intel.SAVED_FOR_PRIORITY and hits["abuse"] == []
    # The same address on a high alert does not reuse that partial result: AbuseIPDB is asked now.
    status, _, results, _ = _run(_job("8.8.8.8", "high"))
    assert hits["abuse"] == ["8.8.8.8"] and results["AbuseIPDB"]["verdict"] == "unknown" and status == "done"


def test_manual_lookup_uses_limited_providers_on_a_low_alert(admin):
    mk_tool("abuseipdb", "AbuseIPDB", {"url": "https://abuse.corp.local/api/v2"}, {"api_key": "k"})
    calls: list = []
    mock_http(_abuse(lambda n: (200, {}), calls))
    with dbmod.session_scope() as db:
        from app.models import User
        analyst = db.execute(select(User).where(User.id != system_user(db).id)).scalars().first()
        analyst_id = analyst.id
    status, verdict, _, _ = _run(_job(PUBLIC_IP, "low", requester=analyst_id))
    assert (status, verdict) == ("done", "malicious") and calls == [PUBLIC_IP]
