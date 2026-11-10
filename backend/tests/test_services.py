from __future__ import annotations

import csv
import io
from datetime import timedelta

import fakeredis
import httpx

from app import audit
from app import db as dbmod
from app.db import session_factory
from app.models import Alert, AuditEvent, AutomationRule, Case, NotificationDelivery, Outbox, ReportJob, utcnow
from app.services import events, notifications, reports
from tests.helpers import jresp, mk_alert, mk_tool, mock_http


def _drain(n=5):
    total = 0
    for _ in range(n):
        total += events.dispatch_once(session_factory())
    return total


# ---------------------------------------------------------------- audit
def test_audit_chain_detects_tampering():
    with dbmod.session_scope() as db:
        for i in range(5):
            audit.record(db, "test.event", actor="a", meta={"i": i, "password": "hunter2", "nested": {"api_token": "abc"}})
    with dbmod.session_scope() as db:
        assert audit.verify_chain(db) == {"ok": True, "checked": 5, "head": db.query(AuditEvent).order_by(AuditEvent.id.desc()).first().hash}
        e = db.query(AuditEvent).first()
        assert e.meta["password"] == "[redacted]" and e.meta["nested"]["api_token"] == "[redacted]"
    with dbmod.session_scope() as db:
        db.query(AuditEvent).filter_by(id=3).one().action = "test.forged"
    with dbmod.session_scope() as db:
        r = audit.verify_chain(db)
        assert r["ok"] is False and r["broken_at"] == 3
    with dbmod.session_scope() as db:
        db.query(AuditEvent).filter_by(id=3).one().action = "test.event"
        db.delete(db.query(AuditEvent).filter_by(id=2).one())  # deletion also breaks the chain
    with dbmod.session_scope() as db:
        assert audit.verify_chain(db)["ok"] is False


def test_audit_hmac_key_changes_hashes(monkeypatch):
    with dbmod.session_scope() as db:
        h1 = audit.record(db, "a", actor="x").hash
    monkeypatch.setenv("SOC_AUDIT_HMAC_KEY", "k" * 32)
    from app.config import reset_settings_cache

    reset_settings_cache()
    with dbmod.session_scope() as db:
        e = db.query(AuditEvent).one()
        assert audit._digest(e.prev_hash, e) != h1


def test_security_relevant_actions_are_audited(superadmin, make_session):
    admin = superadmin
    admin.post("/api/admin/users", {"email": "n@t.local", "role": "viewer", "password": "Str0ng-Passw0rd!x"})
    from app.ratelimit import limiter

    limiter.reset()
    from fastapi.testclient import TestClient

    TestClient(admin.c.app, client=("10.0.0.5", 1)).post("/api/auth/login", json={"email": "admin@t.local", "password": "bad-password-12AB", "totp": "123456"})
    with dbmod.session_scope() as db:
        actions = [(e.action, e.outcome) for e in db.query(AuditEvent)]
    assert ("auth.login", "success") in actions and ("auth.login", "failure") in actions and ("user.create", "success") in actions
    r = admin.get("/api/admin/audit/verify").json()
    assert r["ok"]
    assert admin.get("/api/admin/audit", params={"action": "user."}).json()["total"] == 1
    assert make_session("l2@t.local", "l2").get("/api/admin/audit").status_code == 403
    assert "csv" in admin.get("/api/admin/audit/export").headers["content-type"]


# ---------------------------------------------------------------- outbox + redis streams
def test_outbox_retry_backoff_and_dead_letter():
    calls = {"n": 0}

    @events.handler("test.fail")
    def boom(db, payload):
        calls["n"] += 1
        raise RuntimeError("nope")

    with dbmod.session_scope() as db:
        events.enqueue(db, "test.fail", {})
    assert _drain(1) == 0 and calls["n"] == 1
    with dbmod.session_scope() as db:
        row = db.query(Outbox).one()
        assert row.attempts == 1 and row.status == "pending" and row.run_after > utcnow()
        row.attempts, row.run_after = events.MAX_ATTEMPTS - 1, utcnow() - timedelta(seconds=1)
    _drain(1)
    with dbmod.session_scope() as db:
        assert db.query(Outbox).one().status == "dead"
    events.HANDLERS.pop("test.fail")


def test_events_published_to_redis_stream_with_consumer_groups():
    r = fakeredis.FakeRedis(decode_responses=True)
    events.set_redis(r)
    mk_alert(None, "Stream me")
    _drain()
    msgs = events.read_stream("g1", "c1")
    assert [m[1]["type"] for m in msgs] == ["alert.created"]
    assert "title" not in msgs[0][1]  # identifiers only; no alert content on the bus
    assert events.read_stream("g1", "c1") == []  # acked, not redelivered to same group
    assert len(events.read_stream("g2", "c1")) == 1  # another group gets its own copy


def test_sse_hub_filters_by_client_scope():
    own = events.hub.subscribe(lambda ev: ev.get("client_id") == "A")
    allv = events.hub.subscribe(lambda ev: True)
    events.hub.broadcast({"type": "alert.created", "client_id": "A"})
    events.hub.broadcast({"type": "alert.created", "client_id": "B"})
    assert own.qsize() == 1 and allv.qsize() == 2
    events.hub.unsubscribe(own)
    events.hub.unsubscribe(allv)


# ---------------------------------------------------------------- notifications
def _slack_setup(min_sev="high", **rule_kw):
    from app.models import NotificationDestination, NotificationRule

    tid = mk_tool("slack", "slack", {}, {"webhook_url": "https://hooks.slack.com/services/T/B/X"})
    with dbmod.session_scope() as db:
        d = NotificationDestination(name="soc-channel", channel="slack", tool_id=tid)
        db.add(d)
        db.flush()
        r = NotificationRule(name="crit", event_types=["alert.created", "server.down"], min_severity=min_sev, destinations=[d.id], **rule_kw)
        db.add(r)
        db.flush()
        return d.id, r.id


def test_notification_routing_dedupe_and_delivery():
    sent = []
    mock_http(lambda r: (sent.append(r.content), httpx.Response(200))[1])
    _slack_setup()
    mk_alert(None, "Low thing", severity="low", host="a", rule_id="1")
    mk_alert(None, "Critical thing", severity="critical", host="b", rule_id="2")
    _drain()
    assert len(sent) == 1 and b"Critical thing" in sent[0]
    with dbmod.session_scope() as db:
        assert db.query(NotificationDelivery).one().status == "sent"
        a = db.query(Alert).filter_by(severity="critical").one()
        notifications.on_event(db, {"type": "alert.created", "id": a.id})  # replayed event
        assert db.query(NotificationDelivery).count() == 1  # deduped


def test_notification_failure_retries_then_succeeds():
    state = {"n": 0}

    def handler(r):
        state["n"] += 1
        return httpx.Response(500) if state["n"] == 1 else httpx.Response(200)

    mock_http(handler)
    _slack_setup()
    mk_alert(None, "Critical", severity="critical")
    _drain(2)  # pass 1 fans the event out, pass 2 attempts delivery
    with dbmod.session_scope() as db:
        d = db.query(NotificationDelivery).one()
        assert d.status == "failed" and d.attempts == 1
        db.query(Outbox).filter(Outbox.kind == "notify.deliver").one().run_after = utcnow() - timedelta(seconds=1)
    _drain(1)
    with dbmod.session_scope() as db:
        assert db.query(NotificationDelivery).one().status == "sent"


def test_escalation_when_unacknowledged():
    mock_http(lambda r: httpx.Response(200))
    d1, rid = _slack_setup(escalate_after_minutes=10)
    with dbmod.session_scope() as db:
        from app.models import NotificationRule

        db.get(NotificationRule, rid).escalation_destinations = [d1]
    aid = mk_alert(None, "Critical", severity="critical")
    _drain()
    with dbmod.session_scope() as db:
        assert notifications.escalate_pending(db) == 0  # too early
        db.query(NotificationDelivery).one().sent_at = utcnow() - timedelta(minutes=11)
    with dbmod.session_scope() as db:
        assert notifications.escalate_pending(db) == 1
    with dbmod.session_scope() as db:
        assert notifications.escalate_pending(db) == 0  # only once (deduped)
        db.get(Alert, aid).acknowledged_at = utcnow()


def test_summary_notifications_do_not_leak_details():
    sent = []
    mock_http(lambda r: (sent.append(r.content.decode()), httpx.Response(200))[1])
    _slack_setup()
    mk_alert(None, "Critical", severity="critical", host="secret-host-name", description="internal details here")
    _drain()
    assert "secret-host-name" not in sent[0] and "internal details" not in sent[0]


# ---------------------------------------------------------------- automation
def test_automation_requires_dry_run_then_creates_case(admin, make_session):
    aid = mk_alert(None, "Ransomware behaviour", severity="critical")
    _drain()  # its creation event is processed before the rule exists
    rule = {"name": "crit-to-case", "conditions": [{"field": "severity", "op": "gte", "value": "critical"}], "actions": [{"type": "create_case", "template": "Malware / EDR detection"}, {"type": "add_note", "text": "auto"}]}
    r = admin.post("/api/automation/rules", rule)
    assert r.status_code == 201 and r.json()["enabled"] is False
    rid = r.json()["id"]
    assert admin.post(f"/api/automation/rules/{rid}/toggle", {"enabled": True}).status_code == 409
    d = admin.post(f"/api/automation/rules/{rid}/dry-run").json()
    assert d["matched"] == 1 and d["samples"][0]["would_do"][0]["dry_run"] is True
    with dbmod.session_scope() as db:
        assert db.query(Case).count() == 0  # dry run has no side effects
    assert admin.post(f"/api/automation/rules/{rid}/toggle", {"enabled": True}).status_code == 200
    mk_alert(None, "Another ransomware", severity="critical", host="h2", rule_id="9")
    mk_alert(None, "Harmless", severity="low", host="h3", rule_id="10")
    _drain()
    with dbmod.session_scope() as db:
        assert db.query(Case).count() == 1
        assert db.get(Alert, aid).case_id is None  # pre-existing alert untouched
    assert make_session("l1@t.local", "l1").get("/api/automation/rules").status_code == 403


def test_automation_validation_and_breaker(admin):
    assert admin.post("/api/automation/rules", {"name": "bad", "conditions": [{"field": "password", "op": "eq", "value": 1}], "actions": [{"type": "add_note"}]}).status_code == 400
    assert admin.post("/api/automation/rules", {"name": "bad2", "conditions": [], "actions": [{"type": "rm_rf"}]}).status_code == 400
    assert admin.post("/api/automation/rules", {"name": "bad3", "conditions": [{"field": "title", "op": "regex", "value": ".*"}], "actions": [{"type": "add_note"}]}).status_code == 400
    from app.services import automation

    with dbmod.session_scope() as db:
        rule = AutomationRule(name="x", conditions=[], actions=[{"type": "set_status", "status": "bogus"}], enabled=True)
        db.add(rule)
        db.flush()
    for i in range(automation.MAX_CONSECUTIVE_FAILURES):
        mk_alert(None, f"a{i}", host=f"h{i}", rule_id=str(i))
        _drain()
    with dbmod.session_scope() as db:
        assert db.query(AutomationRule).one().enabled is False  # breaker tripped


def test_automation_cannot_bypass_approval(admin, make_session):
    mk_tool("wazuh_manager", "wm", {"url": "https://wazuh.corp.local:55000", "username": "u"}, {"password": "p"})
    rule = {"name": "auto-block", "conditions": [{"field": "severity", "op": "gte", "value": "high"}], "actions": [{"type": "request_action", "action_key": "block_ip", "target_field": "src_ip"}]}
    rid = admin.post("/api/automation/rules", rule).json()["id"]
    mk_alert(None, "seed", severity="high", host="seed", rule_id="s")
    admin.post(f"/api/automation/rules/{rid}/dry-run")
    admin.post(f"/api/automation/rules/{rid}/toggle", {"enabled": True})
    mk_alert(None, "Attack", severity="critical", host="victim", rule_id="77", src_ip="198.51.100.20")
    _drain()
    reqs = admin.get("/api/response/requests").json()["items"]
    assert reqs and all(r["status"] == "pending_approval" for r in reqs)  # automation only *requests*


# ---------------------------------------------------------------- reports
def test_report_generation_csv_injection_and_download(admin, make_session, tmp_path, monkeypatch):
    monkeypatch.setenv("SOC_REPORT_DIR", str(tmp_path))
    from app.config import reset_settings_cache

    reset_settings_cache()
    from app.models import Asset, Finding

    with dbmod.session_scope() as db:
        a = Asset(name="ws-1")
        db.add(a)
        db.flush()
        db.add(Finding(asset_id=a.id, vuln_id="CVE-1", title='=HYPERLINK("http://evil","x")', severity="high"))
    r = admin.post("/api/reports", {"kind": "vulnerabilities", "fmt": "csv"})
    assert r.status_code == 202
    jid = r.json()["id"]
    _drain()
    assert admin.get("/api/reports").json()["items"][0]["status"] == "done"
    dl = admin.get(f"/api/reports/{jid}/download")
    assert dl.status_code == 200 and dl.headers["content-security-policy"] == "sandbox" and "attachment" in dl.headers["content-disposition"]
    rows = list(csv.reader(io.StringIO(dl.text)))
    assert rows[1][1].startswith("'=")  # formula neutralised
    l1 = make_session("l1@t.local", "l1")
    assert l1.get(f"/api/reports/{jid}/download").status_code == 200  # global (client-less) report readable by l1+
    assert l1.post("/api/reports", {"kind": "soc_metrics", "fmt": "html", "params": {"evil": 1}}).status_code == 400


def test_report_html_escapes_content(admin, tmp_path, monkeypatch):
    monkeypatch.setenv("SOC_REPORT_DIR", str(tmp_path))
    from app.config import reset_settings_cache

    reset_settings_cache()
    with dbmod.session_scope() as db:
        j = ReportJob(kind="soc_metrics", fmt="html", requester_id=db.query(__import__("app.models", fromlist=["User"]).User).first().id)
        db.add(j)
        db.flush()
    html = reports.render({"title": "<script>alert(1)</script>", "rows": [{"a": "<img src=x onerror=alert(1)>"}]}, "html").decode()
    assert "<script>" not in html and "<img" not in html


def test_report_scope_and_schedule_dedup(admin, make_session, clients, tmp_path, monkeypatch):
    a, b = clients
    scoped = make_session("l1a@t.local", "l1", all_clients=False, client_ids=[a])
    assert scoped.post("/api/reports", {"kind": "client", "client_id": b}).status_code == 404
    assert scoped.post("/api/reports", {"kind": "client"}).status_code == 400
    r = admin.post("/api/reports/schedules", {"name": "weekly", "kind": "soc_metrics", "cadence": "weekly", "hour": 8})
    assert r.status_code == 201
    assert admin.post("/api/reports/schedules", {"name": "bad", "kind": "soc_metrics", "cadence": "daily", "timezone": "Mars/Base"}).status_code == 400
    with dbmod.session_scope() as db:
        from app.models import ReportSchedule

        s = db.query(ReportSchedule).one()
        s.next_run_at = utcnow() - timedelta(minutes=1)
    with dbmod.session_scope() as db:
        assert reports.run_due_schedules(db) == 1
    with dbmod.session_scope() as db:
        s = db.query(ReportSchedule).one()
        s.next_run_at = utcnow() - timedelta(minutes=1)
        # same occurrence cannot run twice
        db.query(ReportJob).one().occurrence = s.next_run_at.isoformat()
    with dbmod.session_scope() as db:
        assert reports.run_due_schedules(db) == 0


def test_metrics_values(make_session):
    a1 = mk_alert(None, "x", severity="high", host="h1", rule_id="1")
    mk_alert(None, "y", severity="low", host="h2", rule_id="2")
    with dbmod.session_scope() as db:
        al = db.get(Alert, a1)
        al.acknowledged_at = al.first_seen + timedelta(minutes=10)
        al.resolved_at = al.first_seen + timedelta(minutes=50)
        al.status = "resolved"
    m = make_session("v@t.local", "viewer").get("/api/dashboard").json()["metrics"]
    assert m["alerts_total"] == 2 and m["alerts_by_severity"]["high"] == 1 and m["mtta_minutes"] == 10.0 and m["mttr_minutes"] == 50.0


def test_case_sync_to_thehive_and_failure_recovery(make_session):
    from app.db import session_factory

    l1 = make_session("l1@t.local", "l1")
    cid = l1.post("/api/cases", {"title": "needs sync", "severity": "high"}).json()["id"]
    _drain(2)
    assert l1.get(f"/api/cases/{cid}").json()["sync_status"] == "pending"  # no TheHive yet: not an error
    mk_tool("thehive", "hive", {"url": "https://hive.corp.local"}, {"api_key": "k"})
    state = {"n": 0}

    def handler(r):
        state["n"] += 1
        return httpx.Response(503) if state["n"] == 1 else jresp({"_id": "~42"})

    mock_http(handler)
    with dbmod.session_scope() as db:
        events.enqueue(db, "case.sync", {"case_id": cid})
    events.dispatch_once(session_factory())
    c = l1.get(f"/api/cases/{cid}").json()
    assert c["sync_status"] == "failed"
    with dbmod.session_scope() as db:
        for o in db.query(Outbox).filter(Outbox.kind == "case.sync", Outbox.status == "pending"):
            o.run_after = utcnow() - timedelta(seconds=1)
    events.dispatch_once(session_factory())
    c = l1.get(f"/api/cases/{cid}").json()
    assert c["sync_status"] == "synced" and c["external_id"] == "~42"


def test_hub_async_subscriber_receives_events_from_other_threads() -> None:
    import asyncio
    import threading

    from app.services import events

    async def run() -> dict:
        q = events.hub.subscribe(lambda ev: True, loop=asyncio.get_running_loop())
        try:
            threading.Thread(target=events.hub.broadcast, args=({"type": "alert.created", "id": "x"},)).start()
            return await asyncio.wait_for(q.get(), 3)
        finally:
            events.hub.unsubscribe(q)

    assert asyncio.run(run())["id"] == "x"
