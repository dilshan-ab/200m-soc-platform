from __future__ import annotations

import json
import time

import httpx
from fastapi.testclient import TestClient

from app import db as dbmod
from app.connectors.base import NormAlert
from app.models import Alert, AlertReceipt, Asset, Server, Tool
from app.security import hmac_sha256
from app.services import ingest, polling
from tests.helpers import jresp, mk_tool, mock_http, webhook_secret


def _wazuh_payload(i=1, level=10, host="ws-001"):
    return {"id": f"evt-{i}", "timestamp": "2026-11-06T10:00:00.000+0000", "rule": {"id": "5710", "level": level, "description": "sshd: brute force", "mitre": {"id": ["T1110"]}, "pci_dss": ["10.2.4"]},
            "agent": {"id": "001", "name": host}, "data": {"srcip": "203.0.113.50", "dstuser": "root"}}


def _hmac_headers(secret: str, body: bytes, ts: float | None = None):
    ts_s = str(ts if ts is not None else time.time())
    return {"X-SOC-Timestamp": ts_s, "X-SOC-Signature": hmac_sha256(secret, f"{ts_s}.".encode() + body), "Content-Type": "application/json"}


def test_webhook_bearer_ingest_and_dedup(app, clients):
    tid = mk_tool("wazuh_manager", "wm", {"url": "https://wazuh.corp.local:55000", "username": "u", "client_id": clients[0]}, {"password": "p"}, webhook_auth_mode="bearer")
    sec = webhook_secret(tid)
    c = TestClient(app, client=("10.0.0.7", 1))
    body = json.dumps(_wazuh_payload())
    h = {"Authorization": f"Bearer {sec}", "Content-Type": "application/json"}
    r = c.post(f"/api/webhooks/{tid}", content=body, headers=h)
    assert r.status_code == 202 and r.json()["created"] == 1
    r = c.post(f"/api/webhooks/{tid}", content=body, headers=h)  # same event again
    assert r.json()["created"] == 0
    with dbmod.session_scope() as db:
        assert db.query(Alert).count() == 1 and db.query(AlertReceipt).count() == 1
        a = db.query(Alert).one()
        assert a.severity == "medium" and a.mitre == ["T1110"] and a.client_id == clients[0] and a.ack_due is not None
    assert c.post(f"/api/webhooks/{tid}", content=body, headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert c.post(f"/api/webhooks/{tid}", content=body).status_code == 401


def test_webhook_hmac_replay_skew_size_and_source(app):
    tid = mk_tool("shuffle", "sh", {"url": "https://shuffle.corp.local", "exposed_workflows": []}, {"api_key": "k"}, webhook_auth_mode="hmac")
    sec = webhook_secret(tid)
    c = TestClient(app, client=("10.0.0.7", 1))
    body = json.dumps({"id": "x", "rule": {"id": "1", "level": 3, "description": "t"}, "agent": {"name": "h"}}).encode()
    h = _hmac_headers(sec, body)
    assert c.post(f"/api/webhooks/{tid}", content=body, headers=h).status_code == 202
    assert c.post(f"/api/webhooks/{tid}", content=body, headers=h).status_code == 409  # replay
    old = _hmac_headers(sec, body, ts=time.time() - 3600)
    assert c.post(f"/api/webhooks/{tid}", content=body, headers=old).status_code == 401
    bad = _hmac_headers("other-secret", body)
    assert c.post(f"/api/webhooks/{tid}", content=body, headers=bad).status_code == 401
    big = b"{" + b" " * (1_048_576 + 10) + b"}"
    assert c.post(f"/api/webhooks/{tid}", content=big, headers=_hmac_headers(sec, big)).status_code == 413
    ext = TestClient(app, client=("8.8.8.8", 1))
    assert ext.post(f"/api/webhooks/{tid}", content=body, headers=_hmac_headers(sec, body)).status_code == 404  # public source rejected
    assert c.post("/api/webhooks/unknown-id", content=body, headers=h).status_code == 404
    b2 = b"[1,2]"
    assert c.post(f"/api/webhooks/{tid}", content=b2, headers=_hmac_headers(sec, b2)).status_code == 400


def test_webhook_for_tool_without_webhook_support_is_404(app):
    tid = mk_tool("slack", "sl", {}, {"webhook_url": "https://hooks.slack.com/x"})
    assert TestClient(app, client=("10.0.0.7", 1)).post(f"/api/webhooks/{tid}", json={}).status_code == 404


def test_uptime_kuma_down_up_cycle(app):
    with dbmod.session_scope() as db:
        db.add(Server(name="PM-Tool", host="pm-tool", role="monitored"))
    tid = mk_tool("uptime_kuma", "uk", {"url": "https://kuma.corp.local"}, {"api_key": "k"}, webhook_auth_mode="bearer")
    h = {"Authorization": f"Bearer {webhook_secret(tid)}"}
    c = TestClient(app, client=("10.0.0.7", 1))
    down = {"msg": "down", "monitor": {"id": 3, "name": "PM-Tool", "hostname": "pm-tool"}, "heartbeat": {"status": 0, "time": "2026-11-06 10:00:00"}}
    up = {"msg": "up", "monitor": {"id": 3, "name": "PM-Tool", "hostname": "pm-tool"}, "heartbeat": {"status": 1, "time": "2026-11-06 10:05:00"}}
    assert c.post(f"/api/webhooks/{tid}", json=down, headers=h).json()["created"] == 1
    with dbmod.session_scope() as db:
        assert db.query(Server).one().status == "down"
        a = db.query(Alert).filter_by(rule_id="kuma.down").one()
        assert a.severity == "critical" and a.category == "infrastructure"
    c.post(f"/api/webhooks/{tid}", json=up, headers=h)
    with dbmod.session_scope() as db:
        assert db.query(Server).one().status == "up"
        assert db.query(Alert).filter_by(rule_id="kuma.down").one().status == "resolved"


def test_dedup_window_collapses_repeats_and_escalates_severity():
    n = lambda sev, sid: NormAlert(source_id=sid, title="Brute force", severity=sev, host="h", src_ip="1.2.3.4", rule_id="5710")  # noqa: E731
    with dbmod.session_scope() as db:
        t = Tool(type="wazuh_indexer", name="wi", config={})
        db.add(t)
        db.flush()
        a1, c1 = ingest.ingest_alert(db, t, n("low", "e1"))
        a2, c2 = ingest.ingest_alert(db, t, n("high", "e2"))
        a3, c3 = ingest.ingest_alert(db, t, n("low", "e3"))
        assert (c1, c2, c3) == (True, False, False)
        assert a1.id == a2.id == a3.id and a1.count == 3 and a1.severity == "high"


def test_severity_mapping_override():
    t = Tool(type="wazuh_indexer", name="x", config={}, severity_map={"12": "critical", "7": "low"})
    assert ingest.map_severity(t, "12") == "critical" and ingest.map_severity(t, "7") == "low"
    assert ingest.map_severity(None, "15") == "critical" and ingest.map_severity(None, "12") == "high" and ingest.map_severity(None, "3") == "info"
    assert ingest.map_severity(None, "HIGH") == "high" and ingest.map_severity(None, "weird") == "low"


def test_asset_and_client_resolution():
    with dbmod.session_scope() as db:
        from app.models import Client

        c = Client(name="C", code="C")
        db.add(c)
        db.flush()
        db.add(Asset(name="ws-001", agent_id="001", client_id=c.id))
        db.flush()
        a, _ = ingest.ingest_alert(db, None, NormAlert(source_id="", title="t", host="ws-001", agent_id="001"), source="manual")
        assert a.client_id == c.id and a.asset_id is not None


def test_poller_checkpoint_and_idempotent_replay():
    tid = mk_tool("wazuh_indexer", "wi", {"url": "https://wazuh.corp.local:9200", "username": "ro"}, {"password": "pw"})
    seen_bodies = []

    def handler(req: httpx.Request):
        body = json.loads(req.content)
        seen_bodies.append(body)
        hits = [{"_id": f"h{i}", "_source": _wazuh_payload(i)} for i in (1, 2)]
        return jresp({"hits": {"hits": hits}})

    mock_http(handler)
    with dbmod.session_scope() as db:
        # First poll ever only seeds the checkpoint at the current newest alert
        # (so a freshly-enabled connector tails new alerts instead of backfilling
        # the entire historical index from the beginning) — it creates nothing yet.
        r = polling.poll_tool(db, db.get(Tool, tid))
        assert r["ok"] and r["created"] == 0
    with dbmod.session_scope() as db:
        st = db.get(Tool, tid).state
        assert st.checkpoint["ts"] and st.error_count == 0 and st.items_total == 0
    assert "sort" in seen_bodies[0] and "query" not in seen_bodies[0]  # seed query: just the latest alert
    with dbmod.session_scope() as db:
        r = polling.poll_tool(db, db.get(Tool, tid))  # second poll: actually fetches alerts since the seeded checkpoint
        assert r["ok"] and r["created"] >= 1
    with dbmod.session_scope() as db:
        st = db.get(Tool, tid).state
        assert st.checkpoint["ts"] and st.error_count == 0 and st.items_total >= 1
        n_before = db.query(Alert).count()
        polling.poll_tool(db, db.get(Tool, tid))  # overlapping window returns same hits: no duplicates
        assert db.query(Alert).count() == n_before
    assert "range" in json.dumps(seen_bodies[1])


def test_poller_failure_backoff_and_isolation():
    tid = mk_tool("wazuh_indexer", "wi", {"url": "https://wazuh.corp.local:9200", "username": "ro"}, {"password": "pw"})
    mock_http(lambda r: httpx.Response(503))
    with dbmod.session_scope() as db:
        r = polling.poll_tool(db, db.get(Tool, tid))
        assert not r["ok"]
    with dbmod.session_scope() as db:
        t = db.get(Tool, tid)
        assert t.state.error_count == 1 and "503" in t.state.last_error
        assert not polling.is_due(t)  # backing off
