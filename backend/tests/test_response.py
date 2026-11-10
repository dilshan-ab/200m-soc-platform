from __future__ import annotations

from datetime import timedelta

import httpx

from app import db as dbmod
from app.models import ActionRequest, Server, utcnow
from app.services import events
from tests.helpers import jresp, mk_alert, mk_tool, mock_http


def _wazuh_manager():
    return mk_tool("wazuh_manager", "wm", {"url": "https://wazuh.corp.local:55000", "username": "api"}, {"password": "pw"})


def _drain():
    from app.db import session_factory

    return events.dispatch_once(session_factory())


def _req(s, aid=None, targets=("198.51.100.9",), action="block_ip", **kw):
    return s.post("/api/response/requests", {"action_key": action, "targets": list(targets), "reason": "brute force source", "alert_id": aid, **kw})


def test_request_approve_execute_flow(make_session, clients):
    _wazuh_manager()
    calls = []

    def handler(req: httpx.Request):
        calls.append((req.method, req.url.path))
        if req.url.path.endswith("/authenticate"):
            return httpx.Response(200, text="jwt-token")
        return jresp({"data": {"total_affected_items": 1}})

    mock_http(handler)
    aid = mk_alert(clients[0])
    l1, l2 = make_session("l1@t.local", "l1"), make_session("l2@t.local", "l2")
    r = _req(l1, aid)
    assert r.status_code == 201 and r.json()["status"] == "pending_approval"
    rid = r.json()["id"]
    assert l1.post(f"/api/response/requests/{rid}/decision", {"decision": "approve", "reason": "ok fine"}).status_code == 403  # l1 lacks approve (also no self-approval)
    r = l2.post(f"/api/response/requests/{rid}/decision", {"decision": "approve", "reason": "verified source ip"})
    assert r.status_code == 200 and r.json()["status"] == "approved"
    assert _drain() >= 1
    done = l2.get(f"/api/response/requests/{rid}").json()
    assert done["status"] == "succeeded", done
    assert ("PUT", "/active-response") in calls
    assert l2.post(f"/api/response/requests/{rid}/decision", {"decision": "approve", "reason": "again"}).status_code == 409


def test_no_self_approval_even_for_admin(admin, admin2, clients):
    aid = mk_alert(clients[0])
    rid = _req(admin, aid).json()["id"]
    r = admin.post(f"/api/response/requests/{rid}/decision", {"decision": "approve", "reason": "my own request"})
    assert r.status_code == 403 and "own request" in r.json()["detail"]
    assert admin2.post(f"/api/response/requests/{rid}/decision", {"decision": "reject", "reason": "not needed"}).json()["status"] == "rejected"


def test_critical_action_needs_two_distinct_approvers(make_session, admin, clients):
    _wazuh_manager()
    mock_http(lambda r: httpx.Response(200, text="t") if r.url.path.endswith("authenticate") else jresp({"data": {"total_affected_items": 1}}))
    rid = _req(make_session("l1@t.local", "l1"), None, targets=("jdoe",), action="disable_account").json()
    assert rid["approvals_required"] == 2
    rid = rid["id"]
    l2 = make_session("l2@t.local", "l2")
    assert l2.post(f"/api/response/requests/{rid}/decision", {"decision": "approve", "reason": "looks right"}).status_code == 403  # critical needs admin role
    assert admin.post(f"/api/response/requests/{rid}/decision", {"decision": "approve", "reason": "approved first"}).json()["status"] == "pending_approval"
    assert admin.post(f"/api/response/requests/{rid}/decision", {"decision": "approve", "reason": "again?"}).status_code == 409  # same approver twice
    a2 = make_session("admin3@t.local", "admin")
    assert a2.post(f"/api/response/requests/{rid}/decision", {"decision": "approve", "reason": "approved second"}).json()["status"] == "approved"


def test_viewer_cannot_request_and_validation(make_session, clients):
    v = make_session("v@t.local", "viewer")
    assert _req(v).status_code == 403
    l1 = make_session("l1@t.local", "l1")
    assert _req(l1, targets=("not-an-ip",)).status_code == 400
    assert _req(l1, targets=("127.0.0.1",)).status_code == 400
    assert _req(l1, targets=("169.254.169.254",)).status_code == 400
    assert l1.post("/api/response/requests", {"action_key": "nuke_all", "targets": ["1.1.1.1"], "reason": "because"}).status_code == 400
    assert l1.post("/api/response/requests", {"action_key": "block_ip", "targets": ["1.1.1.1"], "reason": "x"}).status_code == 422
    too_many = [f"198.51.100.{i}" for i in range(1, 15)]
    assert _req(l1, targets=too_many).status_code == 400  # blast radius cap
    assert _req(l1, targets=("10.1.1.1",), action="collect_artifact").status_code == 400  # hostname required? 'artifact' param missing


def test_protected_targets_cannot_be_acted_on(make_session, admin, clients):
    with dbmod.session_scope() as db:
        db.add(Server(name="soc-server-1", host="10.0.0.11", role="soc_core"))
    l1 = make_session("l1@t.local", "l1")
    r = l1.post("/api/response/requests", {"action_key": "isolate_host", "targets": ["soc-server-1"], "reason": "test isolate"})
    assert r.status_code == 403 and "protected" in r.json()["detail"]
    r = l1.post("/api/response/requests", {"action_key": "block_ip", "targets": ["10.0.0.11"], "reason": "test block"})
    assert r.status_code == 403
    admin.step_up()
    assert admin.put("/api/response/protected-targets", {"targets": ["198.51.100.50"]}).status_code == 200
    assert _req(l1, targets=("198.51.100.50",)).status_code == 403


def test_payload_tamper_detected(make_session, admin, clients):
    aid = mk_alert(clients[0])
    rid = _req(make_session("l1@t.local", "l1"), aid).json()["id"]
    with dbmod.session_scope() as db:
        db.get(ActionRequest, rid).targets = ["192.0.2.200"]  # tamper after submission
    r = admin.post(f"/api/response/requests/{rid}/decision", {"decision": "approve", "reason": "approve it"})
    assert r.status_code == 409 and "changed" in r.json()["detail"]


def test_expired_and_idempotent(make_session, admin, clients):
    aid = mk_alert(clients[0])
    l1 = make_session("l1@t.local", "l1")
    r1 = _req(l1, aid, idempotency_key="k1")
    r2 = _req(l1, aid, idempotency_key="k1")
    assert r1.json()["id"] == r2.json()["id"]
    with dbmod.session_scope() as db:
        db.get(ActionRequest, r1.json()["id"]).expires_at = utcnow() - timedelta(seconds=1)
    assert admin.post(f"/api/response/requests/{r1.json()['id']}/decision", {"decision": "approve", "reason": "too late"}).status_code == 409


def test_kill_switch_blocks_new_and_approved(make_session, admin, admin2, clients):
    _wazuh_manager()
    mock_http(lambda r: httpx.Response(200, text="t") if r.url.path.endswith("authenticate") else jresp({"data": {"total_affected_items": 1}}))
    aid = mk_alert(clients[0])
    l1 = make_session("l1@t.local", "l1")
    rid = _req(l1, aid).json()["id"]
    assert admin.post("/api/response/kill-switch", {"engaged": True, "reason": "incident in progress"}).status_code == 200
    assert _req(l1, aid, targets=("198.51.100.77",)).status_code == 423
    assert admin2.post(f"/api/response/requests/{rid}/decision", {"decision": "approve", "reason": "approved before"}).status_code == 200
    _drain()
    assert admin.get(f"/api/response/requests/{rid}").json()["status"] == "failed"  # execution refused
    assert admin.post("/api/response/kill-switch", {"engaged": False, "reason": "all clear now"}).status_code == 200


def test_ambiguous_outcome_is_not_marked_failed(make_session, admin2, clients):
    _wazuh_manager()

    def handler(req):
        if req.url.path.endswith("authenticate"):
            return httpx.Response(200, text="t")
        raise httpx.ReadTimeout("boom")

    mock_http(handler)
    aid = mk_alert(clients[0])
    rid = _req(make_session("l1@t.local", "l1"), aid).json()["id"]
    admin2.post(f"/api/response/requests/{rid}/decision", {"decision": "approve", "reason": "go ahead"})
    _drain()
    assert admin2.get(f"/api/response/requests/{rid}").json()["status"] == "outcome_unknown"
    r = admin2.post(f"/api/response/requests/{rid}/resolve-unknown", {"decision": "reject", "reason": "verified not applied"})
    assert r.json()["status"] == "failed"


def test_no_enabled_tool_fails_cleanly(make_session, admin2, clients):
    aid = mk_alert(clients[0])
    rid = _req(make_session("l1@t.local", "l1"), aid).json()["id"]
    admin2.post(f"/api/response/requests/{rid}/decision", {"decision": "approve", "reason": "go ahead"})
    _drain()
    r = admin2.get(f"/api/response/requests/{rid}").json()
    assert r["status"] == "failed" and "no enabled" in r["result"]["error"]


def test_scope_for_response_requests(make_session, clients):
    a, b = clients
    aid_b = mk_alert(b)
    scoped = make_session("l1a@t.local", "l1", all_clients=False, client_ids=[a])
    assert _req(scoped, aid_b).status_code == 404
    assert _req(scoped, None).status_code == 403  # cannot determine client for a scoped user


def test_auto_revert_of_block(make_session, admin2, clients):
    _wazuh_manager()
    mock_http(lambda r: httpx.Response(200, text="t") if r.url.path.endswith("authenticate") else jresp({"data": {"total_affected_items": 1}}))
    aid = mk_alert(clients[0])
    rid = _req(make_session("l1@t.local", "l1"), aid, params={"revert_minutes": 30}).json()["id"]
    admin2.post(f"/api/response/requests/{rid}/decision", {"decision": "approve", "reason": "temporary block"})
    _drain()
    with dbmod.session_scope() as db:
        r = db.get(ActionRequest, rid)
        assert r.status == "succeeded" and r.revert_at is not None
        r.revert_at = utcnow() - timedelta(seconds=1)
    from app.services import response

    with dbmod.session_scope() as db:
        assert response.revert_due(db) == 1
    _drain()
    with dbmod.session_scope() as db:
        assert {x.action_key for x in db.query(ActionRequest).all()} == {"block_ip", "unblock_ip"}
        assert all(x.status == "succeeded" for x in db.query(ActionRequest).all())
