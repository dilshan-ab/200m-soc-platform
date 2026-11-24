"""Attack simulation: starting a simulation goes through approval; stopping runs at once; the bundled Caldera address."""
from __future__ import annotations

import json

import httpx
import pytest

from app.connectors.base import ConnectorError, get_connector_cls
from app.services import events
from tests.helpers import jresp, mk_tool, mock_http

CALDERA = "http://caldera:8888"


def _drain():
    from app.db import session_factory

    return events.dispatch_once(session_factory())


@pytest.fixture()
def caldera():
    calls: list[tuple[str, str, dict]] = []

    def handler(req: httpx.Request):
        body = json.loads(req.content) if req.content else {}
        calls.append((req.method, req.url.path, body))
        assert req.headers.get("KEY") == "red-key"
        if req.url.path == "/api/v2/operations" and req.method == "POST":
            return jresp({"id": "op-1", "name": body.get("name"), "state": "running"})
        if req.url.path.startswith("/api/v2/operations/") and req.method == "PATCH":
            return jresp({"id": "op-1", "state": "cleanup"})
        return jresp({"status": "ok"})

    mock_http(handler)
    tool_id = mk_tool("caldera", "Caldera", cfg={"url": CALDERA, "group": "red"}, secrets={"api_key": "red-key"})
    return tool_id, calls


def _start(s, tool_id, **kw):
    body = {"tool_id": tool_id, "action_key": "run_adversary", "targets": ["red"],
            "params": {"adversary_id": "adv-123", "operation_name": "Quarterly purple team"}, "reason": "validate ransomware detections", **kw}
    return s.post("/api/simulation/run", body)


def test_starting_an_adversary_waits_for_two_approvals_and_does_not_touch_caldera(admin, caldera):
    tool_id, calls = caldera
    r = _start(admin, tool_id)
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "pending_approval" and r.json()["approvals_required"] == 2
    assert calls == []  # nothing ran yet


def test_after_two_approvals_the_operation_runs_against_the_chosen_agent_group(admin, make_session, caldera):
    tool_id, calls = caldera
    rid = _start(admin, tool_id, targets=["blue-team-hosts"]).json()["request_id"]
    a2, a3 = make_session("a2@t.local", "admin"), make_session("a3@t.local", "admin")
    assert admin.post(f"/api/response/requests/{rid}/decision", {"decision": "approve", "reason": "mine"}).status_code == 403  # no self-approval
    assert a2.post(f"/api/response/requests/{rid}/decision", {"decision": "approve", "reason": "scope agreed"}).json()["status"] == "pending_approval"
    assert a3.post(f"/api/response/requests/{rid}/decision", {"decision": "approve", "reason": "window agreed"}).json()["status"] == "approved"
    assert _drain() >= 1
    assert a2.get(f"/api/response/requests/{rid}").json()["status"] == "succeeded"
    method, path, body = calls[-1]
    assert (method, path) == ("POST", "/api/v2/operations")
    assert body["adversary"] == {"adversary_id": "adv-123"} and body["group"] == "blue-team-hosts" and body["name"] == "Quarterly purple team"


def test_stopping_an_operation_runs_at_once(admin, caldera):
    tool_id, calls = caldera
    r = admin.post("/api/simulation/run", {"tool_id": tool_id, "action_key": "stop_operation", "params": {"operation_id": "op-1"}})
    assert r.status_code == 200 and r.json()["result"]["state"] == "cleanup"
    assert calls == [("PATCH", "/api/v2/operations/op-1", {"state": "cleanup"})]


def test_bad_requests_are_refused(admin, make_session, caldera):
    tool_id, calls = caldera
    assert _start(admin, tool_id, reason="").status_code == 400  # a reason is required
    assert _start(admin, tool_id, params={"adversary_id": "adv-123"}).status_code == 400  # operation name required
    assert admin.post("/api/simulation/run", {"tool_id": tool_id, "action_key": "run_atomic", "targets": ["h"], "reason": "wrong tool"}).status_code == 400
    assert admin.post("/api/simulation/run", {"tool_id": tool_id, "action_key": "delete_everything", "reason": "nope"}).status_code == 400
    assert make_session("l2@t.local", "l2").post("/api/simulation/run", {"tool_id": tool_id, "action_key": "stop_operation"}).status_code == 403
    assert calls == []


def test_only_the_bundled_caldera_address_may_use_plain_http():
    seen = []
    mock_http(lambda r: (seen.append(str(r.url)), jresp({"status": "ok"}))[1])
    bundled = get_connector_cls("caldera")({"url": CALDERA}, {"api_key": "k"})
    assert bundled.test()[0].ok and seen == [f"{CALDERA}/api/v2/health"]
    elsewhere = get_connector_cls("caldera")({"url": "http://10.0.0.9:8888"}, {"api_key": "k"})
    with pytest.raises(ConnectorError, match="egress policy"):
        elsewhere.test()
    lookalike = get_connector_cls("caldera")({"url": "http://caldera:8888.evil.example"}, {"api_key": "k"})
    with pytest.raises(ConnectorError, match="egress policy"):
        lookalike.test()
