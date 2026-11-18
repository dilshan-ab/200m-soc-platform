from __future__ import annotations

import httpx

from app import db as dbmod
from app.models import Alert
from app.services import events
from tests.helpers import jresp, mk_alert, mk_tool, mock_http


def _drain():
    from app.db import session_factory

    return events.dispatch_once(session_factory())


def _graph_set_status_and_branch():
    nodes = [
        {"id": "t1", "type": "trigger", "data": {"label": "Alert created"}},
        {"id": "a1", "type": "action", "data": {"label": "Ack", "action_type": "set_status", "status": "acknowledged"}},
        {"id": "c1", "type": "condition", "data": {"label": "High+?", "field": "severity", "op": "gte", "value": "high"}},
        {"id": "a2", "type": "action", "data": {"label": "Note", "action_type": "add_note", "text": "escalated by playbook"}},
        {"id": "e1", "type": "end", "data": {"label": "Done (escalated)"}},
        {"id": "e2", "type": "end", "data": {"label": "Done (no match)"}},
    ]
    edges = [
        {"id": "x1", "source": "t1", "target": "a1"},
        {"id": "x2", "source": "a1", "target": "c1"},
        {"id": "x3", "source": "c1", "target": "a2", "label": "Yes"},
        {"id": "x4", "source": "c1", "target": "e2", "label": "No"},
        {"id": "x5", "source": "a2", "target": "e1"},
    ]
    return nodes, edges


def test_execute_walks_graph_and_branches(admin, clients):
    aid = mk_alert(clients[0], severity="high")
    nodes, edges = _graph_set_status_and_branch()
    pb = admin.post("/api/playbooks", {"name": "Triage flow", "trigger": "manual", "nodes": nodes, "edges": edges}).json()
    pub = admin.patch(f"/api/playbooks/{pb['id']}", {"status": "published"})
    assert pub.status_code == 200, pub.json()

    run = admin.post(f"/api/playbooks/{pb['id']}/execute", {"alert_id": aid}).json()
    assert run["status"] == "completed", run
    assert run["current_node"] == "e1"
    types = [e["type"] for e in run["execution_log"]]
    assert types == ["trigger", "action", "condition", "action", "end"]
    assert run["execution_log"][2]["result"]["matched"] is True

    with dbmod.session_scope() as db:
        a = db.get(Alert, aid)
        assert a.status == "acknowledged"
        assert "escalated by playbook" in a.tuning_note


def test_execute_other_branch_when_condition_fails(admin, clients):
    aid = mk_alert(clients[0], severity="low")
    nodes, edges = _graph_set_status_and_branch()
    pb = admin.post("/api/playbooks", {"name": "Triage flow 2", "trigger": "manual", "nodes": nodes, "edges": edges}).json()
    admin.patch(f"/api/playbooks/{pb['id']}", {"status": "published"})
    run = admin.post(f"/api/playbooks/{pb['id']}/execute", {"alert_id": aid}).json()
    assert run["status"] == "completed"
    assert run["current_node"] == "e2"


def test_publish_rejects_invalid_node_config(admin):
    nodes = [
        {"id": "t1", "type": "trigger", "data": {}},
        {"id": "c1", "type": "condition", "data": {"label": "bad"}},  # missing field/op
    ]
    edges = [{"id": "x1", "source": "t1", "target": "c1"}]
    pb = admin.post("/api/playbooks", {"name": "Broken flow", "trigger": "manual", "nodes": nodes, "edges": edges}).json()
    r = admin.patch(f"/api/playbooks/{pb['id']}", {"status": "published"})
    assert r.status_code == 400
    assert "condition node" in r.json()["detail"]


def test_request_action_node_pauses_for_approval_then_resumes(admin, admin2, clients):
    mk_tool("wazuh_manager", "wm", {"url": "https://wazuh.corp.local:55000", "username": "api"}, {"password": "pw"})

    def handler(req: httpx.Request):
        if req.url.path.endswith("/authenticate"):
            return httpx.Response(200, text="jwt-token")
        return jresp({"data": {"total_affected_items": 1}})

    mock_http(handler)
    aid = mk_alert(clients[0], src_ip="198.51.100.20")
    nodes = [
        {"id": "t1", "type": "trigger", "data": {}},
        {"id": "a1", "type": "action", "data": {"label": "Block", "action_type": "request_action", "action_key": "block_ip", "target_field": "src_ip"}},
        {"id": "e1", "type": "end", "data": {}},
    ]
    edges = [{"id": "x1", "source": "t1", "target": "a1"}, {"id": "x2", "source": "a1", "target": "e1"}]
    pb = admin.post("/api/playbooks", {"name": "Block flow", "trigger": "manual", "nodes": nodes, "edges": edges}).json()
    admin.patch(f"/api/playbooks/{pb['id']}", {"status": "published"})

    run = admin.post(f"/api/playbooks/{pb['id']}/execute", {"alert_id": aid}).json()
    assert run["status"] == "paused", run
    assert run["current_node"] == "a1"
    request_id = run["execution_log"][-1]["result"]["request_id"]

    r = admin2.post(f"/api/response/requests/{request_id}/decision", {"decision": "approve", "reason": "confirmed malicious"})
    assert r.status_code == 200 and r.json()["status"] == "approved"
    assert _drain() >= 1  # runs action.execute, then the playbook-resume event handler

    final = admin.get(f"/api/playbooks/{pb['id']}/runs").json()["items"][0]
    assert final["status"] == "completed", final
    assert final["current_node"] == "e1"
