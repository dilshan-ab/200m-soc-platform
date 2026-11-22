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


# --------------------------------------------------------------------------- scheduled trigger
def _sched_graph():
    nodes = [
        {"id": "t1", "type": "trigger", "data": {"label": "Schedule"}},
        {"id": "e1", "type": "end", "data": {"label": "Done"}},
    ]
    return nodes, [{"id": "x1", "source": "t1", "target": "e1"}]


def _mk_scheduled(admin, name, interval=15, publish=True, enable=True):
    nodes, edges = _sched_graph()
    pb = admin.post("/api/playbooks", {"name": name, "trigger": "scheduled", "schedule_interval_minutes": interval, "nodes": nodes, "edges": edges})
    assert pb.status_code == 201, pb.text
    pb = pb.json()
    patch = {}
    if publish:
        patch["status"] = "published"
    if enable:
        patch["enabled"] = True
    if patch:
        assert admin.patch(f"/api/playbooks/{pb['id']}", patch).status_code == 200
    return pb["id"]


def _force_due(pid, minutes_ago=1):
    from datetime import timedelta

    from app.db import session_scope
    from app.models import Playbook, utcnow

    with session_scope() as db:
        db.get(Playbook, pid).next_run_at = utcnow() - timedelta(minutes=minutes_ago)


def _run_due():
    from app.db import session_scope
    from app.services import playbooks_engine

    with session_scope() as db:
        return playbooks_engine.run_due_scheduled(db)


def test_scheduled_requires_valid_interval(admin):
    nodes, edges = _sched_graph()
    for bad in (None, 1, 99999):
        r = admin.post("/api/playbooks", {"name": f"bad-{bad}", "trigger": "scheduled", "schedule_interval_minutes": bad, "nodes": nodes, "edges": edges})
        assert r.status_code in (400, 422), (bad, r.text)


def test_scheduled_playbook_fires_when_due_and_reschedules(admin):
    pid = _mk_scheduled(admin, "sched-fires")
    detail = admin.get(f"/api/playbooks/{pid}").json()
    assert detail["next_run_at"] and detail["schedule_interval_minutes"] == 15
    assert _run_due() == 0  # not due yet
    _force_due(pid)
    assert _run_due() == 1
    runs = admin.get(f"/api/playbooks/{pid}/runs").json()["items"]
    assert len(runs) == 1 and runs[0]["status"] == "completed" and runs[0]["trigger_ref"].startswith("scheduled:")
    after = admin.get(f"/api/playbooks/{pid}").json()
    assert after["last_run_at"] and after["next_run_at"] > after["last_run_at"]
    assert _run_due() == 0  # rescheduled into the future, no double fire


def test_scheduled_playbook_skips_disabled_and_draft(admin):
    off = _mk_scheduled(admin, "sched-disabled", enable=False)
    draft = _mk_scheduled(admin, "sched-draft", publish=False, enable=False)
    _force_due(off)
    _force_due(draft)
    assert _run_due() == 0


def test_missed_intervals_run_once_not_burst(admin):
    pid = _mk_scheduled(admin, "sched-outage", interval=5)
    _force_due(pid, minutes_ago=600)  # 2 hours of missed 5-min intervals
    assert _run_due() == 1
    assert _run_due() == 0


def test_changing_trigger_clears_schedule(admin):
    pid = _mk_scheduled(admin, "sched-switch")
    r = admin.patch(f"/api/playbooks/{pid}", {"trigger": "manual"}).json()
    assert r["next_run_at"] is None and r["schedule_interval_minutes"] is None
