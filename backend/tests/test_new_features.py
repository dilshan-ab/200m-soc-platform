"""Coverage for the triage queue, investigation notebooks, report templates/schedules, and the integration health dashboard."""
from __future__ import annotations

from .helpers import mk_alert


def test_triage_queue_smoke(make_session, clients):
    cid, _ = clients
    s = make_session("l1@t.local", "l1", client_ids=[cid], all_clients=False)
    r = s.get("/api/alerts/queue")
    assert r.status_code == 200, r.text
    body = r.json()
    assert "items" in body and "by_severity" in body and "total_waiting" in body


def test_triage_queue_claim_flow(make_session, clients):
    cid, _ = clients
    aid = mk_alert(cid, title="Suspicious login", severity="critical")
    s = make_session("l1e@t.local", "l1", client_ids=[cid], all_clients=False)
    r = s.get("/api/alerts/queue")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["total_waiting"] >= 1
    assert any(item["id"] == aid for item in body["items"])
    assert body["by_severity"]["critical"] >= 1

    me = s.get("/api/auth/me").json()
    version = next(item["version"] for item in body["items"] if item["id"] == aid)
    r = s.patch(f"/api/alerts/{aid}", {"version": version, "assignee_id": me["id"], "status": "acknowledged"})
    assert r.status_code == 200, r.text

    r = s.get("/api/alerts/queue")
    assert aid not in [item["id"] for item in r.json()["items"]]


def test_notebooks_crud_smoke(make_session):
    s = make_session("l1b@t.local", "l1")
    r = s.post("/api/notebooks", {"title": "Phishing campaign", "description": "tracking", "tags": ["phish"]})
    assert r.status_code == 201, r.text
    nb = r.json()
    assert nb["cells"] == []

    r = s.post(f"/api/notebooks/{nb['id']}/cells/new", {"type": "note", "content": "initial note", "filters": {}})
    assert r.status_code == 200, r.text
    nb2 = r.json()
    assert len(nb2["cells"]) == 1
    assert nb2["cells"][0]["type"] == "note"

    r = s.put(f"/api/notebooks/{nb['id']}/cells", {"version": nb2["version"], "cells": []})
    assert r.status_code == 200, r.text
    assert r.json()["cells"] == []

    r = s.get("/api/notebooks")
    assert r.status_code == 200
    assert any(x["id"] == nb["id"] for x in r.json())

    r = s.delete(f"/api/notebooks/{nb['id']}")
    assert r.status_code == 204


def test_report_templates_smoke(make_session):
    s = make_session("l1c@t.local", "l1")
    r = s.post("/api/report-templates", {"name": "Weekly exec", "kind": "soc_metrics", "fmt": "html", "params": {"days": 7}})
    assert r.status_code == 201, r.text
    tid = r.json()["id"]
    r = s.get("/api/report-templates")
    assert r.status_code == 200
    assert any(t["id"] == tid for t in r.json())
    r = s.delete(f"/api/report-templates/{tid}")
    assert r.status_code == 204


def test_report_schedule_run_now_and_delete(admin):
    r = admin.post("/api/reports/schedules", {"name": "Daily", "kind": "soc_metrics", "cadence": "daily", "hour": 7, "fmt": "html", "timezone": "UTC"})
    assert r.status_code == 201, r.text
    sid = r.json()["id"]
    r = admin.post(f"/api/reports/schedules/{sid}/run-now")
    assert r.status_code == 202, r.text
    r = admin.delete(f"/api/reports/schedules/{sid}")
    assert r.status_code == 204, r.text


def test_integration_health_smoke(admin):
    r = admin.get("/api/integrations/health")
    assert r.status_code == 200, r.text
    body = r.json()
    assert "counts" in body and "tools" in body


def test_copilot_status_smoke(make_session):
    s = make_session("l1d@t.local", "l1")
    r = s.get("/api/copilot/status")
    assert r.status_code == 200, r.text
    assert r.json()["enabled"] is False


def test_simulation_platforms_smoke(make_session):
    s = make_session("l2@t.local", "l2")
    r = s.get("/api/simulation/platforms")
    assert r.status_code == 200, r.text
    assert isinstance(r.json(), list)
