from __future__ import annotations

from tests.helpers import mk_alert


def test_search_hunt_runs_query_against_existing_alerts(make_session, clients):
    client_id = clients[0]
    mk_alert(client_id, "Suspicious PowerShell encoded command", severity="high", host="ws-01", mitre=["T1059.001"])
    mk_alert(client_id, "Normal login", severity="low", host="ws-02")
    mk_alert(client_id, "Another encoded command sighting", severity="critical", host="ws-03", mitre=["T1059.001"])

    l2 = make_session("l2@t.local", "l2")
    viewer = make_session("v@t.local", "viewer")
    assert viewer.post("/api/hunts/search", {"name": "x", "query": {}}).status_code == 403

    r = l2.post("/api/hunts/search", {
        "name": "Encoded PowerShell hunt", "hypothesis": "Attackers are using encoded PowerShell to evade detection",
        "query": {"q": "encoded", "technique_ids": ["T1059.001"], "days": 30},
    })
    assert r.status_code == 201, r.text
    hunt = r.json()
    assert hunt["kind"] == "search" and hunt["status"] == "active" and hunt["match_count"] == 2
    assert len(hunt["results"]) == 2
    hid = hunt["id"]

    got = l2.get(f"/api/hunts/{hid}").json()
    assert got["hypothesis"].startswith("Attackers")
    titles = {row["title"] for row in got["results"]}
    assert titles == {"Suspicious PowerShell encoded command", "Another encoded command sighting"}

    listing = l2.get("/api/hunts").json()
    assert any(h["id"] == hid for h in listing)

    rerun = l2.post(f"/api/hunts/{hid}/run")
    assert rerun.status_code == 200 and rerun.json()["match_count"] == 2

    concluded = l2.post(f"/api/hunts/{hid}/conclude", {"verdict": "true_positive", "note": "Confirmed obfuscated loader, escalating."})
    assert concluded.status_code == 200 and concluded.json()["status"] == "concluded" and concluded.json()["verdict"] == "true_positive"
    assert l2.post(f"/api/hunts/{hid}/conclude", {"verdict": "inconclusive", "note": "x"}).status_code == 409
    assert l2.post(f"/api/hunts/{hid}/run").status_code == 409  # concluded hunts can't be re-run


def test_hunt_escalation_creates_case_from_matches(make_session, clients):
    client_id = clients[0]
    mk_alert(client_id, "Lateral movement via WMI", severity="critical", host="dc-01")

    l2 = make_session("l2b@t.local", "l2")
    hunt = l2.post("/api/hunts/search", {"name": "WMI hunt", "query": {"q": "WMI"}}).json()
    assert hunt["match_count"] == 1

    esc = l2.post(f"/api/hunts/{hunt['id']}/escalate", {})
    assert esc.status_code == 201, esc.text
    case_id = esc.json()["id"]
    assert l2.get(f"/api/hunts/{hunt['id']}").json()["case_id"] is not None

    # escalating again with no remaining un-cased alerts fails cleanly
    again = l2.post(f"/api/hunts/{hunt['id']}/escalate", {})
    assert again.status_code == 409


def test_collection_hunt_flow_is_unchanged(make_session, clients):
    from tests.helpers import mk_tool

    mk_tool("velociraptor", "Raptor", cfg={"allowed_artifacts": ["Windows.System.Pslist"]}, secrets={"api_config": "cfg"})
    l2 = make_session("l2c@t.local", "l2")
    r = l2.post("/api/hunts", {"name": "Collect pslist", "artifact": "Windows.System.Pslist", "targets": ["host-1"], "reason": "investigate host-1"})
    assert r.status_code == 201, r.text
    hid = r.json()["id"]
    got = l2.get(f"/api/hunts/{hid}").json()
    assert got["kind"] == "collection" and got["artifact"] == "Windows.System.Pslist"
