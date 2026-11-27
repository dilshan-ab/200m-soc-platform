from __future__ import annotations

from app import db as dbmod
from app.models import Case
from tests.helpers import mk_alert


def test_client_scope_isolation(make_session, clients):
    a, b = clients
    ida, idb, idn = mk_alert(a, "A alert", source_id=""), mk_alert(b, "B alert", host="h2", rule_id="2"), mk_alert(None, "Unassigned", host="h3", rule_id="3")
    scoped = make_session("l1a@t.local", "l1", all_clients=False, client_ids=[a])
    ids = {x["id"] for x in scoped.get("/api/alerts").json()["items"]}
    assert ids == {ida}
    assert scoped.get(f"/api/alerts/{idb}").status_code == 404  # 404, not 403: no existence oracle
    assert scoped.get(f"/api/alerts/{idn}").status_code == 404
    r = scoped.post("/api/alerts/bulk", {"ids": [ida, idb], "status": "acknowledged"}).json()
    assert r["updated"] == 1 and r["skipped"] == [idb]
    assert scoped.post("/api/alerts/to-case", {"alert_ids": [idb]}).status_code == 404
    full = make_session("l2@t.local", "l2")
    assert len(full.get("/api/alerts").json()["items"]) == 3
    # a scoped user with no memberships sees nothing
    none = make_session("none@t.local", "l1", all_clients=False)
    assert none.get("/api/alerts").json()["total"] == 0


def test_scope_applies_to_dashboard_search_stats(make_session, clients):
    a, b = clients
    mk_alert(a, "Alpha thing")
    mk_alert(b, "Bravo thing", host="h2", rule_id="2")
    s = make_session("l1a@t.local", "l1", all_clients=False, client_ids=[a])
    assert s.get("/api/dashboard").json()["metrics"]["alerts_total"] == 1
    res = s.get("/api/search", params={"q": "thing"}).json()
    assert [x["title"] for x in res["alerts"]] == ["Alpha thing"]
    assert s.get("/api/dashboard", params={"client_id": b}).status_code == 404


def test_alert_patch_rules(make_session, clients):
    aid = mk_alert(clients[0])
    l1 = make_session("l1@t.local", "l1")
    v = l1.get(f"/api/alerts/{aid}").json()["version"]
    assert l1.patch(f"/api/alerts/{aid}", {"version": v, "status": "false_positive"}).status_code == 400  # needs note
    assert l1.patch(f"/api/alerts/{aid}", {"version": v, "tuning_note": "x"}).status_code == 403  # tuning needs l2
    r = l1.patch(f"/api/alerts/{aid}", {"version": v, "status": "acknowledged"})
    assert r.status_code == 200 and r.json()["version"] == v + 1
    assert l1.patch(f"/api/alerts/{aid}", {"version": v, "status": "investigating"}).status_code == 409  # stale
    viewer = make_session("v@t.local", "viewer")
    assert viewer.patch(f"/api/alerts/{aid}", {"version": v + 1, "status": "resolved"}).status_code == 403
    assert l1.patch(f"/api/alerts/{aid}", {"version": v + 1, "bogus": 1}).status_code == 422  # extra fields forbidden


def test_alert_filters_and_search_are_safe(make_session):
    mk_alert(None, "100% match_me", host="h1", rule_id="1")
    mk_alert(None, "other", host="h2", rule_id="2")
    s = make_session("v@t.local", "viewer")
    assert s.get("/api/alerts", params={"q": "%"}).json()["total"] == 1  # LIKE wildcard is escaped, not a match-all
    assert s.get("/api/alerts", params={"q": "' OR 1=1 --"}).json()["total"] == 0
    assert s.get("/api/alerts", params={"severity": "high"}).json()["total"] == 2
    assert s.get("/api/alerts", params={"limit": 100000}).json()["limit"] == 200


def test_case_lifecycle_and_sla(make_session, clients):
    a = clients[0]
    ids = [mk_alert(a, host="h1", rule_id="1"), mk_alert(a, host="h2", rule_id="2")]
    l2 = make_session("l2@t.local", "l2")
    r = l2.post("/api/alerts/to-case", {"alert_ids": ids, "template": "Phishing"})
    assert r.status_code == 201, r.text
    cid = r.json()["id"]
    c = l2.get(f"/api/cases/{cid}").json()
    assert len(c["tasks"]) == 5 and len(c["alerts"]) == 2 and c["resolve_due"]
    assert l2.post("/api/alerts/to-case", {"alert_ids": ids[:1]}).status_code == 409  # already in a case
    v = c["version"]
    r = l2.patch(f"/api/cases/{cid}", {"version": v, "status": "resolved", "resolution": "true_positive"})
    assert r.status_code == 400 and "required task" in r.json()["detail"]
    for t in c["tasks"]:
        assert l2.patch(f"/api/cases/{cid}/tasks/{t['id']}", {"status": "done"}).status_code == 200
    assert l2.patch(f"/api/cases/{cid}", {"version": v, "status": "resolved"}).status_code == 400  # resolution required
    r = l2.patch(f"/api/cases/{cid}", {"version": v, "status": "resolved", "resolution": "true_positive"})
    assert r.status_code == 200
    r = l2.patch(f"/api/cases/{cid}", {"version": r.json()["version"], "status": "closed"})
    assert r.status_code == 200 and r.json()["status"] == "closed"
    assert l2.patch(f"/api/cases/{cid}", {"version": r.json()["version"], "title": "edit after close"}).status_code == 409
    l1 = make_session("l1@t.local", "l1")
    cid2 = l1.post("/api/cases", {"title": "manual case", "severity": "low"}).json()["id"]
    v2 = l1.get(f"/api/cases/{cid2}").json()["version"]
    assert l1.patch(f"/api/cases/{cid2}", {"version": v2, "status": "resolved", "resolution": "x"}).status_code == 403  # l1 can't close


def test_cases_cannot_mix_clients(make_session, clients):
    a, b = clients
    ids = [mk_alert(a, host="h1", rule_id="1"), mk_alert(b, host="h2", rule_id="2")]
    r = make_session("l2@t.local", "l2").post("/api/alerts/to-case", {"alert_ids": ids})
    assert r.status_code == 400


def test_case_scope_and_versions(make_session, clients):
    a, b = clients
    with dbmod.session_scope() as db:
        db.add(Case(number=1, title="B case", client_id=b))
        db.flush()
        cid = db.query(Case).one().id
    s = make_session("l1a@t.local", "l1", all_clients=False, client_ids=[a])
    assert s.get(f"/api/cases/{cid}").status_code == 404
    assert s.get("/api/cases").json()["total"] == 0
    assert s.post("/api/cases", {"title": "sneaky", "client_id": b}).status_code == 403
    assert s.post("/api/cases", {"title": "Unassigned case"}).status_code == 403
    created = s.post("/api/cases", {"title": "Assigned client case", "client_id": a})
    assert created.status_code == 201
    assert {row["id"] for row in s.get("/api/cases").json()["items"]} == {created.json()["id"]}
