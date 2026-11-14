"""Coverage for threat intel sharing (STIX/TAXII), shift handoff, war room, and MSSP/client management."""
from __future__ import annotations

import json


def test_indicator_crud_and_stats(make_session):
    s = make_session("l2a@t.local", "l2")
    r = s.post("/api/threat-intel/indicators", {"type": "ip", "value": "198.51.100.23", "labels": ["malicious-activity"], "confidence": 80, "tlp": "AMBER"})
    assert r.status_code == 201, r.text
    iid = r.json()["id"]
    assert r.json()["sightings"] == 1

    # Re-adding the same (type, value) bumps sightings instead of duplicating.
    r2 = s.post("/api/threat-intel/indicators", {"type": "ip", "value": "198.51.100.23"})
    assert r2.status_code == 201
    assert r2.json()["id"] == iid
    assert r2.json()["sightings"] == 2

    r = s.get("/api/threat-intel/indicators", params={"type": "ip"})
    assert r.status_code == 200
    assert any(i["id"] == iid for i in r.json()["items"])

    r = s.get("/api/threat-intel/stats")
    assert r.status_code == 200
    assert r.json()["total"] >= 1

    r = s.post(f"/api/threat-intel/indicators/{iid}/revoke")
    assert r.status_code == 200 and r.json()["revoked"] is True


def test_stix_bundle_import_and_export(make_session):
    s = make_session("l2b@t.local", "l2")
    bundle = {
        "type": "bundle", "id": "bundle--test",
        "objects": [
            {"type": "indicator", "id": "indicator--abc", "pattern": "[ipv4-addr:value = '203.0.113.9']", "indicator_types": ["malicious-activity"], "confidence": 70, "pattern_type": "stix"},
            {"type": "indicator", "id": "indicator--def", "pattern": "[domain-name:value = 'evil.example.com']", "confidence": 60},
            {"type": "identity", "id": "identity--ignored", "name": "Not an indicator"},
        ],
    }
    r = s.post("/api/threat-intel/import", {"bundle": bundle})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["imported"] == 2 and body["skipped"] == 1

    # Importing as a JSON string (not just a dict) also works.
    r = s.post("/api/threat-intel/import", {"bundle": json.dumps(bundle)})
    assert r.status_code == 200
    assert r.json()["imported"] == 2  # same indicators, sightings just increment

    r = s.get("/api/threat-intel/export", params={"type": "domain"})
    assert r.status_code == 200
    out = r.json()
    assert out["type"] == "bundle"
    assert any("evil.example.com" in o["pattern"] for o in out["objects"])


def test_taxii_server_discovery_and_collection(make_session):
    s = make_session("l2c@t.local", "l2")
    s.post("/api/threat-intel/indicators", {"type": "hash", "value": "d" * 64})
    r = s.get("/taxii2/")
    assert r.status_code == 200 and "api_roots" in r.json()
    r = s.get("/taxii2/api1/collections/")
    assert r.status_code == 200
    cid = r.json()["collections"][0]["id"]
    r = s.get(f"/taxii2/api1/collections/{cid}/objects/")
    assert r.status_code == 200
    assert any(o["pattern"].count("d") >= 60 for o in r.json()["objects"])


def test_threat_feed_requires_admin_and_rejects_private_hosts(make_session, admin):
    l1 = make_session("l1x@t.local", "l1")
    assert l1.post("/api/threat-intel/feeds", {"name": "x", "taxii_discovery_url": "https://example.com/taxii2/"}).status_code == 403

    # An admin pointing a feed at a private/internal address is rejected (SSRF guard).
    r = admin.post("/api/threat-intel/feeds", {"name": "Internal", "taxii_discovery_url": "https://127.0.0.1/taxii2/"})
    assert r.status_code == 400


def test_shift_handoff_lifecycle(make_session):
    out = make_session("out@t.local", "l1")
    incoming = make_session("inc@t.local", "l1")
    r = out.post("/api/handoffs", {"shift_name": "Night", "summary": "Quiet night.", "open_items": [{"title": "Watch alert X", "priority": "high"}]})
    assert r.status_code == 201, r.text
    hid = r.json()["id"]
    assert r.json()["status"] == "draft"

    r = out.patch(f"/api/handoffs/{hid}", {"summary": "Quiet night overall."})
    assert r.status_code == 200

    r = out.post(f"/api/handoffs/{hid}/submit")
    assert r.status_code == 200 and r.json()["status"] == "submitted"

    # Editing after submit is rejected.
    assert out.patch(f"/api/handoffs/{hid}", {"summary": "too late"}).status_code == 409

    r = incoming.get("/api/handoffs/pending")
    assert r.status_code == 200
    assert any(h["id"] == hid for h in r.json())

    r = incoming.post(f"/api/handoffs/{hid}/acknowledge")
    assert r.status_code == 200 and r.json()["status"] == "acknowledged"
    assert incoming.post(f"/api/handoffs/{hid}/acknowledge").status_code == 409


def test_war_room_chat_pin_and_stand_down(make_session):
    lead = make_session("lead@t.local", "l2")
    member = make_session("member@t.local", "l1")
    r = lead.post("/api/warrooms", {"title": "Ransomware outbreak", "severity": "critical"})
    assert r.status_code == 201, r.text
    wid = r.json()["id"]

    r = member.post(f"/api/warrooms/{wid}/join")
    assert r.status_code == 200
    assert len(r.json()["participants"]) == 2

    r = lead.post(f"/api/warrooms/{wid}/messages", {"content": "Containment started on ws-12."})
    assert r.status_code == 201, r.text
    mid = r.json()["id"]

    r = lead.post(f"/api/warrooms/{wid}/messages/{mid}/pin")
    assert r.status_code == 200 and r.json()["pinned"] is True

    detail = lead.get(f"/api/warrooms/{wid}")
    assert detail.status_code == 200
    assert len(detail.json()["messages"]) >= 2  # system join message + the chat message

    # Members (l1) lack warroom.manage and cannot stand the room down.
    assert member.post(f"/api/warrooms/{wid}/stand-down", {"summary": "n/a"}).status_code == 403
    r = lead.post(f"/api/warrooms/{wid}/stand-down", {"summary": "Contained and resolved."})
    assert r.status_code == 200 and r.json()["status"] == "stood_down"
    assert lead.post(f"/api/warrooms/{wid}/messages", {"content": "too late"}).status_code == 409


def test_client_branding_and_membership(admin, clients):
    cid, _ = clients
    r = admin.patch(f"/api/clients/{cid}", {"brand_color": "#145fbd", "tier": "premium", "contact_email": "ciso@acme.test"})
    assert r.status_code == 200, r.text
    assert r.json()["tier"] == "premium"

    from tests.conftest import make_user

    uid, _ = make_user("analyst-for-acme@t.local", "l1", all_clients=False)
    r = admin.post(f"/api/clients/{cid}/members", {"user_id": uid})
    assert r.status_code == 201, r.text

    r = admin.get(f"/api/clients/{cid}/members")
    assert r.status_code == 200
    assert any(m["user_id"] == uid for m in r.json())

    r = admin.delete(f"/api/clients/{cid}/members/{uid}")
    assert r.status_code == 204


def test_mssp_dashboard_requires_all_clients_scope(admin, make_session, clients):
    r = admin.get("/api/clients/mssp/dashboard")
    assert r.status_code == 200, r.text
    body = r.json()
    assert "clients" in body and "total_clients" in body

    cid, _ = clients
    scoped = make_session("scoped-l2@t.local", "l2", client_ids=[cid], all_clients=False)
    assert scoped.get("/api/clients/mssp/dashboard").status_code == 403
