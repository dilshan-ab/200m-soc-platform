from __future__ import annotations


def test_list_starts_empty(admin):
    assert admin.get("/api/dashboard-links").json() == []


def test_viewer_can_read_but_not_write(admin, make_session):
    viewer = make_session("v@t.local", "viewer")
    assert viewer.get("/api/dashboard-links").status_code == 200
    r = viewer.post("/api/dashboard-links", {"name": "Wazuh", "url": "https://wazuh.corp.local"})
    assert r.status_code == 403


def test_admin_can_add_and_remove_a_link(admin):
    r = admin.post("/api/dashboard-links", {"name": "Wazuh dashboard", "url": "https://wazuh.corp.local"})
    assert r.status_code == 201, r.text
    links = r.json()
    assert len(links) == 1 and links[0]["name"] == "Wazuh dashboard" and links[0]["url"] == "https://wazuh.corp.local"
    lid = links[0]["id"]

    r2 = admin.post("/api/dashboard-links", {"name": "Grafana", "url": "http://grafana.corp.local:3000"})
    assert len(r2.json()) == 2

    assert admin.get("/api/dashboard-links").json() == r2.json()

    r3 = admin.delete(f"/api/dashboard-links/{lid}")
    assert r3.status_code == 200
    remaining = r3.json()
    assert len(remaining) == 1 and remaining[0]["name"] == "Grafana"


def test_rejects_non_http_urls(admin):
    for bad in ("javascript:alert(1)", "ftp://x", "not a url", ""):
        r = admin.post("/api/dashboard-links", {"name": "x", "url": bad or "x"})
        assert r.status_code in (400, 422), bad
