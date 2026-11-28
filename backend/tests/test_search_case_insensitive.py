"""Search boxes match regardless of letter case (PostgreSQL's LIKE is case-sensitive; SQLite's is not, which hid this)."""
from __future__ import annotations

from tests.helpers import mk_alert


def test_alert_search_ignores_case(admin, clients):
    mk_alert(clients[0], title="PowerShell Encoded Command", host="WS-Finance-01")
    for q in ("powershell", "POWERSHELL", "ws-finance"):
        assert admin.get("/api/alerts", params={"q": q, "severity": ["high"]}).json()["total"] == 1, q


def test_case_and_global_search_ignore_case(superadmin, clients):
    created = superadmin.post("/api/cases", {"title": "Ransomware on FileServer", "severity": "high", "client_id": clients[0]})
    assert created.status_code in (200, 201), created.text
    assert superadmin.get("/api/cases", params={"q": "ransomware"}).json()["total"] == 1
    assert superadmin.get("/api/cases", params={"q": "FILESERVER"}).json()["total"] == 1
