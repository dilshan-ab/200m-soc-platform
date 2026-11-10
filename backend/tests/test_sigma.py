from __future__ import annotations

RULE_A = """
title: Suspicious PowerShell Encoded Command
id: 1a2b3c4d-5e6f-7890-abcd-ef1234567890
status: experimental
description: Detects obfuscated PowerShell via -enc
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains: '-enc'
  condition: selection
falsepositives:
  - Legitimate admin scripts
level: high
"""

RULE_B_NO_TITLE = """
description: no title here
level: low
"""


def test_import_parses_rule_and_extracts_technique(make_session):
    l2 = make_session("l2@t.local", "l2")
    viewer = make_session("v@t.local", "viewer")
    assert viewer.post("/api/sigma/rules/import", {"yaml": RULE_A}).status_code == 403

    r = l2.post("/api/sigma/rules/import", {"yaml": RULE_A})
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["imported"] == 1 and body["duplicates"] == [] and body["skipped"] == []

    rows = l2.get("/api/sigma/rules").json()["items"]
    assert len(rows) == 1
    row = rows[0]
    assert row["title"] == "Suspicious PowerShell Encoded Command"
    assert row["technique_ids"] == ["T1059.001"]
    assert row["level"] == "high" and row["status"] == "experimental" and row["enabled"] is True

    detail = l2.get(f"/api/sigma/rules/{row['id']}").json()
    assert "detection" in detail["raw_yaml"]
    assert detail["false_positives"] == ["Legitimate admin scripts"]


def test_duplicate_import_is_skipped_and_invalid_doc_reported(make_session):
    l2 = make_session("l2b@t.local", "l2")
    first = l2.post("/api/sigma/rules/import", {"yaml": RULE_A}).json()
    assert first["imported"] == 1
    second = l2.post("/api/sigma/rules/import", {"yaml": RULE_A + "\n---\n" + RULE_B_NO_TITLE})
    body = second.json()
    assert body["imported"] == 0
    assert body["duplicates"] == ["Suspicious PowerShell Encoded Command"]
    assert any("missing required field 'title'" in s for s in body["skipped"])


def test_rule_filters_and_toggle_disable(make_session):
    l2 = make_session("l2c@t.local", "l2")
    l2.post("/api/sigma/rules/import", {"yaml": RULE_A})
    rid = l2.get("/api/sigma/rules").json()["items"][0]["id"]

    assert l2.get("/api/sigma/rules", params={"technique_id": "T1059.001"}).json()["total"] == 1
    assert l2.get("/api/sigma/rules", params={"technique_id": "T1110"}).json()["total"] == 0
    assert l2.get("/api/sigma/rules", params={"level": "critical"}).json()["total"] == 0
    assert l2.get("/api/sigma/rules", params={"q": "powershell"}).json()["total"] == 1

    r = l2.patch(f"/api/sigma/rules/{rid}", {"enabled": False, "status": "deprecated"})
    assert r.status_code == 200 and r.json()["enabled"] is False and r.json()["status"] == "deprecated"
    assert l2.get("/api/sigma/rules", params={"enabled": True}).json()["total"] == 0

    assert l2.delete(f"/api/sigma/rules/{rid}").status_code == 204
    assert l2.get(f"/api/sigma/rules/{rid}").status_code == 404


def test_mitre_matrix_reflects_enabled_rule_coverage(make_session):
    l1 = make_session("l1d@t.local", "l1")
    l2 = make_session("l2d@t.local", "l2")
    before = l1.get("/api/mitre/matrix").json()
    assert before["rules_covered"] == 0

    rid_resp = l2.post("/api/sigma/rules/import", {"yaml": RULE_A})
    assert rid_resp.status_code == 201
    after = l1.get("/api/mitre/matrix").json()
    assert after["rules_covered"] == 1 and after["total_rules_mapped"] == 1
    entry = next(e for col in after["matrix"].values() for e in col if e["id"] == "T1059.001")
    assert entry["rule_count"] == 1

    rid = l2.get("/api/sigma/rules").json()["items"][0]["id"]
    l2.patch(f"/api/sigma/rules/{rid}", {"enabled": False})
    disabled = l1.get("/api/mitre/matrix").json()
    assert disabled["rules_covered"] == 0  # disabled rules don't count toward coverage
