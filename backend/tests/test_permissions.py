from __future__ import annotations

from app.policy import CAPABILITIES, has_capability, role_capabilities


def test_superadmin_bypasses_everything_unconditionally():
    assert set(role_capabilities("superadmin")) == set(CAPABILITIES)
    for cap in CAPABILITIES:
        assert has_capability("superadmin", grants=[], cap=cap, denied=[cap]) is True  # even a (nonsensical) deny can't stop superadmin


def test_denied_overrides_role_default_and_grant():
    assert has_capability("l2", grants=[], cap="cases.read", denied=[]) is True  # role default
    assert has_capability("l2", grants=[], cap="cases.read", denied=["cases.read"]) is False  # explicit deny wins
    assert has_capability("l2", grants=["cases.read"], cap="cases.read", denied=["cases.read"]) is False  # deny still wins over grant
    assert has_capability("viewer", grants=["cases.write"], cap="cases.write", denied=[]) is True  # grant adds beyond role default


def test_admin_can_change_other_users_permissions(admin, make_session):
    target = make_session("l1target@t.local", "l1")
    uid = target.get("/api/auth/me").json()["id"]
    r = admin.patch(f"/api/admin/users/{uid}", {"grants": ["servers.write"]})
    assert r.status_code == 200
    assert r.json()["grants"] == ["servers.write"]


def test_superadmin_can_grant_and_deny_user_permissions(superadmin, make_session):
    target = make_session("l1target2@t.local", "l1")
    uid = target.get("/api/auth/me").json()["id"]

    grant = superadmin.patch(f"/api/admin/users/{uid}", {"grants": ["servers.write"]})
    assert grant.status_code == 200 and grant.json()["grants"] == ["servers.write"]

    deny = superadmin.patch(f"/api/admin/users/{uid}", {"denied": ["cases.read"]})
    assert deny.status_code == 200 and deny.json()["denied"] == ["cases.read"]

    both = superadmin.get("/api/admin/users").json()
    row = next(u for u in both if u["id"] == uid)
    assert row["grants"] == ["servers.write"] and row["denied"] == ["cases.read"]


def test_grant_and_deny_cannot_overlap(superadmin, make_session):
    target = make_session("l1target3@t.local", "l1")
    uid = target.get("/api/auth/me").json()["id"]
    superadmin.patch(f"/api/admin/users/{uid}", {"grants": ["servers.write"]})
    r = superadmin.patch(f"/api/admin/users/{uid}", {"denied": ["servers.write"]})
    assert r.status_code == 400
    assert "granted and denied" in r.json()["detail"]


def test_unknown_capability_rejected(superadmin, make_session):
    target = make_session("l1target4@t.local", "l1")
    uid = target.get("/api/auth/me").json()["id"]
    r = superadmin.patch(f"/api/admin/users/{uid}", {"grants": ["not.a.real.capability"]})
    assert r.status_code == 400


def test_admin_can_view_but_not_edit_role_permission_matrix(admin):
    view = admin.get("/api/admin/permissions")
    assert view.status_code == 200 and "matrix" in view.json()
    edit = admin.put("/api/admin/permissions", {"matrix": {"viewer": ["alerts.read"]}})
    assert edit.status_code == 403


def test_superadmin_can_edit_role_permission_matrix(superadmin):
    baseline = set(superadmin.get("/api/admin/permissions").json()["matrix"]["l1"])
    r = superadmin.put("/api/admin/permissions", {"matrix": {"l1": ["cases.close"]}})
    assert r.status_code == 200
    matrix = superadmin.get("/api/admin/permissions").json()["matrix"]
    assert set(matrix["l1"]) == baseline | {"cases.close"}
