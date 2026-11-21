from __future__ import annotations

import httpx
from fastapi.testclient import TestClient

from app import db as dbmod
from app.models import ApprovalRequest, SecretRecord, Tool, User
from tests.conftest import PASSWORD
from tests.helpers import jresp, mock_http

HIVE = {"type": "thehive", "name": "TheHive", "values": {"url": "https://hive.corp.local:9000", "api_key": "super-secret-key", "organisation": "SOC"}}


def test_tool_create_never_returns_or_stores_plain_secrets(admin):
    r = admin.post("/api/integrations/tools", HIVE)
    assert r.status_code == 201, r.text
    body = r.json()
    assert "super-secret-key" not in r.text and body["secrets_set"] == ["api_key"]
    assert body["webhook"]["secret"] and body["webhook"]["url"].endswith(f"/api/webhooks/{body['id']}")
    with dbmod.session_scope() as db:
        t = db.get(Tool, body["id"])
        assert "api_key" not in t.config
        assert all("super-secret-key" not in s.ciphertext for s in db.query(SecretRecord))
    again = admin.get(f"/api/integrations/tools/{body['id']}").json()
    assert "secret" not in again["webhook"] and "super-secret-key" not in str(again)


def test_tool_create_validation(admin, make_session):
    assert admin.post("/api/integrations/tools", {**HIVE, "type": "nope"}).status_code == 400
    bad = {**HIVE, "name": "x1", "values": {"url": "http://hive.corp.local", "api_key": "k"}}
    assert admin.post("/api/integrations/tools", bad).status_code == 400  # http
    ssrf = {**HIVE, "name": "x2", "values": {"url": "https://169.254.169.254", "api_key": "k"}}
    assert admin.post("/api/integrations/tools", ssrf).status_code == 400
    missing = {**HIVE, "name": "x3", "values": {"url": "https://hive.corp.local"}}
    assert admin.post("/api/integrations/tools", missing).status_code == 400  # api_key required
    extra = {**HIVE, "name": "x4", "values": {**HIVE["values"], "surprise": 1}}
    assert admin.post("/api/integrations/tools", extra).status_code == 400
    assert admin.post("/api/integrations/tools", HIVE).status_code == 201
    assert admin.post("/api/integrations/tools", HIVE).status_code == 409
    l2 = make_session("l2@t.local", "l2")
    assert l2.post("/api/integrations/tools", {**HIVE, "name": "other"}).status_code == 403
    assert l2.get("/api/integrations/tools").status_code == 200  # read allowed for l2
    assert make_session("l1@t.local", "l1").get("/api/integrations/tools").status_code == 403


def test_test_then_enable_flow_and_reconfigure_resets(admin):
    tid = admin.post("/api/integrations/tools", HIVE).json()["id"]
    assert admin.post(f"/api/integrations/tools/{tid}/enable").status_code == 409  # untested
    mock_http(lambda r: jresp([]))
    r = admin.post(f"/api/integrations/tools/{tid}/test").json()
    assert r["ok"] and r["checks"][0]["name"] == "Cases listed"
    assert admin.post(f"/api/integrations/tools/{tid}/enable").json()["enabled"] is True  # thehive has no 'action' capability
    out = admin.put(f"/api/integrations/tools/{tid}/config", {"values": {"organisation": "NewOrg"}}).json()
    assert out["enabled"] is False and out["status"] == "draft" and out["config"]["organisation"] == "NewOrg" and out["secrets_set"] == ["api_key"]
    assert admin.post(f"/api/integrations/tools/{tid}/enable").status_code == 409  # re-test required
    mock_http(lambda r: httpx.Response(500))
    assert admin.post(f"/api/integrations/tools/{tid}/test").json()["ok"] is False


def test_action_tool_enable_needs_second_admin(admin, admin2):
    vals = {"url": "https://wazuh.corp.local:55000", "username": "api", "password": "pw"}
    tid = admin.post("/api/integrations/tools", {"type": "wazuh_manager", "name": "WM", "values": vals}).json()["id"]
    mock_http(lambda r: httpx.Response(200, text="jwt") if r.url.path.endswith("authenticate") else jresp({"data": {"total_affected_items": 3}}))
    t = admin.post(f"/api/integrations/tools/{tid}/test").json()
    assert t["ok"] is False  # 'Test webhook received' not yet satisfied
    c = TestClient(admin.c.app, client=("10.0.0.7", 1))
    with dbmod.session_scope() as db:
        tool = db.get(Tool, tid)
        sec = __import__("tests.helpers", fromlist=["x"]).webhook_secret(tid)
        assert tool.webhook_auth_mode == "bearer"
    assert c.post(f"/api/webhooks/{tid}", json={"id": "t1", "rule": {"id": "1", "level": 3, "description": "t"}, "agent": {"name": "h"}}, headers={"Authorization": f"Bearer {sec}"}).status_code == 202
    assert admin.post(f"/api/integrations/tools/{tid}/test").json()["ok"] is True
    r = admin.post(f"/api/integrations/tools/{tid}/enable").json()
    assert r["pending_approval"]
    cr = r["request_id"]
    assert admin.post(f"/api/approvals/changes/{cr}/decision", {"decision": "approve", "reason": "own request"}).status_code == 403
    assert admin2.post(f"/api/approvals/changes/{cr}/decision", {"decision": "approve", "reason": "reviewed config"}).json()["status"] == "applied"
    assert admin.get(f"/api/integrations/tools/{tid}").json()["enabled"] is True


def test_pause_resume_rotate_disable(admin):
    tid = admin.post("/api/integrations/tools", HIVE).json()["id"]
    mock_http(lambda r: jresp([]))
    admin.post(f"/api/integrations/tools/{tid}/test")
    admin.post(f"/api/integrations/tools/{tid}/enable")
    assert admin.post(f"/api/integrations/tools/{tid}/pause").json()["status"] == "paused"
    assert admin.post(f"/api/integrations/tools/{tid}/resume").json()["enabled"] is True
    s1 = admin.post(f"/api/integrations/tools/{tid}/rotate-secret").json()["secret"]
    s2 = admin.post(f"/api/integrations/tools/{tid}/rotate-secret").json()["secret"]
    assert s1 != s2 and len(s2) >= 32
    assert admin.delete(f"/api/integrations/tools/{tid}").json()["status"] == "disabled"
    assert admin.get(f"/api/integrations/tools/{tid}").status_code == 200  # history kept


def test_purge_removes_tool_and_secrets(admin):
    tid = admin.post("/api/integrations/tools", HIVE).json()["id"]
    mock_http(lambda r: jresp([]))
    admin.post(f"/api/integrations/tools/{tid}/test")
    admin.post(f"/api/integrations/tools/{tid}/enable")
    assert admin.delete(f"/api/integrations/tools/{tid}/purge").status_code == 204
    assert admin.get(f"/api/integrations/tools/{tid}").status_code == 404
    with dbmod.session_scope() as db:
        assert db.get(Tool, tid) is None
        assert not any(s.ref.startswith(f"tools/{tid}/") for s in db.query(SecretRecord))


def test_mapping_validation(admin):
    tid = admin.post("/api/integrations/tools", HIVE).json()["id"]
    assert admin.put(f"/api/integrations/tools/{tid}/mapping", {"severity_map": {"12": "catastrophic"}}).status_code == 400
    r = admin.put(f"/api/integrations/tools/{tid}/mapping", {"severity_map": {"12": "critical"}, "poll_interval": 60})
    assert r.status_code == 200 and r.json()["severity_map"] == {"12": "critical"}


def test_catalogue_lists_all_28_with_fields(admin):
    cat = admin.get("/api/integrations/catalogue").json()
    assert len(cat) == 28 and {c["type"] for c in cat} >= {"wazuh_indexer", "thehive", "velociraptor", "keycloak", "telegram", "virustotal", "custom", "caldera", "atomic_red_team", "attack_simulator"}
    assert all(c["fields"] and c["link_method"] for c in cat)


def test_admin_promotes_user_directly(admin, make_session):
    target = make_session("l2@t.local", "l2")
    uid = target.get("/api/auth/me").json()["id"]
    r = admin.patch(f"/api/admin/users/{uid}", {"role": "admin"})
    assert r.status_code == 200, r.text
    assert r.json()["role"] == "admin" and "pending_approval" not in r.json()
    with dbmod.session_scope() as db:
        assert db.get(User, uid).role == "admin"


def test_admins_create_users_but_protect_super_admin(admin, superadmin):
    me = admin.get("/api/auth/me").json()
    assert admin.patch(f"/api/admin/users/{me['id']}", {"active": False}).status_code == 403
    body = {"email": "x@t.local", "role": "admin", "password": PASSWORD}
    assert admin.post("/api/admin/users", {**body, "email": "admin-created@t.local"}).status_code == 201
    r = superadmin.post("/api/admin/users", body)
    assert r.status_code == 201 and r.json()["role"] == "admin"  # no second approval needed
    assert superadmin.post("/api/admin/users", {**body, "email": "y@t.local", "role": "superadmin"}).status_code == 422  # one super admin only
    sid = superadmin.get("/api/auth/me").json()["id"]
    assert admin.patch(f"/api/admin/users/{sid}", {"active": False}).status_code == 403  # nobody edits the super admin


def test_api_tokens(app, admin, make_session):
    r = admin.post("/api/tokens", {"name": "ci", "scopes": ["alerts.read"], "days": 7})
    assert r.status_code == 201
    tok = r.json()["token"]
    bearer = TestClient(app, client=("10.0.0.5", 1))
    h = {"Authorization": f"Bearer {tok}"}
    assert bearer.get("/api/alerts", headers=h).status_code == 200
    assert bearer.get("/api/admin/users", headers=h).status_code == 403  # scope-limited even though owner is admin
    assert bearer.post("/api/tokens", json={"name": "xx", "scopes": ["alerts.read"]}, headers=h).status_code == 403
    assert bearer.get("/api/alerts", headers={"Authorization": "Bearer soc_garbage"}).status_code == 401
    viewer = make_session("v@t.local", "viewer")
    assert viewer.post("/api/tokens", {"name": "xx", "scopes": ["admin.users"]}).status_code == 403  # no admin.tokens cap for viewer
    l1 = make_session("l1@t.local", "l1")
    assert l1.post("/api/tokens", {"name": "xx", "scopes": ["admin.users"]}).status_code == 400  # can't mint scopes it doesn't hold
    tid = admin.get("/api/tokens").json()[0]["id"]
    assert admin.delete(f"/api/tokens/{tid}").status_code == 200
    assert bearer.get("/api/alerts", headers=h).status_code == 401


def test_retention_floor_and_approval_on_reduction(admin, admin2):
    assert admin.put("/api/admin/retention", {"dataset": "audit", "days": 30}).status_code == 400
    r = admin.put("/api/admin/retention", {"dataset": "alerts", "days": 60}).json()
    assert r["pending_approval"]
    assert admin.put("/api/admin/retention", {"dataset": "alerts", "days": 200}).json()["days"] == 200  # increases apply directly
    cr = r["pending_approval"]
    assert admin2.post(f"/api/approvals/changes/{cr}/decision", {"decision": "approve", "reason": "policy review"}).status_code == 200
    with dbmod.session_scope() as db:
        assert db.get(ApprovalRequest, cr).status == "applied"


def test_sla_policy_versioning(admin, make_session):
    targets = {s: {"ack_minutes": 5 + i, "resolve_minutes": 60 + i} for i, s in enumerate(["info", "low", "medium", "high", "critical"])}
    assert admin.put("/api/admin/sla", {"targets": targets}).json()["version"] == 2
    bad = dict(targets, high={"ack_minutes": 100, "resolve_minutes": 10})
    assert admin.put("/api/admin/sla", {"targets": bad}).status_code == 400
    assert admin.put("/api/admin/sla", {"targets": {"high": {"ack_minutes": 1, "resolve_minutes": 2}}}).status_code == 400
    assert make_session("v@t.local", "viewer").get("/api/admin/sla").json()["version"] == 2


def test_setup_bootstrap_single_use(app):
    c = TestClient(app, client=("10.0.0.5", 1))
    body = {"token": "bootstrap-secret-value", "email": "first@t.local", "password": PASSWORD}
    assert c.post("/api/setup/admin", json={**body, "token": "wrong-token"}).status_code == 404
    r = c.post("/api/setup/admin", json=body)
    assert r.status_code == 201 and r.json()["totp_secret"]
    assert c.post("/api/setup/admin", json={**body, "email": "second@t.local"}).status_code == 409
    assert c.get("/api/setup/status").json()["steps"]["admin"] is True


def test_metrics_endpoint_protected(app):
    c = TestClient(app, client=("10.0.0.5", 1))
    assert c.get("/api/metrics").status_code == 404
    assert c.get("/api/metrics", headers={"Authorization": "Bearer nope"}).status_code == 404
    r = c.get("/api/metrics", headers={"Authorization": "Bearer metrics-secret"})
    assert r.status_code == 200 and "soc_outbox_pending" in r.text


def test_health_and_docs(admin, app):
    h = admin.get("/api/admin/health").json()
    assert h["database"] == "ok" and h["api"] == "ok"
    assert TestClient(app).get("/healthz").json() == {"status": "ok"}
