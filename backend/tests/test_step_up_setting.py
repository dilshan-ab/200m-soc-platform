"""Re-verification (step-up MFA) for sensitive admin actions is off by default and can be switched on."""
from __future__ import annotations

from datetime import timedelta

from fastapi.testclient import TestClient

from app import db as dbmod
from app.models import SessionRecord, utcnow
from tests.conftest import PASSWORD


def _expire_step_up():
    with dbmod.session_scope() as db:
        for rec in db.query(SessionRecord).all():
            rec.step_up_until = utcnow() - timedelta(minutes=5)


def test_admin_actions_do_not_ask_for_re_verification_by_default(superadmin, make_session):
    target = make_session("t@t.local", "viewer")
    _expire_step_up()
    me = superadmin.get("/api/auth/me").json()
    assert me["step_up_required"] is False
    r = superadmin.post("/api/admin/users", {"email": "n@t.local", "role": "viewer", "password": PASSWORD})
    assert r.status_code == 201, r.text
    uid = target.get("/api/auth/me").json()["id"]
    assert superadmin.post(f"/api/admin/users/{uid}/revoke-sessions").status_code == 200
    assert superadmin.put("/api/admin/retention", {"dataset": "alerts", "days": 30}).status_code != 403


def test_api_tokens_still_cannot_perform_these_actions(superadmin, app):
    token = superadmin.post("/api/tokens", {"name": "limited", "scopes": ["users.provision", "admin.users"], "days": 1}).json()["token"]
    r = TestClient(app).post("/api/admin/users", headers={"Authorization": f"Bearer {token}"}, json={"email": "x@t.local", "role": "viewer", "password": PASSWORD})
    assert r.status_code == 403  # an interactive session is still required


def test_setting_it_on_brings_the_requirement_back(superadmin, step_up_on):
    _expire_step_up()
    assert superadmin.get("/api/auth/me").json()["step_up_required"] is True
    r = superadmin.post("/api/admin/users", {"email": "n@t.local", "role": "viewer", "password": PASSWORD})
    assert r.status_code == 403 and r.json()["detail"]["code"] == "step_up_required"
