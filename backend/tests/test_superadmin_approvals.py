from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from app import db as dbmod
from app.api.approvals import create_change
from app.models import ActionRequest, Approval, ApprovalRequest, AuditEvent, RetentionPolicy, SessionRecord, Tool, User, utcnow
from app.services.response import create_request
from tests.helpers import mk_tool


def uid(s):
    return s.get('/api/auth/me').json()['id']


def change(s, kind='retention.update', payload=None):
    user_id = uid(s)
    with dbmod.session_scope() as db:
        return create_change(db, kind, payload or {'dataset': 'alerts', 'days': 30, 'legal_hold': False}, db.get(User, user_id), 'Existing pending request', required=2).id


def legacy_action(s):
    user_id = uid(s)
    with dbmod.session_scope() as db:
        return create_request(db, requester=db.get(User, user_id), action_key='disable_account', targets=['jdoe'], params={}, reason='Previously submitted request').id


def action(s):
    return s.post('/api/response/requests', {'action_key': 'disable_account', 'targets': ['jdoe'], 'reason': 'Owner requested response'})


def decision(s, kind, id_, value='approve'):
    path = f'/api/approvals/changes/{id_}' if kind == 'change' else f'/api/response/requests/{id_}'
    return s.post(path + '/decision', {'decision': value, 'reason': 'Owner reviewed request'})


def test_owner_promotes_admin_and_supersedes_pending(superadmin, make_session):
    target = uid(make_session('target@t.local', 'l2'))
    old = change(superadmin, 'user.role', {'user_id': target, 'role': 'admin'})
    r = superadmin.patch(f'/api/admin/users/{target}', {'role': 'admin'})
    assert r.status_code == 200 and r.json()['role'] == 'admin', r.text
    assert 'pending_approval' not in r.json()
    assert not superadmin.get('/api/approvals').json()['changes']
    with dbmod.session_scope() as db:
        assert db.get(ApprovalRequest, old).status == 'superseded'
        assert db.query(AuditEvent).filter_by(action='change.supersede', resource_id=old).one().meta['superadmin_override']


def test_owner_reduces_retention_and_removes_hold(superadmin):
    with dbmod.session_scope() as db:
        p = db.query(RetentionPolicy).filter_by(dataset='alerts').one()
        p.days, p.legal_hold = 180, True
    old = change(superadmin)
    r = superadmin.put('/api/admin/retention', {'dataset': 'alerts', 'days': 30, 'legal_hold': False})
    assert r.status_code == 200 and r.json()['days'] == 30, r.text
    assert 'pending_approval' not in r.json()
    with dbmod.session_scope() as db:
        assert db.get(ApprovalRequest, old).status == 'superseded'
        assert db.query(RetentionPolicy).filter_by(dataset='alerts').one().legal_hold is False


def test_owner_creates_missing_retention_policy(superadmin):
    with dbmod.session_scope() as db:
        db.query(RetentionPolicy).filter_by(dataset='reports').delete()
    r = superadmin.put('/api/admin/retention', {'dataset': 'reports', 'days': 30})
    assert r.status_code == 200 and r.json()['dataset'] == 'reports', r.text


def test_owner_enables_action_tool_and_clears_pending(superadmin):
    tool = mk_tool('wazuh_manager', 'owner-tool', enabled=False, last_test={'ok': True, 'config_version': 1})
    old = change(superadmin, 'tool.enable', {'tool_id': tool, 'config_version': 1})
    r = superadmin.post(f'/api/integrations/tools/{tool}/enable')
    assert r.status_code == 200 and r.json()['enabled'] is True, r.text
    with dbmod.session_scope() as db:
        assert db.get(ApprovalRequest, old).status == 'superseded'
        assert db.query(AuditEvent).filter_by(action='tool.enable', resource_id=tool).one().meta['superadmin_override']
    assert decision(superadmin, 'change', old).status_code == 409


def test_owner_still_needs_successful_connection_test(superadmin):
    tool = mk_tool('wazuh_manager', 'untested', enabled=False)
    assert superadmin.post(f'/api/integrations/tools/{tool}/enable').status_code == 409
    with dbmod.session_scope() as db:
        assert db.get(Tool, tool).enabled is False


@pytest.mark.parametrize('value,status', [('approve', 'applied'), ('reject', 'rejected')])
def test_owner_decides_own_existing_change(superadmin, value, status):
    r = decision(superadmin, 'change', change(superadmin), value)
    assert r.status_code == 200 and r.json()['status'] == status, r.text
    assert not superadmin.get('/api/approvals').json()['changes']


def test_owner_finishes_another_admins_two_approval_change(superadmin, admin):
    r = decision(superadmin, 'change', change(admin))
    assert r.status_code == 200 and r.json()['status'] == 'applied', r.text


def test_admin_cannot_decide_own_change(admin):
    assert decision(admin, 'change', change(admin)).status_code == 403


def test_owner_response_needs_no_peer_and_is_audited(superadmin):
    r = action(superadmin)
    assert r.status_code == 201 and r.json()['status'] == 'approved', r.text
    assert r.json()['approvals_required'] == 0
    assert not superadmin.get('/api/approvals').json()['actions']
    with dbmod.session_scope() as db:
        assert db.query(AuditEvent).filter_by(action='response.request', resource_id=r.json()['id']).one().meta['superadmin_override']
    assert next(a for a in superadmin.get('/api/response/catalogue').json() if a['key'] == 'disable_account')['approvals'] == 0


@pytest.mark.parametrize('own', [True, False])
def test_owner_can_resolve_legacy_critical_action(superadmin, admin, own):
    old = legacy_action(superadmin if own else admin)
    r = decision(superadmin, 'action', old)
    assert r.status_code == 200 and r.json()['status'] == 'approved', r.text
    assert decision(superadmin, 'action', old).status_code == 409


def test_owner_api_token_does_not_bypass_approval(superadmin, app):
    token = superadmin.post('/api/tokens', {'name': 'limited', 'scopes': ['response.request', 'response.read'], 'days': 1}).json()['token']
    client = TestClient(app)
    headers = {'Authorization': f'Bearer {token}'}
    r = client.post('/api/response/requests', headers=headers, json={'action_key': 'disable_account', 'targets': ['jdoe'], 'reason': 'Token requested response'})
    assert r.status_code == 201 and r.json()['status'] == 'pending_approval', r.text
    assert r.json()['approvals_required'] == 2
    assert next(a for a in client.get('/api/response/catalogue', headers=headers).json() if a['key'] == 'disable_account')['approvals'] == 2


def test_granted_capabilities_do_not_confer_owner_bypass(make_session):
    viewer = make_session('granted@t.local', 'viewer')
    user_id = uid(viewer)
    with dbmod.session_scope() as db:
        db.get(User, user_id).grants = ['response.request']
    r = action(viewer)
    assert r.status_code == 201 and r.json()['status'] == 'pending_approval', r.text


def test_owner_still_needs_recent_mfa(superadmin):
    user_id = uid(superadmin)
    with dbmod.session_scope() as db:
        for row in db.query(SessionRecord).filter_by(user_id=user_id):
            row.step_up_until = utcnow() - timedelta(minutes=1)
    assert action(superadmin).status_code == 403
    assert superadmin.put('/api/admin/retention', {'dataset': 'alerts', 'days': 30}).status_code == 403


@pytest.mark.parametrize('invalid', ['expired', 'tampered'])
def test_owner_cannot_apply_invalid_change(superadmin, invalid):
    old = change(superadmin)
    with dbmod.session_scope() as db:
        row = db.get(ApprovalRequest, old)
        if invalid == 'expired':
            row.expires_at = utcnow() - timedelta(minutes=1)
        else:
            row.payload = {**row.payload, 'days': 999}
    assert decision(superadmin, 'change', old).status_code == 409


def test_owner_still_obeys_retention_validation(superadmin):
    assert superadmin.put('/api/admin/retention', {'dataset': 'audit', 'days': 1}).status_code == 400


def test_owner_can_finish_a_legacy_request_they_already_partially_approved(superadmin):
    old = legacy_action(superadmin)
    owner = uid(superadmin)
    with dbmod.session_scope() as db:
        row = db.get(ActionRequest, old)
        db.add(Approval(request_id=old, approver_id=owner, decision='approve', reason='Previous first approval', payload_hash=row.payload_hash))
    r = decision(superadmin, 'action', old)
    assert r.status_code == 200 and r.json()['status'] == 'approved', r.text
    with dbmod.session_scope() as db:
        assert db.query(Approval).filter_by(request_id=old, approver_id=owner).count() == 1
