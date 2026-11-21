"""Account management rights are broad for admins; owner identity remains protected."""
import pytest

from tests.conftest import PASSWORD


@pytest.mark.parametrize('body', [
    {'name': 'Changed'}, {'email': 'changed@t.local'}, {'role': 'viewer'},
    {'active': False}, {'all_clients': False}, {'client_ids': []},
    {'grants': ['alerts.read']}, {'denied': ['admin.users']},
])
def test_admin_cannot_edit_owner(admin, superadmin, body):
    uid = superadmin.get('/api/auth/me').json()['id']
    assert admin.patch(f'/api/admin/users/{uid}', body).status_code == 403
    assert superadmin.get('/api/auth/me').status_code == 200


def test_admin_cannot_reset_provision_or_sign_out_owner(admin, superadmin):
    uid = superadmin.get('/api/auth/me').json()['id']
    for action in ('password', 'provision'):
        assert admin.post(f'/api/admin/users/{uid}/{action}', {'password': PASSWORD}).status_code == 403
    assert admin.post(f'/api/admin/users/{uid}/revoke-sessions').status_code == 403
    token = superadmin.post('/api/tokens', {'name': 'Owner token', 'scopes': ['alerts.read']}).json()['id']
    assert admin.delete(f'/api/tokens/{token}').status_code == 403
    assert not next(t for t in superadmin.get('/api/tokens').json() if t['id'] == token)['revoked']


def test_lower_roles_cannot_manage_users(make_session, admin):
    actor = make_session('l2@t.local', 'l2')
    target = make_session('viewer@t.local', 'viewer')
    uid = target.get('/api/auth/me').json()['id']
    assert actor.patch(f'/api/admin/users/{uid}', {'name': 'Changed'}).status_code == 403
    assert actor.post(f'/api/admin/users/{uid}/password', {'password': PASSWORD}).status_code == 403
    assert actor.post('/api/admin/users', {'email': 'new@t.local', 'password': PASSWORD}).status_code == 403


def test_admin_changes_permissions_and_email_revokes_target_session(admin, make_session):
    target = make_session('viewer@t.local', 'viewer')
    uid = target.get('/api/auth/me').json()['id']
    r = admin.patch(f'/api/admin/users/{uid}', {'email': 'new@t.local', 'name': 'New Name', 'grants': ['alerts.triage'], 'all_clients': False})
    assert r.status_code == 200, r.text
    assert r.json()['email'] == 'new@t.local' and r.json()['grants'] == ['alerts.triage']
    assert target.get('/api/auth/me').status_code == 401


def test_email_collision_does_not_change_account(admin, make_session):
    target = make_session('viewer@t.local', 'viewer')
    uid = target.get('/api/auth/me').json()['id']
    email = admin.get('/api/auth/me').json()['email']
    assert admin.patch(f'/api/admin/users/{uid}', {'email': email}).status_code == 409
    assert target.get('/api/auth/me').json()['email'] == 'viewer@t.local'
