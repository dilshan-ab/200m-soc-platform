from app import db as dbmod
from app.models import Asset, User
from tests.helpers import mk_alert


def test_workspace_search_scopes_every_result_type(superadmin, clients, make_session):
    own, other = clients
    alert = mk_alert(client_id=own, title='Needle alert')
    mk_alert(client_id=other, title='Needle outside', rule_id='outside')
    case = superadmin.post('/api/cases', {'title': 'Needle case', 'client_id': own}).json()['id']
    superadmin.post('/api/cases', {'title': 'Needle outside case', 'client_id': other})
    with dbmod.session_scope() as db:
        asset = Asset(name='Needle device', hostname='needle-host', client_id=own)
        db.add_all([asset, Asset(name='Needle outside device', client_id=other)])
        db.flush()
        asset_id = asset.id
    analyst = make_session('workspace-search@t.local', 'l1', all_clients=False, client_ids=[own])
    result = analyst.get('/api/search?q=Needle').json()
    assert [row['id'] for row in result['alerts']] == [alert]
    assert [row['id'] for row in result['cases']] == [case]
    assert [row['id'] for row in result['assets']] == [asset_id]
    assert analyst.get('/api/search?q=needle-host').json()['assets'][0]['id'] == asset_id


def test_workspace_search_respects_each_capability(admin, superadmin):
    alert = mk_alert(title='Lookup alert')
    assert superadmin.post('/api/cases', {'title': 'Lookup case'}).status_code == 201
    uid = admin.get('/api/auth/me').json()['id']
    with dbmod.session_scope() as db:
        db.add(Asset(name='Lookup device'))
        user = db.get(User, uid)
        user.denied = ['cases.read', 'assets.read']
    result = admin.get('/api/search?q=Lookup').json()
    assert [row['id'] for row in result['alerts']] == [alert]
    assert result['cases'] == result['assets'] == []
    with dbmod.session_scope() as db:
        user = db.get(User, uid)
        user.denied = ['alerts.read']
    result = admin.get('/api/search?q=Lookup').json()
    assert result['alerts'] == []
    assert len(result['cases']) == len(result['assets']) == 1


def test_workspace_search_handles_short_and_oversized_queries(admin):
    assert admin.get('/api/search?q=x').json() == {'alerts': [], 'cases': [], 'assets': []}
    assert admin.get('/api/search', params={'q': 'x' * 201}).status_code == 422
