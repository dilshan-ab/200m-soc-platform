from datetime import datetime
from app import db as dbmod
from app.models import Asset, AuditEvent
from tests.helpers import mk_alert


def asset_id():
    with dbmod.session_scope() as db:
        a = Asset(name='ui-asset', hostname='ui-host', kind='server', criticality='medium')
        db.add(a)
        db.flush()
        return a.id


def test_asset_undo_is_guarded_and_audited(admin):
    id_ = asset_id()
    route = f'/api/assets/{id_}'
    r = admin.patch(route, {'criticality': 'high', 'expected_criticality': 'medium'})
    assert r.status_code == 200 and r.json()['criticality'] == 'high'
    r = admin.patch(route, {'criticality': 'medium', 'expected_criticality': 'high'})
    assert r.status_code == 200 and r.json()['criticality'] == 'medium'
    with dbmod.session_scope() as db:
        assert db.query(AuditEvent).filter_by(action='asset.update', resource_id=id_).count() == 2


def test_asset_undo_does_not_overwrite_a_newer_change(admin):
    id_ = asset_id()
    route = f'/api/assets/{id_}'
    admin.patch(route, {'criticality': 'high', 'expected_criticality': 'medium'})
    admin.patch(route, {'criticality': 'critical'})
    r = admin.patch(route, {'criticality': 'medium', 'expected_criticality': 'high'})
    assert r.status_code == 409
    assert admin.get(route).json()['criticality'] == 'critical'


def test_asset_conditional_patch_still_checks_capability(make_session):
    id_ = asset_id()
    viewer = make_session('viewer-ui@t.local', 'viewer')
    assert viewer.patch(f'/api/assets/{id_}', {'criticality': 'high', 'expected_criticality': 'medium'}).status_code == 403


def test_dashboard_bucket_links_match_chart_counts(admin, clients):
    mk_alert(clients[0])
    for days in (1, 7):
        response = admin.get(f'/api/dashboard?days={days}').json()
        assert response['window']['since'] and response['window']['until']
        for point in response['series']:
            results = admin.get('/api/alerts', params={'since': point['since'], 'until': point['until']}).json()
            assert results['total'] == point['alerts']
            if point['critical']:
                critical = admin.get('/api/alerts', params={'since': point['since'], 'until': point['until'], 'severity': 'critical'}).json()
                assert critical['total'] == point['critical']
        for first, second in zip(response['series'], response['series'][1:]):
            end = datetime.fromisoformat(first['until'].replace('Z', '+00:00'))
            start = datetime.fromisoformat(second['since'].replace('Z', '+00:00'))
            assert end < start
