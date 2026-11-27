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
        for first, second in zip(response['series'], response['series'][1:], strict=False):
            end = datetime.fromisoformat(first['until'].replace('Z', '+00:00'))
            start = datetime.fromisoformat(second['since'].replace('Z', '+00:00'))
            assert end < start


def test_triage_claim_keeps_owner_and_records_investigation_activity(make_session, clients):
    client_id, other_client_id = clients
    analyst = make_session('triage-owner@t.local', 'l1', all_clients=False, client_ids=[client_id])
    teammate = make_session('triage-teammate@t.local', 'l1', all_clients=False, client_ids=[client_id])
    alert_id = mk_alert(client_id, title='Investigation alert', username='sam')
    mk_alert(client_id, title='Similar user', username='samuel')
    mk_alert(other_client_id, title='Other client', username='sam')
    route = f'/api/alerts/{alert_id}'
    alert = analyst.get(route).json()

    claimed = analyst.patch(route, {'version': alert['version'], 'claim': True, 'status': 'acknowledged'})
    assert claimed.status_code == 200
    version = claimed.json()['version']
    assert teammate.patch(route, {'version': version, 'claim': True, 'status': 'investigating'}).status_code == 409
    assert analyst.patch(route, {'version': version, 'claim': True, 'status': 'investigating'}).status_code == 200

    mine = analyst.get('/api/alerts/queue', params={'mine': True}).json()['items']
    assert [(row['id'], row['status']) for row in mine] == [(alert_id, 'investigating')]
    assert mine[0]['assignee_name'] and mine[0]['acknowledged_at'] and mine[0]['resolve_due']
    assert teammate.get('/api/alerts/queue', params={'mine': True}).json()['items'] == []

    activity = analyst.get(route).json()['activity']
    assert [(event['status'], event['assigned']) for event in activity] == [
        ('investigating', False), ('acknowledged', True),
    ]
    matches = analyst.get('/api/alerts', params={'username': 'sam'}).json()['items']
    assert [row['id'] for row in matches] == [alert_id]


def test_l2_dashboard_matches_scoped_alerts_and_active_cases(admin, make_session, clients):
    client, other_client = clients
    analyst = make_session("dashboard-l2@t.local", "l2", all_clients=False, client_ids=[client])
    mk_alert(client, title="In scope", severity="low")
    mk_alert(other_client, title="Other client", severity="critical")
    assert admin.post("/api/cases", {"title": "Other client case", "client_id": other_client}).status_code == 201
    created = analyst.post("/api/cases", {"title": "L2 investigation", "client_id": client})
    assert created.status_code == 201

    dashboard = analyst.get("/api/dashboard", params={"days": 1}).json()
    assert sum(bucket["alerts"] for bucket in dashboard["series"]) == 1
    assert dashboard["metrics"]["alerts_by_severity"]["low"] == 1
    assert dashboard["metrics"]["open_cases"] == 1
    active = analyst.get("/api/cases", params={"status": ["open", "in_progress"]}).json()
    assert [case["id"] for case in active["items"]] == [created.json()["id"]]
