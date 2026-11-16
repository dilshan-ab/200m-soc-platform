from datetime import timedelta

from sqlalchemy import select

from app import db as dbmod
from app.models import ActionRequest, Alert, AlertReceipt, AuditEvent, CaseEvidence, EnrichmentJob, Incident, NotificationDelivery, RetentionPolicy, ShiftHandoff, WarRoomMessage, utcnow
from tests.helpers import mk_alert


def test_creator_can_delete_shared_warroom_and_its_messages(make_session, clients):
    lead = make_session('lead-delete@t.local', 'l1', all_clients=False, client_ids=[clients[0]])
    room = lead.post('/api/warrooms', {'title': 'Temporary war room'})
    assert room.status_code == 201
    wid = room.json()['id']
    assert lead.get(f'/api/warrooms/{wid}').status_code == 200
    assert lead.post(f'/api/warrooms/{wid}/messages', {'content': 'An update'}).status_code == 201
    assert lead.delete(f'/api/warrooms/{wid}').status_code == 204
    assert lead.get(f'/api/warrooms/{wid}').status_code == 404
    assert lead.get('/api/warrooms').json() == []
    with dbmod.session_scope() as db:
        assert db.execute(select(WarRoomMessage).where(WarRoomMessage.war_room_id == wid)).first() is None
        assert db.execute(select(AuditEvent).where(AuditEvent.action == 'warroom.delete', AuditEvent.resource_id == wid)).first() is not None


def test_warroom_delete_permissions_and_scope(make_session, clients):
    lead = make_session('room-owner@t.local', 'l1')
    peer = make_session('room-peer@t.local', 'l1')
    manager = make_session('room-manager@t.local', 'l2')
    scoped = make_session('room-scoped@t.local', 'l2', all_clients=False, client_ids=[clients[0]])
    wid = lead.post('/api/warrooms', {'title': 'Shared room'}).json()['id']
    assert peer.delete(f'/api/warrooms/{wid}').status_code == 403
    assert manager.delete(f'/api/warrooms/{wid}').status_code == 204
    private = lead.post('/api/warrooms', {'title': 'Client room', 'client_id': clients[1]}).json()['id']
    assert scoped.delete(f'/api/warrooms/{private}').status_code == 404
    assert scoped.post('/api/warrooms', {'title': 'Out of scope', 'client_id': clients[1]}).status_code == 403


def test_alert_deletion_requires_capability(admin, make_session):
    aid = mk_alert()
    analyst = make_session('alert-delete-analyst@t.local', 'l2')
    assert analyst.delete(f'/api/alerts/{aid}').status_code == 403
    assert analyst.post('/api/alerts/bulk-delete', {'ids': [aid]}).status_code == 403
    assert admin.delete(f'/api/alerts/{aid}').status_code == 204
    assert admin.get(f'/api/alerts/{aid}').status_code == 404
    assert admin.delete(f'/api/alerts/{aid}').status_code == 404


def test_alert_deletion_cleans_links_and_preserves_related_records(admin, clients):
    aid = mk_alert(client_id=clients[0])
    other = mk_alert(client_id=clients[0], title='Remaining alert', rule_id='another')
    case_id = admin.post('/api/alerts/to-case', {'alert_ids': [aid]}).json()['id']
    uid = admin.get('/api/auth/me').json()['id']
    with dbmod.session_scope() as db:
        request = ActionRequest(action_key='block_ip', requester_id=uid, alert_id=aid, client_id=clients[0], payload_hash='test', expires_at=utcnow() + timedelta(hours=1))
        evidence = CaseEvidence(case_id=case_id, name='Collected log', alert_id=aid)
        enrichment = EnrichmentJob(indicator='203.0.113.7', indicator_type='ip', requester_id=uid, alert_id=aid)
        notice = NotificationDelivery(destination_id='destination', event_ref='event', dedupe_key='delete-test', alert_id=aid)
        receipt = AlertReceipt(tool_id='tool', source_id='event', alert_id=aid)
        incident = Incident(name='Correlated incident', client_id=clients[0], alert_ids=[aid, other], alert_count=2)
        handoff = ShiftHandoff(created_by=uid, client_id=clients[0], alert_ids=[aid, other])
        db.add_all([request, evidence, enrichment, notice, receipt, incident, handoff])
        db.flush()
        references = [(type(row), row.id) for row in [request, evidence, enrichment, notice, receipt]]
        iid, hid = incident.id, handoff.id
    assert admin.delete(f'/api/alerts/{aid}').status_code == 204
    with dbmod.session_scope() as db:
        for model, rid in references:
            assert db.get(model, rid).alert_id is None
        incident = db.get(Incident, iid)
        assert incident.alert_ids == [other] and incident.alert_count == 1
        assert incident.first_alert_time == incident.last_alert_time == db.get(Alert, other).time
        assert db.get(ShiftHandoff, hid).alert_ids == [other]
        assert db.execute(select(AuditEvent).where(AuditEvent.action == 'alert.delete', AuditEvent.resource_id == aid)).first() is not None
    detail = admin.get(f'/api/cases/{case_id}').json()
    assert detail['alerts'] == []
    assert detail['evidence'][0]['name'] == 'Collected log'
    assert any(entry['kind'] == 'alert' and aid == entry['meta'].get('alert_id') for entry in detail['timeline'])


def test_bulk_alert_delete_is_atomic_scoped_and_deduplicated(make_session, clients):
    a = mk_alert(client_id=clients[0])
    b = mk_alert(client_id=clients[1], rule_id='other')
    scoped = make_session('delete-scoped-admin@t.local', 'admin', all_clients=False, client_ids=[clients[0]])
    assert scoped.post('/api/alerts/bulk-delete', {'ids': [a, b]}).status_code == 404
    assert scoped.get(f'/api/alerts/{a}').status_code == 200
    assert scoped.post('/api/alerts/bulk-delete', {'ids': []}).status_code == 422
    result = scoped.post('/api/alerts/bulk-delete', {'ids': [a, a]})
    assert result.status_code == 200 and result.json() == {'deleted': 1}
    with dbmod.session_scope() as db:
        assert db.get(Alert, b) is not None


def test_alert_delete_respects_legal_hold(admin):
    aid = mk_alert()
    with dbmod.session_scope() as db:
        policy = db.execute(select(RetentionPolicy).where(RetentionPolicy.dataset == 'alerts')).scalar_one()
        policy.legal_hold = True
    assert admin.delete(f'/api/alerts/{aid}').status_code == 409
    assert admin.post('/api/alerts/bulk-delete', {'ids': [aid]}).status_code == 409
    assert admin.get(f'/api/alerts/{aid}').status_code == 200
