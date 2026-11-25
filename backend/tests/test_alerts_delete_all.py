from sqlalchemy import func, select

from app import db as dbmod
from app.models import Alert, RetentionPolicy
from tests.helpers import mk_alert


def test_delete_all_alerts_requires_capability_and_is_scoped(admin, make_session, clients):
    a = mk_alert(client_id=clients[0])
    b = mk_alert(client_id=clients[1], rule_id='other')
    analyst = make_session('delete-all-analyst@t.local', 'l2')
    assert analyst.post('/api/alerts/delete-all', {}).status_code == 403

    scoped = make_session('delete-all-scoped@t.local', 'admin', all_clients=False, client_ids=[clients[0]])
    result = scoped.post('/api/alerts/delete-all', {})
    assert result.status_code == 200 and result.json() == {'deleted': 1, 'remaining': 0}
    assert scoped.get(f'/api/alerts/{a}').status_code == 404
    with dbmod.session_scope() as db:
        assert db.get(Alert, b) is not None  # out-of-scope alert untouched

    result = admin.post('/api/alerts/delete-all', {})
    assert result.status_code == 200 and result.json() == {'deleted': 1, 'remaining': 0}
    with dbmod.session_scope() as db:
        assert db.get(Alert, b) is None


def test_delete_all_alerts_respects_legal_hold(admin):
    mk_alert()
    with dbmod.session_scope() as db:
        policy = db.execute(select(RetentionPolicy).where(RetentionPolicy.dataset == 'alerts')).scalar_one()
        policy.legal_hold = True
    assert admin.post('/api/alerts/delete-all', {}).status_code == 409


def test_delete_all_alerts_works_in_batches(admin, monkeypatch):
    """One call deletes a bounded batch and reports what is left, so a big workspace is cleared over several short requests."""
    from app.api import alerts as alerts_api

    monkeypatch.setattr(alerts_api, 'DELETE_ALL_BATCH', 2)
    ids = [mk_alert(rule_id=f'r{i}', title=f'bulk {i}') for i in range(5)]
    seen = []
    for _ in range(10):
        r = admin.post('/api/alerts/delete-all', {}).json()
        seen.append((r['deleted'], r['remaining']))
        if r['remaining'] == 0:
            break
    assert seen == [(2, 3), (2, 1), (1, 0)]
    with dbmod.session_scope() as db:
        assert all(db.get(Alert, i) is None for i in ids)
    assert admin.post('/api/alerts/delete-all', {}).json() == {'deleted': 0, 'remaining': 0}  # nothing left is not an error


def test_delete_all_alerts_writes_one_audit_entry_per_alert(admin, monkeypatch):
    from app.api import alerts as alerts_api
    from app.models import AuditEvent

    monkeypatch.setattr(alerts_api, 'DELETE_ALL_BATCH', 2)
    mk_alert(rule_id='a1'), mk_alert(rule_id='a2'), mk_alert(rule_id='a3')
    while admin.post('/api/alerts/delete-all', {}).json()['remaining']:
        pass
    with dbmod.session_scope() as db:
        assert db.execute(select(func.count()).select_from(AuditEvent).where(AuditEvent.action == 'alert.delete')).scalar_one() == 3


def test_a_full_batch_is_set_based_and_keeps_the_audit_chain_intact(admin):
    """A 1,000-alert batch must finish quickly (the live site hit the proxy's 100 s timeout on 300) without losing the
    one-audit-entry-per-alert record or breaking the hash chain."""
    import time

    from app import audit
    from app.models import AuditEvent, Outbox, utcnow

    with dbmod.session_scope() as db:
        now = utcnow()
        db.add_all([Alert(source='wazuh_indexer', source_id=f'bulk-{i}', title=f'scan {i}', severity='low', time=now, first_seen=now, last_seen=now,
                          dedup_key=f'bulk-{i}') for i in range(1000)])
    started = time.monotonic()
    result = admin.post('/api/alerts/delete-all', {}).json()
    elapsed = time.monotonic() - started
    assert result == {'deleted': 1000, 'remaining': 0}
    assert elapsed < 20, elapsed
    with dbmod.session_scope() as db:
        assert db.execute(select(func.count()).select_from(Alert)).scalar_one() == 0
        assert db.execute(select(func.count()).select_from(AuditEvent).where(AuditEvent.action == 'alert.delete')).scalar_one() == 1000
        assert audit.verify_chain(db)['ok'] is True
        deleted_events = [row.payload for row in db.execute(select(Outbox).where(Outbox.kind == 'event')).scalars() if row.payload.get('type') == 'alert.deleted']
        assert len(deleted_events) == 1 and deleted_events[0]['count'] == 1000  # one per client in the batch, not one per alert
