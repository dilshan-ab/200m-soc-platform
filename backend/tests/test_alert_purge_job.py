from __future__ import annotations

from datetime import timedelta

from sqlalchemy import func, select

from app import audit
from app import db as dbmod
from app.db import session_factory
from app.models import Alert, AlertReceipt, AuditEvent, Outbox, RetentionPolicy, utcnow
from app.services import events
from tests.helpers import mk_alert


def _drain(rounds=20):
    for _ in range(rounds):
        if not events.dispatch_once(session_factory()):
            break


def _add_alerts(n, client_id=None, prefix='p'):
    with dbmod.session_scope() as db:
        now = utcnow()
        db.add_all([Alert(source='wazuh_indexer', source_id=f'{prefix}-{i}', title=f'scan {i}', severity='low', time=now, first_seen=now,
                          last_seen=now, dedup_key=f'{prefix}-{i}', client_id=client_id) for i in range(n)])


def test_background_purge_deletes_everything_in_scope_in_batches(superadmin, monkeypatch):
    from app.api import alerts as alerts_api

    monkeypatch.setattr(alerts_api, 'DELETE_ALL_BATCH', 40)
    _add_alerts(100)
    started = superadmin.post('/api/alerts/delete-all/background', {})
    assert started.status_code == 202 and started.json()['status'] == 'running' and started.json()['remaining'] == 100
    # A second start while running returns the same job instead of starting another.
    assert superadmin.post('/api/alerts/delete-all/background', {}).json()['started_at'] == started.json()['started_at']
    _drain()
    status = superadmin.get('/api/alerts/delete-all/status').json()
    assert status['status'] == 'done' and status['deleted'] == 100 and status['remaining'] == 0
    with dbmod.session_scope() as db:
        assert db.execute(select(func.count()).select_from(Alert)).scalar_one() == 0
        assert db.execute(select(func.count()).select_from(AuditEvent).where(AuditEvent.action == 'alert.delete')).scalar_one() == 100
        actions = set(db.execute(select(AuditEvent.action).where(AuditEvent.action.like('alert.purge%'))).scalars())
        assert actions == {'alert.purge.start', 'alert.purge.finish'}
        assert audit.verify_chain(db)['ok'] is True


def test_background_purge_respects_scope_capability_and_legal_hold(superadmin, make_session, clients):
    _add_alerts(3, client_id=clients[0], prefix='a')
    _add_alerts(2, client_id=clients[1], prefix='b')
    analyst = make_session('purge-analyst@t.local', 'l2')
    assert analyst.post('/api/alerts/delete-all/background', {}).status_code == 403
    scoped = make_session('purge-scoped@t.local', 'superadmin', all_clients=False, client_ids=[clients[0]])
    assert scoped.post('/api/alerts/delete-all/background', {}).json()['remaining'] == 3
    _drain()
    with dbmod.session_scope() as db:
        left = db.execute(select(Alert.client_id)).scalars().all()
        assert sorted(left) == [clients[1], clients[1]]
        db.execute(select(RetentionPolicy).where(RetentionPolicy.dataset == 'alerts')).scalar_one().legal_hold = True
    assert superadmin.post('/api/alerts/delete-all/background', {}).status_code == 409


def test_maintenance_prunes_old_receipts_and_finished_outbox_rows():
    from app.workers.runner import prune_bookkeeping

    aid = mk_alert()
    with dbmod.session_scope() as db:
        now = utcnow()
        db.add_all([
            AlertReceipt(tool_id='t', source_id='old', alert_id=aid, received_at=now - timedelta(days=30)),
            AlertReceipt(tool_id='t', source_id='new', alert_id=aid, received_at=now - timedelta(days=1)),
            Outbox(kind='event', payload={}, status='done', created_at=now - timedelta(days=10)),
            Outbox(kind='event', payload={}, status='pending', created_at=now - timedelta(days=10)),
            Outbox(kind='event', payload={}, status='done', created_at=now),
        ])
    out = prune_bookkeeping()
    assert out['receipts'] == 1 and out['outbox'] == 1
    with dbmod.session_scope() as db:
        assert db.execute(select(AlertReceipt.source_id).where(AlertReceipt.tool_id == 't')).scalars().all() == ['new']
        assert db.execute(select(func.count()).select_from(Outbox).where(Outbox.status == 'pending')).scalar_one() >= 1


def test_delete_all_skips_alerts_a_racing_batch_already_removed(superadmin):
    """After a proxy timeout the earlier batch can still be finishing; the retry must not fail on the alerts it took."""
    from app.api.alerts import _delete_alerts
    from app.deps import Principal
    from app.models import User

    keep_going = mk_alert(rule_id='race-1')
    with dbmod.session_scope() as db:
        user = db.execute(select(User).where(User.role == 'superadmin')).scalars().first() or db.execute(select(User)).scalars().first()
        p = Principal(user=user, session=None, token=None, client_ids=None, ip='', correlation_id='t')
        assert _delete_alerts(db, p, [keep_going, 'already-gone'], strict=False) == 1
        assert _delete_alerts(db, p, ['already-gone'], strict=False) == 0
