from sqlalchemy import select

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
    assert result.status_code == 200 and result.json() == {'deleted': 1}
    assert scoped.get(f'/api/alerts/{a}').status_code == 404
    with dbmod.session_scope() as db:
        assert db.get(Alert, b) is not None  # out-of-scope alert untouched

    result = admin.post('/api/alerts/delete-all', {})
    assert result.status_code == 200 and result.json() == {'deleted': 1}
    with dbmod.session_scope() as db:
        assert db.get(Alert, b) is None


def test_delete_all_alerts_respects_legal_hold(admin):
    mk_alert()
    with dbmod.session_scope() as db:
        policy = db.execute(select(RetentionPolicy).where(RetentionPolicy.dataset == 'alerts')).scalar_one()
        policy.legal_hold = True
    assert admin.post('/api/alerts/delete-all', {}).status_code == 409
