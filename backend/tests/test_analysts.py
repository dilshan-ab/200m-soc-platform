from __future__ import annotations

from datetime import timedelta

from app import db as dbmod
from app.models import Alert, Case, utcnow
from tests.conftest import make_user
from tests.helpers import mk_alert


def test_analyst_performance_aggregates_mtta_mttr_and_cases(make_session, clients):
    client_id = clients[0]
    analyst_id, _ = make_user("analyst@t.local", "l1")
    now = utcnow()

    a1 = mk_alert(client_id, "Brute force", severity="high")
    a2 = mk_alert(client_id, "Malware beacon", severity="critical")
    with dbmod.session_scope() as db:
        alert1 = db.get(Alert, a1)
        alert1.assignee_id = analyst_id
        alert1.first_seen = now - timedelta(minutes=30)
        alert1.acknowledged_at = now - timedelta(minutes=20)  # 10 min MTTA
        alert1.resolved_at = now - timedelta(minutes=5)  # 25 min MTTR
        alert1.sla_breached = False
        alert2 = db.get(Alert, a2)
        alert2.assignee_id = analyst_id
        alert2.first_seen = now - timedelta(minutes=40)
        alert2.acknowledged_at = now - timedelta(minutes=10)  # 30 min MTTA
        alert2.sla_breached = True

        case = Case(number=1, title="Test case", severity="high", status="closed", owner_id=analyst_id, client_id=client_id,
                    created_at=now - timedelta(hours=2), closed_at=now - timedelta(hours=1))  # 60 min case MTTR
        db.add(case)

    viewer = make_session("v@t.local", "viewer")
    assert viewer.get("/api/analysts/performance").status_code == 403  # viewer lacks metrics.read

    l1 = make_session("l1viewer@t.local", "l1")
    r = l1.get("/api/analysts/performance", params={"days": 7})
    assert r.status_code == 200
    body = r.json()
    rows = {row["id"]: row for row in body["analysts"]}
    me = rows[analyst_id]
    assert me["alerts_assigned"] == 2 and me["alerts_acknowledged"] == 2 and me["alerts_resolved"] == 1
    assert me["alerts_breached"] == 1 and me["critical_high_handled"] == 2
    assert me["mtta_minutes"] == 20.0  # average of 10 and 30
    assert me["mttr_minutes"] == 25.0
    assert me["cases_owned"] == 1 and me["cases_closed"] == 1
    assert me["case_mttr_minutes"] == 60.0
    assert body["team"]["analysts_active"] == 1
