from __future__ import annotations

import os

# Set SOC_TEST_DATABASE_URL (e.g. postgresql+psycopg://user@host/db) to run the suite on PostgreSQL instead of in-memory SQLite.
# The database is wiped between tests, so point it at a throwaway database.
TEST_DATABASE_URL = os.environ.get("SOC_TEST_DATABASE_URL", "")

os.environ.update({
    "SOC_ENVIRONMENT": "test", "SOC_AUTH_MODE": "dev", "SOC_COOKIE_SECURE": "false", "SOC_DATABASE_URL": TEST_DATABASE_URL or "sqlite://", "SOC_WORKERS_ENABLED": "false",
    "SOC_METRICS_TOKEN": "metrics-secret", "SOC_BOOTSTRAP_TOKEN": "bootstrap-secret-value", "SOC_REPORT_DIR": "/tmp/soc-test-reports",
})

import pyotp  # noqa: E402
import pytest  # noqa: E402
from cryptography.fernet import Fernet  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app import db as dbmod  # noqa: E402
from app import security  # noqa: E402
from app.config import reset_settings_cache  # noqa: E402
from app.connectors import base as cbase  # noqa: E402
from app.models import Client, ClientMembership, User  # noqa: E402
from app.ratelimit import limiter  # noqa: E402
from app.security import hash_password  # noqa: E402
from app.seed import seed_defaults  # noqa: E402
from app.services import events  # noqa: E402
from app.vault import LocalSecretStore, set_secret_store  # noqa: E402

PASSWORD = "Str0ng-Passw0rd!x"


_postgres_ready = False


def _reset_database() -> None:
    """A clean schema for every test: a new in-memory SQLite database, or on PostgreSQL a one-time build then TRUNCATE."""
    global _postgres_ready
    if not TEST_DATABASE_URL:
        dbmod.init_engine("sqlite://")
        dbmod.create_all()
        return
    from sqlalchemy import text

    from app.db import Base

    if not _postgres_ready:
        dbmod.init_engine(TEST_DATABASE_URL)
        Base.metadata.drop_all(dbmod.get_engine())
        dbmod.create_all()
        _postgres_ready = True
    names = ", ".join(f'"{t.name}"' for t in Base.metadata.sorted_tables)
    with dbmod.get_engine().begin() as conn:
        conn.execute(text("SET LOCAL lock_timeout = '10s'"))  # fail fast if a test left a transaction open, instead of hanging
        conn.execute(text(f"TRUNCATE {names} RESTART IDENTITY CASCADE"))


@pytest.fixture(autouse=True)
def fresh(monkeypatch):
    from app.policy import set_role_overrides

    reset_settings_cache()
    _reset_database()
    with dbmod.session_scope() as db:
        seed_defaults(db)
    set_secret_store(LocalSecretStore(Fernet.generate_key().decode()))
    limiter.reset()
    events.set_redis(None)
    set_role_overrides(None)  # PUT /api/admin/permissions sets a process-global; never let it leak across tests
    monkeypatch.setattr(security, "_default_resolve", lambda host: ["10.0.0.9"])
    cbase.set_http_factory(None)
    yield
    set_role_overrides(None)
    cbase.set_http_factory(None)
    events.set_redis(None)


@pytest.fixture()
def app():
    from app.main import create_app

    return create_app()


class Session:
    """TestClient wrapper that automatically sends the CSRF header after login."""

    def __init__(self, app, email: str | None = None, totp: str | None = None, ip: str = "10.0.0.5") -> None:
        self.c = TestClient(app, client=(ip, 50000), base_url="http://testserver")
        self.csrf: str | None = None
        self.email = email
        self.totp_secret = totp
        if email:
            self.login()

    def login(self, password: str = PASSWORD, code: str | None = None):
        r = self.c.post("/api/auth/login", json={"email": self.email, "password": password, "totp": code or pyotp.TOTP(self.totp_secret).now()})
        if r.status_code == 200:
            self.csrf = r.json()["csrf_token"]
        return r

    def step_up(self):
        return self.c.post("/api/auth/step-up", headers=self._h(), json={"password": PASSWORD, "totp": pyotp.TOTP(self.totp_secret).now()})

    def _h(self, extra=None):
        h = {"X-CSRF-Token": self.csrf} if self.csrf else {}
        h.update(extra or {})
        return h

    def get(self, url, **kw):
        return self.c.get(url, headers=self._h(kw.pop("headers", None)), **kw)

    def post(self, url, json=None, **kw):
        return self.c.post(url, json=json, headers=self._h(kw.pop("headers", None)), **kw)

    def put(self, url, json=None, **kw):
        return self.c.put(url, json=json, headers=self._h(kw.pop("headers", None)), **kw)

    def patch(self, url, json=None, **kw):
        return self.c.patch(url, json=json, headers=self._h(kw.pop("headers", None)), **kw)

    def delete(self, url, **kw):
        return self.c.delete(url, headers=self._h(kw.pop("headers", None)), **kw)


def make_user(email: str, role: str = "viewer", all_clients: bool = True, client_ids: list[str] | None = None, active: bool = True) -> tuple[str, str]:
    secret = pyotp.random_base32()
    with dbmod.session_scope() as db:
        u = User(subject=f"dev:{email}", email=email, name=email.split("@")[0], role=role, all_clients=all_clients, password_hash=hash_password(PASSWORD), totp_secret=secret, active=active)
        db.add(u)
        db.flush()
        for cid in client_ids or []:
            db.add(ClientMembership(user_id=u.id, client_id=cid))
        return u.id, secret


@pytest.fixture()
def step_up_on(monkeypatch):
    """Turn on SOC_STEP_UP_REQUIRED (off by default) for tests that check the re-verification requirement."""
    monkeypatch.setenv("SOC_STEP_UP_REQUIRED", "true")
    reset_settings_cache()
    yield
    monkeypatch.undo()
    reset_settings_cache()


@pytest.fixture()
def make_session(app):
    def _make(email: str, role: str = "viewer", all_clients: bool = True, client_ids: list[str] | None = None) -> Session:
        _, secret = make_user(email, role, all_clients, client_ids)
        return Session(app, email, secret)

    return _make


@pytest.fixture()
def clients():
    with dbmod.session_scope() as db:
        a, b = Client(name="Acme", code="ACME"), Client(name="Globex", code="GLOBEX")
        db.add_all([a, b])
        db.flush()
        return a.id, b.id


@pytest.fixture()
def admin(make_session):
    return make_session("admin@t.local", "admin")


@pytest.fixture()
def superadmin(make_session):
    return make_session("super@t.local", "superadmin")


@pytest.fixture()
def admin2(make_session):
    return make_session("admin2@t.local", "admin")
