"""Alembic migrations, run on a real PostgreSQL database (production's engine).

Set SOC_TEST_MIGRATIONS_URL to an empty throwaway PostgreSQL database; the test is skipped otherwise. SQLite is not
covered: development databases are built from the models by `init-db`, and production runs migrations on PostgreSQL.
"""
from __future__ import annotations

import os

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, text

from app import models  # noqa: F401  (register tables)
from app.config import reset_settings_cache
from app.db import Base

URL = os.environ.get("SOC_TEST_MIGRATIONS_URL", "")
pytestmark = pytest.mark.skipif(not URL.startswith("postgresql"), reason="set SOC_TEST_MIGRATIONS_URL to an empty PostgreSQL database")


@pytest.fixture()
def alembic_cfg(monkeypatch):
    monkeypatch.setenv("SOC_DATABASE_URL", URL)
    reset_settings_cache()
    engine = create_engine(URL)
    with engine.begin() as conn:  # start from an empty database every time
        conn.execute(text("DROP SCHEMA public CASCADE"))
        conn.execute(text("CREATE SCHEMA public"))
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cfg = Config(os.path.join(here, "alembic.ini"))
    cfg.set_main_option("script_location", os.path.join(here, "migrations"))
    yield cfg, engine
    engine.dispose()
    monkeypatch.undo()
    reset_settings_cache()


def _drift(engine):
    with engine.connect() as conn:
        return compare_metadata(MigrationContext.configure(conn, opts={"compare_type": True}), Base.metadata)


def test_upgrade_to_head_matches_the_models(alembic_cfg):
    cfg, engine = alembic_cfg
    command.upgrade(cfg, "head")
    with engine.connect() as conn:
        current = MigrationContext.configure(conn).get_current_revision()
    assert current == ScriptDirectory.from_config(cfg).get_current_head()
    assert _drift(engine) == []  # a model change without a migration (or a migration that differs from the model) fails here


def test_every_migration_downgrades_and_upgrades_again(alembic_cfg):
    cfg, engine = alembic_cfg
    command.upgrade(cfg, "head")
    command.downgrade(cfg, "base")
    command.upgrade(cfg, "head")
    assert _drift(engine) == []


def test_timestamps_are_timezone_aware_and_keep_their_instant(alembic_cfg):
    cfg, engine = alembic_cfg
    command.upgrade(cfg, "0012")
    with engine.begin() as conn:
        conn.execute(text("INSERT INTO users (id, subject, email, name, role, grants, denied, all_clients, active, failed_logins, created_at) "
                          "VALUES ('u1', 'dev:x', 'x@t', 'x', 'viewer', '[]', '[]', false, true, 0, now())"))
        conn.execute(text("INSERT INTO war_rooms (id, title, created_by, created_at) VALUES ('w1', 'r', 'u1', '2026-11-24 10:00:00')"))
    command.upgrade(cfg, "head")
    with engine.begin() as conn:
        conn.execute(text("SET TIME ZONE 'Asia/Colombo'"))  # a non-UTC session must not change the stored instant
        value = conn.execute(text("SELECT created_at AT TIME ZONE 'UTC' FROM war_rooms WHERE id = 'w1'")).scalar_one()
        kinds = {r[0] for r in conn.execute(text("SELECT data_type FROM information_schema.columns WHERE table_schema = 'public' AND data_type LIKE 'timestamp%'"))}
    assert str(value) == "2026-11-24 10:00:00"
    assert kinds == {"timestamp with time zone"}
