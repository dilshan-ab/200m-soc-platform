"""PostgreSQL schema drift: timezone-aware timestamps and NOT NULL enrichment rule columns

Migrations 0005 to 0009 created 31 timestamp columns as TIMESTAMP WITHOUT TIME ZONE, while the models declare
timezone-aware UTC timestamps. The app always writes UTC, so stored values are UTC; they are converted in place.
Migration 0011 left six enrichment_rules columns nullable that the models declare NOT NULL.
notification_deliveries.dedupe_key (120) and event_ref (80) were too short for the keys the app builds, so rule-based
notifications failed to save on PostgreSQL (SQLite ignores VARCHAR lengths); both are widened to 255.

Revision ID: 0013
Revises: 0012
"""
import sqlalchemy as sa
from alembic import op

revision = '0013'
down_revision = '0012'
branch_labels = None
depends_on = None

TIMESTAMPS = [
    ('case_evidence', 'collected_at'), ('case_evidence', 'created_at'),
    ('correlation_rules', 'created_at'), ('correlation_rules', 'updated_at'),
    ('entity_profiles', 'first_seen'), ('entity_profiles', 'last_seen'), ('entity_profiles', 'updated_at'),
    ('incidents', 'first_alert_time'), ('incidents', 'last_alert_time'), ('incidents', 'created_at'), ('incidents', 'updated_at'),
    ('notebooks', 'created_at'), ('notebooks', 'updated_at'),
    ('playbook_runs', 'started_at'), ('playbook_runs', 'finished_at'),
    ('playbooks', 'created_at'), ('playbooks', 'updated_at'),
    ('report_templates', 'created_at'),
    ('shift_handoffs', 'submitted_at'), ('shift_handoffs', 'acknowledged_at'), ('shift_handoffs', 'created_at'), ('shift_handoffs', 'updated_at'),
    ('threat_feeds', 'last_sync_at'), ('threat_feeds', 'created_at'),
    ('threat_indicators', 'valid_until'), ('threat_indicators', 'first_seen'), ('threat_indicators', 'last_seen'), ('threat_indicators', 'created_at'),
    ('war_room_messages', 'created_at'),
    ('war_rooms', 'created_at'), ('war_rooms', 'closed_at'),
]

# column -> value for rows that are NULL today (the model defaults)
ENRICHMENT_RULE_DEFAULTS = {
    'description': "''", 'verdict': "'suspicious'", 'confidence': '70', 'tags': "'[]'", 'enabled': 'true', 'hit_count': '0',
}


def _postgres() -> bool:
    # Migrations target PostgreSQL (production). SQLite development databases are built from the models by `init-db`.
    return op.get_bind().dialect.name == 'postgresql'


def upgrade() -> None:
    if not _postgres():
        return
    for table, col in TIMESTAMPS:
        op.execute(f"ALTER TABLE {table} ALTER COLUMN {col} TYPE TIMESTAMP WITH TIME ZONE USING {col} AT TIME ZONE 'UTC'")
    for col, value in ENRICHMENT_RULE_DEFAULTS.items():
        op.execute(f"UPDATE enrichment_rules SET {col} = {value} WHERE {col} IS NULL")
        op.alter_column('enrichment_rules', col, nullable=False)
    op.alter_column('notification_deliveries', 'event_ref', type_=sa.String(255), existing_type=sa.String(80))
    op.alter_column('notification_deliveries', 'dedupe_key', type_=sa.String(255), existing_type=sa.String(120))


def downgrade() -> None:
    if not _postgres():
        return
    # narrowing again fails if longer values were stored since; that is the point of the upgrade, so it is not undone
    for col in ENRICHMENT_RULE_DEFAULTS:
        op.alter_column('enrichment_rules', col, nullable=True)
    for table, col in TIMESTAMPS:
        op.execute(f"ALTER TABLE {table} ALTER COLUMN {col} TYPE TIMESTAMP WITHOUT TIME ZONE USING {col} AT TIME ZONE 'UTC'")
