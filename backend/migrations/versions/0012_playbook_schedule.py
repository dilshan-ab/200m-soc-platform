"""playbook schedule: interval, next_run_at, last_run_at

Revision ID: 0012
Revises: 0011
"""
import sqlalchemy as sa
from alembic import op

revision = '0012'
down_revision = '0011'
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table('playbooks') as b:
        b.add_column(sa.Column('schedule_interval_minutes', sa.Integer, nullable=True))
        b.add_column(sa.Column('next_run_at', sa.DateTime(timezone=True), nullable=True))
        b.add_column(sa.Column('last_run_at', sa.DateTime(timezone=True), nullable=True))
        b.create_index('ix_playbooks_next_run_at', ['next_run_at'])


def downgrade() -> None:
    with op.batch_alter_table('playbooks') as b:
        b.drop_index('ix_playbooks_next_run_at')
        b.drop_column('last_run_at')
        b.drop_column('next_run_at')
        b.drop_column('schedule_interval_minutes')
