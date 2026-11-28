"""Add uptime_monitors and uptime_checks tables

Revision ID: 0015
Revises: 0014
"""
from alembic import op
import sqlalchemy as sa

revision = '0015'
down_revision = '0014'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'uptime_monitors',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('name', sa.String(200), nullable=False),
        sa.Column('url', sa.String(2000), nullable=False),
        sa.Column('method', sa.String(10), server_default='HEAD', nullable=False),
        sa.Column('interval_seconds', sa.Integer, server_default='60', nullable=False),
        sa.Column('timeout_seconds', sa.Integer, server_default='10', nullable=False),
        sa.Column('expected_status', sa.Integer, server_default='200', nullable=False),
        sa.Column('headers', sa.JSON, server_default='{}', nullable=False),
        sa.Column('tags', sa.JSON, server_default='[]', nullable=False),
        sa.Column('notify_channels', sa.JSON, server_default='[]', nullable=False),
        sa.Column('enabled', sa.Boolean, server_default=sa.text('true'), nullable=False),
        sa.Column('status', sa.String(20), server_default='unknown', nullable=False),
        sa.Column('last_checked_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_status_change', sa.DateTime(timezone=True), nullable=True),
        sa.Column('consecutive_failures', sa.Integer, server_default='0', nullable=False),
        sa.Column('fail_threshold', sa.Integer, server_default='2', nullable=False),
        sa.Column('client_id', sa.String(36), sa.ForeignKey('clients.id'), nullable=True, index=True),
        sa.Column('created_by', sa.String(200), server_default='', nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    )

    op.create_table(
        'uptime_checks',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('monitor_id', sa.String(36), sa.ForeignKey('uptime_monitors.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('status', sa.String(10), nullable=False),
        sa.Column('status_code', sa.Integer, nullable=True),
        sa.Column('response_time_ms', sa.Integer, nullable=True),
        sa.Column('error', sa.String(1000), nullable=True),
        sa.Column('checked_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    )

    op.create_index('ix_uptime_checks_monitor_checked', 'uptime_checks', ['monitor_id', 'checked_at'])


def downgrade() -> None:
    op.drop_index('ix_uptime_checks_monitor_checked', table_name='uptime_checks')
    op.drop_table('uptime_checks')
    op.drop_table('uptime_monitors')
