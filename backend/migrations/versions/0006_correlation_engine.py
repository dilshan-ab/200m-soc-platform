"""correlation rules and incidents tables for alert correlation engine

Revision ID: 0006
Revises: 0005
"""
import sqlalchemy as sa
from alembic import op

revision = '0006'
down_revision = '0005'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'correlation_rules',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('name', sa.String(200), unique=True, nullable=False),
        sa.Column('description', sa.Text(), nullable=False, server_default=''),
        sa.Column('strategy', sa.String(30), nullable=False, server_default='ioc_overlap'),
        sa.Column('config', sa.JSON(), nullable=False, server_default='{}'),
        sa.Column('severity_boost', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('enabled', sa.Boolean(), nullable=False, server_default='1', index=True),
        sa.Column('client_id', sa.String(36), sa.ForeignKey('clients.id'), nullable=True, index=True),
        sa.Column('created_by', sa.String(160), nullable=False, server_default=''),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
    )
    op.create_table(
        'incidents',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('name', sa.String(300), nullable=False),
        sa.Column('description', sa.Text(), nullable=False, server_default=''),
        sa.Column('severity', sa.String(10), nullable=False, server_default='medium', index=True),
        sa.Column('status', sa.String(20), nullable=False, server_default='open', index=True),
        sa.Column('rule_id', sa.String(36), sa.ForeignKey('correlation_rules.id'), nullable=True, index=True),
        sa.Column('rule_name', sa.String(200), nullable=False, server_default=''),
        sa.Column('strategy', sa.String(30), nullable=False, server_default='manual'),
        sa.Column('alert_ids', sa.JSON(), nullable=False, server_default='[]'),
        sa.Column('shared_iocs', sa.JSON(), nullable=False, server_default='{}'),
        sa.Column('kill_chain_stages', sa.JSON(), nullable=False, server_default='[]'),
        sa.Column('alert_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('first_alert_time', sa.DateTime(), nullable=True),
        sa.Column('last_alert_time', sa.DateTime(), nullable=True),
        sa.Column('case_id', sa.String(36), sa.ForeignKey('cases.id'), nullable=True, index=True),
        sa.Column('client_id', sa.String(36), sa.ForeignKey('clients.id'), nullable=True, index=True),
        sa.Column('assignee_id', sa.String(36), sa.ForeignKey('users.id'), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table('incidents')
    op.drop_table('correlation_rules')
