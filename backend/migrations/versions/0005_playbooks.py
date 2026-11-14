"""playbook and playbook_run tables for visual SOAR builder

Revision ID: 0005
Revises: 0004
"""
import sqlalchemy as sa
from alembic import op

revision = '0005'
down_revision = '0004'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'playbooks',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('name', sa.String(200), unique=True, nullable=False),
        sa.Column('description', sa.Text(), nullable=False, server_default=''),
        sa.Column('trigger', sa.String(40), nullable=False, server_default='manual'),
        sa.Column('nodes', sa.JSON(), nullable=False, server_default='[]'),
        sa.Column('edges', sa.JSON(), nullable=False, server_default='[]'),
        sa.Column('status', sa.String(20), nullable=False, server_default='draft', index=True),
        sa.Column('enabled', sa.Boolean(), nullable=False, server_default='0'),
        sa.Column('version', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('client_id', sa.String(36), sa.ForeignKey('clients.id'), nullable=True, index=True),
        sa.Column('created_by', sa.String(160), nullable=False, server_default=''),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
    )
    op.create_table(
        'playbook_runs',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('playbook_id', sa.String(36), sa.ForeignKey('playbooks.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('trigger_ref', sa.String(120), nullable=False, server_default=''),
        sa.Column('status', sa.String(20), nullable=False, server_default='running', index=True),
        sa.Column('current_node', sa.String(60), nullable=False, server_default=''),
        sa.Column('execution_log', sa.JSON(), nullable=False, server_default='[]'),
        sa.Column('error', sa.Text(), nullable=False, server_default=''),
        sa.Column('started_at', sa.DateTime(), nullable=False),
        sa.Column('finished_at', sa.DateTime(), nullable=True),
    )


def downgrade() -> None:
    op.drop_table('playbook_runs')
    op.drop_table('playbooks')
