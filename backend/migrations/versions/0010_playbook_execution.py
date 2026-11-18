"""link action_requests to the playbook run/node that spawned them, for the SOAR execution engine

Revision ID: 0010
Revises: 0009
"""
import sqlalchemy as sa
from alembic import op

revision = '0010'
down_revision = '0009'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('action_requests', sa.Column('playbook_run_id', sa.String(36), sa.ForeignKey('playbook_runs.id', ondelete='SET NULL'), nullable=True, index=True))
    op.add_column('action_requests', sa.Column('playbook_node_id', sa.String(60), nullable=True))


def downgrade() -> None:
    op.drop_column('action_requests', 'playbook_node_id')
    op.drop_column('action_requests', 'playbook_run_id')
