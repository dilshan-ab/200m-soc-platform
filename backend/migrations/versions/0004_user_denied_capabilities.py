"""per-user permission denial list

Revision ID: 0004
Revises: 0003
"""
import sqlalchemy as sa
from alembic import op

revision = '0004'
down_revision = '0003'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('users', sa.Column('denied', sa.JSON(), nullable=False, server_default='[]'))
    op.alter_column('users', 'denied', server_default=None)


def downgrade() -> None:
    op.drop_column('users', 'denied')
