"""investigation notebooks and report templates

Revision ID: 0008
Revises: 0007
"""
import sqlalchemy as sa
from alembic import op

revision = '0008'
down_revision = '0007'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'notebooks',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('title', sa.String(300), nullable=False),
        sa.Column('description', sa.Text(), nullable=False, server_default=''),
        sa.Column('case_id', sa.String(36), sa.ForeignKey('cases.id', ondelete='SET NULL'), nullable=True, index=True),
        sa.Column('client_id', sa.String(36), sa.ForeignKey('clients.id'), nullable=True, index=True),
        sa.Column('tags', sa.JSON(), nullable=False, server_default='[]'),
        sa.Column('cells', sa.JSON(), nullable=False, server_default='[]'),
        sa.Column('created_by', sa.String(36), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('version', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
    )
    op.create_table(
        'report_templates',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('name', sa.String(160), nullable=False),
        sa.Column('description', sa.Text(), nullable=False, server_default=''),
        sa.Column('kind', sa.String(40), nullable=False),
        sa.Column('fmt', sa.String(10), nullable=False, server_default='html'),
        sa.Column('params', sa.JSON(), nullable=False, server_default='{}'),
        sa.Column('client_id', sa.String(36), nullable=True),
        sa.Column('created_by', sa.String(36), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table('report_templates')
    op.drop_table('notebooks')
