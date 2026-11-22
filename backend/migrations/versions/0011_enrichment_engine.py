"""enrichment engine: custom rules table and ThreatIndicator enhancements

Revision ID: 0011
Revises: 0010
"""
import sqlalchemy as sa
from alembic import op

revision = '0011'
down_revision = '0010'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'enrichment_rules',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('name', sa.String(200), nullable=False),
        sa.Column('description', sa.Text, server_default=''),
        sa.Column('rule_type', sa.String(20), nullable=False),
        sa.Column('indicator_type', sa.String(20), nullable=False),
        sa.Column('pattern', sa.Text, nullable=False),
        sa.Column('verdict', sa.String(20), server_default='suspicious'),
        sa.Column('confidence', sa.Integer, server_default='70'),
        sa.Column('tags', sa.JSON, server_default='[]'),
        sa.Column('enabled', sa.Boolean, server_default='1'),
        sa.Column('hit_count', sa.Integer, server_default='0'),
        sa.Column('last_hit_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_by', sa.String(36), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table('enrichment_rules')
