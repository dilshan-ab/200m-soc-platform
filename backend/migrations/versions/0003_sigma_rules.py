"""sigma rule library

Revision ID: 0003
Revises: 0002
"""
import sqlalchemy as sa
from alembic import op

import app.models

revision = '0003'
down_revision = '0002'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'sigma_rules',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('sigma_id', sa.String(length=64), nullable=False),
        sa.Column('title', sa.String(length=300), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('status', sa.String(length=20), nullable=False),
        sa.Column('level', sa.String(length=10), nullable=False),
        sa.Column('log_source', sa.JSON(), nullable=False),
        sa.Column('technique_ids', sa.JSON(), nullable=False),
        sa.Column('tags', sa.JSON(), nullable=False),
        sa.Column('references', sa.JSON(), nullable=False),
        sa.Column('false_positives', sa.JSON(), nullable=False),
        sa.Column('raw_yaml', sa.Text(), nullable=False),
        sa.Column('enabled', sa.Boolean(), nullable=False),
        sa.Column('imported_by', sa.String(length=36), nullable=True),
        sa.Column('created_at', app.models.UTCDateTime(timezone=True), nullable=False),
        sa.Column('updated_at', app.models.UTCDateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['imported_by'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_sigma_rules_status'), 'sigma_rules', ['status'], unique=False)
    op.create_index(op.f('ix_sigma_rules_sigma_id'), 'sigma_rules', ['sigma_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_sigma_rules_sigma_id'), table_name='sigma_rules')
    op.drop_index(op.f('ix_sigma_rules_status'), table_name='sigma_rules')
    op.drop_table('sigma_rules')
