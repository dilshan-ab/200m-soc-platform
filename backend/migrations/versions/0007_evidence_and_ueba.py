"""case evidence chain and UEBA entity profiles

Revision ID: 0007
Revises: 0006
"""
import sqlalchemy as sa
from alembic import op

revision = '0007'
down_revision = '0006'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'case_evidence',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('case_id', sa.String(36), sa.ForeignKey('cases.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('name', sa.String(300), nullable=False),
        sa.Column('type', sa.String(30), nullable=False, server_default='file'),
        sa.Column('description', sa.Text(), nullable=False, server_default=''),
        sa.Column('hash_sha256', sa.String(64), nullable=False, server_default=''),
        sa.Column('file_size', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('storage_ref', sa.String(500), nullable=False, server_default=''),
        sa.Column('tags', sa.JSON(), nullable=False, server_default='[]'),
        sa.Column('collected_by', sa.String(160), nullable=False, server_default=''),
        sa.Column('collected_at', sa.DateTime(), nullable=False),
        sa.Column('chain_of_custody', sa.JSON(), nullable=False, server_default='[]'),
        sa.Column('observable_id', sa.String(36), nullable=True),
        sa.Column('alert_id', sa.String(36), nullable=True),
        sa.Column('client_id', sa.String(36), sa.ForeignKey('clients.id'), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
    )
    op.create_table(
        'entity_profiles',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('entity_type', sa.String(20), nullable=False, index=True),
        sa.Column('entity_value', sa.String(255), nullable=False, index=True),
        sa.Column('client_id', sa.String(36), sa.ForeignKey('clients.id'), nullable=True, index=True),
        sa.Column('risk_score', sa.Float(), nullable=False, server_default='0'),
        sa.Column('alert_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('baseline', sa.JSON(), nullable=False, server_default='{}'),
        sa.Column('anomalies', sa.JSON(), nullable=False, server_default='[]'),
        sa.Column('first_seen', sa.DateTime(), nullable=False),
        sa.Column('last_seen', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.UniqueConstraint('entity_type', 'entity_value', 'client_id'),
    )


def downgrade() -> None:
    op.drop_table('entity_profiles')
    op.drop_table('case_evidence')
