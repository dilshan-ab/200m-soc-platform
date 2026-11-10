"""hunt workbench: hypothesis, ATT&CK mapping, query, verdict on hunts

Revision ID: 0002
Revises: 0001
"""
import sqlalchemy as sa
from alembic import op

import app.models

revision = '0002'
down_revision = '0001'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('hunts', sa.Column('kind', sa.String(length=20), nullable=False, server_default='collection'))
    op.add_column('hunts', sa.Column('hypothesis', sa.Text(), nullable=False, server_default=''))
    op.add_column('hunts', sa.Column('technique_ids', sa.JSON(), nullable=False, server_default='[]'))
    op.add_column('hunts', sa.Column('query', sa.JSON(), nullable=False, server_default='{}'))
    op.add_column('hunts', sa.Column('verdict', sa.String(length=20), nullable=False, server_default=''))
    op.add_column('hunts', sa.Column('conclusion_note', sa.Text(), nullable=False, server_default=''))
    op.add_column('hunts', sa.Column('match_count', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('hunts', sa.Column('concluded_at', app.models.UTCDateTime(timezone=True), nullable=True))
    op.alter_column('hunts', 'artifact', existing_type=sa.String(length=120), nullable=False, server_default='')
    # existing rows predate the workbench and were all artifact-collection requests
    op.execute("UPDATE hunts SET kind = 'collection'")
    op.alter_column('hunts', 'kind', server_default=None)
    op.alter_column('hunts', 'hypothesis', server_default=None)
    op.alter_column('hunts', 'query', server_default=None)
    op.alter_column('hunts', 'verdict', server_default=None)
    op.alter_column('hunts', 'conclusion_note', server_default=None)
    op.alter_column('hunts', 'match_count', server_default=None)
    op.alter_column('hunts', 'artifact', server_default=None)


def downgrade() -> None:
    op.drop_column('hunts', 'concluded_at')
    op.drop_column('hunts', 'match_count')
    op.drop_column('hunts', 'conclusion_note')
    op.drop_column('hunts', 'verdict')
    op.drop_column('hunts', 'query')
    op.drop_column('hunts', 'technique_ids')
    op.drop_column('hunts', 'hypothesis')
    op.drop_column('hunts', 'kind')
    op.alter_column('hunts', 'artifact', existing_type=sa.String(length=120), nullable=False)
