"""threat intel sharing, shift handoff, war room, client branding (MSSP)

Revision ID: 0009
Revises: 0008
"""
import sqlalchemy as sa
from alembic import op

revision = '0009'
down_revision = '0008'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('clients', sa.Column('logo_url', sa.String(500), nullable=False, server_default=''))
    op.add_column('clients', sa.Column('brand_color', sa.String(10), nullable=False, server_default=''))
    op.add_column('clients', sa.Column('timezone', sa.String(60), nullable=False, server_default='UTC'))
    op.add_column('clients', sa.Column('contact_email', sa.String(255), nullable=False, server_default=''))
    op.add_column('clients', sa.Column('tier', sa.String(20), nullable=False, server_default='standard'))

    op.create_table(
        'threat_indicators',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('stix_id', sa.String(200), nullable=False, server_default='', index=True),
        sa.Column('type', sa.String(20), nullable=False, index=True),
        sa.Column('value', sa.String(500), nullable=False, index=True),
        sa.Column('pattern', sa.String(1000), nullable=False, server_default=''),
        sa.Column('labels', sa.JSON(), nullable=False, server_default='[]'),
        sa.Column('confidence', sa.Integer(), nullable=False, server_default='50'),
        sa.Column('tlp', sa.String(10), nullable=False, server_default='AMBER'),
        sa.Column('verdict', sa.String(20), nullable=False, server_default='unknown'),
        sa.Column('source', sa.String(160), nullable=False, server_default='manual'),
        sa.Column('sightings', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('revoked', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('valid_until', sa.DateTime(), nullable=True),
        sa.Column('client_id', sa.String(36), sa.ForeignKey('clients.id'), nullable=True, index=True),
        sa.Column('created_by', sa.String(36), sa.ForeignKey('users.id'), nullable=True),
        sa.Column('first_seen', sa.DateTime(), nullable=False),
        sa.Column('last_seen', sa.DateTime(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.UniqueConstraint('type', 'value'),
    )
    op.create_table(
        'threat_feeds',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('name', sa.String(160), nullable=False),
        sa.Column('direction', sa.String(10), nullable=False, server_default='import'),
        sa.Column('taxii_discovery_url', sa.String(500), nullable=False, server_default=''),
        sa.Column('taxii_collection_id', sa.String(120), nullable=False, server_default=''),
        sa.Column('taxii_username', sa.String(160), nullable=False, server_default=''),
        sa.Column('auth_secret_ref', sa.String(160), nullable=True),
        sa.Column('enabled', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('last_sync_at', sa.DateTime(), nullable=True),
        sa.Column('last_sync_status', sa.String(20), nullable=False, server_default=''),
        sa.Column('last_sync_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('last_error', sa.String(400), nullable=False, server_default=''),
        sa.Column('created_by', sa.String(36), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
    )

    op.create_table(
        'shift_handoffs',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('shift_name', sa.String(80), nullable=False, server_default=''),
        sa.Column('status', sa.String(20), nullable=False, server_default='draft'),
        sa.Column('summary', sa.Text(), nullable=False, server_default=''),
        sa.Column('open_items', sa.JSON(), nullable=False, server_default='[]'),
        sa.Column('watch_items', sa.JSON(), nullable=False, server_default='[]'),
        sa.Column('handoff_notes', sa.Text(), nullable=False, server_default=''),
        sa.Column('case_ids', sa.JSON(), nullable=False, server_default='[]'),
        sa.Column('alert_ids', sa.JSON(), nullable=False, server_default='[]'),
        sa.Column('from_analyst_id', sa.String(36), sa.ForeignKey('users.id'), nullable=True),
        sa.Column('to_analyst_id', sa.String(36), sa.ForeignKey('users.id'), nullable=True),
        sa.Column('submitted_at', sa.DateTime(), nullable=True),
        sa.Column('acknowledged_at', sa.DateTime(), nullable=True),
        sa.Column('acknowledged_by', sa.String(36), sa.ForeignKey('users.id'), nullable=True),
        sa.Column('client_id', sa.String(36), sa.ForeignKey('clients.id'), nullable=True, index=True),
        sa.Column('created_by', sa.String(36), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
    )

    op.create_table(
        'war_rooms',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('title', sa.String(300), nullable=False),
        sa.Column('status', sa.String(20), nullable=False, server_default='active'),
        sa.Column('severity', sa.String(10), nullable=False, server_default='high'),
        sa.Column('case_id', sa.String(36), sa.ForeignKey('cases.id'), nullable=True, index=True),
        sa.Column('incident_id', sa.String(36), sa.ForeignKey('incidents.id'), nullable=True, index=True),
        sa.Column('participants', sa.JSON(), nullable=False, server_default='[]'),
        sa.Column('summary', sa.Text(), nullable=False, server_default=''),
        sa.Column('client_id', sa.String(36), sa.ForeignKey('clients.id'), nullable=True, index=True),
        sa.Column('created_by', sa.String(36), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('closed_at', sa.DateTime(), nullable=True),
    )
    op.create_table(
        'war_room_messages',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('war_room_id', sa.String(36), sa.ForeignKey('war_rooms.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('author_id', sa.String(36), sa.ForeignKey('users.id'), nullable=True),
        sa.Column('author_label', sa.String(160), nullable=False, server_default=''),
        sa.Column('kind', sa.String(20), nullable=False, server_default='message'),
        sa.Column('content', sa.Text(), nullable=False, server_default=''),
        sa.Column('pinned', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('created_at', sa.DateTime(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table('war_room_messages')
    op.drop_table('war_rooms')
    op.drop_table('shift_handoffs')
    op.drop_table('threat_feeds')
    op.drop_table('threat_indicators')
    op.drop_column('clients', 'tier')
    op.drop_column('clients', 'contact_email')
    op.drop_column('clients', 'timezone')
    op.drop_column('clients', 'brand_color')
    op.drop_column('clients', 'logo_url')
