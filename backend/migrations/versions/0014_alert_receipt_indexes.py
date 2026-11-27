"""Index alert_receipts.alert_id and received_at

alert_receipts grows by one row per raw source event (about 130,000 a day on the live site, 5.7 million rows by
27 Nov 2026). Deleting alerts unlinks their receipts by alert_id, which had no index, so each 1,000-alert batch scanned
the whole table and ran past the proxy timeout. received_at is indexed so old receipts can be pruned cheaply.
IF NOT EXISTS: the alert_id index may already have been created by hand on the live database to unblock a clean-up.

Revision ID: 0014
Revises: 0013
"""
from alembic import op

revision = '0014'
down_revision = '0013'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index('ix_alert_receipts_alert_id', 'alert_receipts', ['alert_id'], if_not_exists=True)
    op.create_index('ix_alert_receipts_received_at', 'alert_receipts', ['received_at'], if_not_exists=True)


def downgrade() -> None:
    op.drop_index('ix_alert_receipts_received_at', table_name='alert_receipts', if_exists=True)
    op.drop_index('ix_alert_receipts_alert_id', table_name='alert_receipts', if_exists=True)
