"""phase 12: finding sources, remediation sources and race-fix watermarks

- findings.source: who reported the finding (vulnsight / nessus / openvas).
- remediation_items.sources: every source that has reported the item.
- remediation_items.last_evaluated_at: scan time of the newest scan that
  saw or verified the item; no older scan may change it.
- targets.remediation_watermarks: per source, scan time of the newest
  scan whose remediation sync ran; an older scan of that source is stale.

Revision ID: b7e2c41d9a10
Revises: 679f594a2bac
Create Date: 2026-11-26 10:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "b7e2c41d9a10"
down_revision: Union[str, Sequence[str], None] = "679f594a2bac"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "findings",
        sa.Column("source", sa.String(length=20), server_default="vulnsight", nullable=False),
    )
    op.add_column(
        "targets",
        sa.Column(
            "remediation_watermarks",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
    )
    op.add_column(
        "remediation_items",
        sa.Column(
            "sources",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[\"vulnsight\"]'::jsonb"),
            nullable=False,
        ),
    )
    op.add_column(
        "remediation_items",
        sa.Column("last_evaluated_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.execute(
        """
        UPDATE remediation_items AS ri
        SET last_evaluated_at = GREATEST(
            ri.last_seen_at,
            COALESCE((SELECT s.created_at FROM scans s WHERE s.id = ri.verified_scan_id),
                     ri.last_seen_at)
        )
        """
    )
    op.alter_column("remediation_items", "last_evaluated_at", nullable=False)


def downgrade() -> None:
    op.drop_column("remediation_items", "last_evaluated_at")
    op.drop_column("remediation_items", "sources")
    op.drop_column("targets", "remediation_watermarks")
    op.drop_column("findings", "source")
