"""add threat intel (KEV/EPSS) and applicability columns

Phase 10: findings.kev/epss/epss_percentile/unverified_prerequisite and
scans.threat_intel_failed. All nullable; NULL = not enriched (rows that
predate this phase stay NULL, never backfilled).

Revision ID: 943fd406e800
Revises: 545d8b7edd29
Create Date: 2026-11-24 20:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '943fd406e800'
down_revision: Union[str, Sequence[str], None] = '545d8b7edd29'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('findings', sa.Column('kev', sa.Boolean(), nullable=True))
    op.add_column('findings', sa.Column('epss', sa.Float(), nullable=True))
    op.add_column('findings', sa.Column('epss_percentile', sa.Float(), nullable=True))
    op.add_column('findings', sa.Column('unverified_prerequisite', sa.String(length=40), nullable=True))
    op.add_column('scans', sa.Column('threat_intel_failed', sa.Integer(), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('scans', 'threat_intel_failed')
    op.drop_column('findings', 'unverified_prerequisite')
    op.drop_column('findings', 'epss_percentile')
    op.drop_column('findings', 'epss')
    op.drop_column('findings', 'kev')
