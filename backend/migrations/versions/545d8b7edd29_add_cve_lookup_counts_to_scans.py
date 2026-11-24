"""add cve lookup counts to scans

Records how complete CVE correlation was, so a failed NVD lookup or
findings insert is no longer indistinguishable from "no known CVEs".
NULL for scans that predate this column or haven't reached CORRELATING.

Revision ID: 545d8b7edd29
Revises: e548c7c94ffd
Create Date: 2026-11-24 18:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '545d8b7edd29'
down_revision: Union[str, Sequence[str], None] = 'e548c7c94ffd'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('scans', sa.Column('cve_lookups_total', sa.Integer(), nullable=True))
    op.add_column('scans', sa.Column('cve_lookups_failed', sa.Integer(), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('scans', 'cve_lookups_failed')
    op.drop_column('scans', 'cve_lookups_total')
