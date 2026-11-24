"""widen findings.cvss_vector to text

A full CVSS v4.0 vector (every optional metric spelled out, as NVD
returns them) runs to ~180 characters; varchar(100) made the whole
findings insert for that CPE fail, silently dropping every CVE matched
through it (found by the Phase 9 benchmark).

Revision ID: e548c7c94ffd
Revises: f03cf5ee5305
Create Date: 2026-11-24 17:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = 'e548c7c94ffd'
down_revision: Union[str, Sequence[str], None] = 'f03cf5ee5305'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.alter_column(
        'findings', 'cvss_vector',
        existing_type=sa.String(length=100), type_=sa.Text(), existing_nullable=True,
    )


def downgrade() -> None:
    """Downgrade schema. Truncates any vector longer than 100 characters."""
    op.execute("UPDATE findings SET cvss_vector = left(cvss_vector, 100)")
    op.alter_column(
        'findings', 'cvss_vector',
        existing_type=sa.Text(), type_=sa.String(length=100), existing_nullable=True,
    )
