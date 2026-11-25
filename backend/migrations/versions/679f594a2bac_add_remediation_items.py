"""add remediation_items table

Phase 11: one persistent remediation item per (target, port, protocol,
CVE), with lifecycle state, SLA deadline and rescan verification.

Revision ID: 679f594a2bac
Revises: 943fd406e800
Create Date: 2026-11-25 10:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '679f594a2bac'
down_revision: Union[str, Sequence[str], None] = '943fd406e800'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

remediation_state = sa.Enum('open', 'accepted', 'fixed', 'verified', name='remediation_state')


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'remediation_items',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('project_id', sa.Uuid(), nullable=False),
        sa.Column('target_id', sa.Uuid(), nullable=False),
        sa.Column('port', sa.Integer(), nullable=False),
        sa.Column('protocol', sa.String(length=10), nullable=False),
        sa.Column('cve_id', sa.String(length=20), nullable=False),
        sa.Column('severity', sa.String(length=20), nullable=False),
        sa.Column('cvss_score', sa.Float(), nullable=True),
        sa.Column('kev', sa.Boolean(), nullable=True),
        sa.Column('state', remediation_state, nullable=False),
        sa.Column('note', sa.Text(), nullable=True),
        sa.Column('first_seen_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('first_seen_scan_id', sa.Uuid(), nullable=True),
        sa.Column('last_seen_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_seen_scan_id', sa.Uuid(), nullable=True),
        sa.Column('due_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('state_changed_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('fixed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('verified_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('verified_scan_id', sa.Uuid(), nullable=True),
        sa.Column('verification_reason', sa.String(length=30), nullable=True),
        sa.Column('reopened_count', sa.Integer(), nullable=False),
        sa.Column('simulated', sa.Boolean(), server_default='false', nullable=False),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['target_id'], ['targets.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['first_seen_scan_id'], ['scans.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['last_seen_scan_id'], ['scans.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['verified_scan_id'], ['scans.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('target_id', 'port', 'protocol', 'cve_id', name='uq_remediation_target_port_cve'),
    )
    op.create_index('ix_remediation_items_project_id', 'remediation_items', ['project_id'])
    op.create_index('ix_remediation_items_target_id', 'remediation_items', ['target_id'])


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index('ix_remediation_items_target_id', table_name='remediation_items')
    op.drop_index('ix_remediation_items_project_id', table_name='remediation_items')
    op.drop_table('remediation_items')
    remediation_state.drop(op.get_bind(), checkfirst=True)
