"""Remediation Approval, Containment, and Verification Lineage

Revision ID: 0018
Revises: 0017
Create Date: 2026-09-25 19:20:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0018"
down_revision: str | None = "0017"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Add approval_metadata, pre_apply_spis, and post_capture_hash to remediation_runs
    op.add_column(
        "remediation_runs",
        sa.Column(
            "approval_metadata",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=True,
        ),
    )
    op.add_column(
        "remediation_runs",
        sa.Column(
            "pre_apply_spis",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=True,
        ),
    )
    op.add_column(
        "remediation_runs",
        sa.Column(
            "post_capture_hash",
            sa.String(length=64),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("remediation_runs", "post_capture_hash")
    op.drop_column("remediation_runs", "pre_apply_spis")
    op.drop_column("remediation_runs", "approval_metadata")
