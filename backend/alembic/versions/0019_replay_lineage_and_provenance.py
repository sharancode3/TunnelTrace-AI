"""Replay Lineage, Forensic Comparison, and Provenance DAG

Revision ID: 0019
Revises: 0018
Create Date: 2026-09-25 19:35:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0019"
down_revision: str | None = "0018"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. Add parent_analysis_id, replay_mode, provenance_metadata to analysis_runs
    op.add_column(
        "analysis_runs",
        sa.Column(
            "parent_analysis_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("analysis_runs.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.create_index(
        "ix_analysis_runs_parent_analysis_id",
        "analysis_runs",
        ["parent_analysis_id"],
    )
    op.add_column(
        "analysis_runs",
        sa.Column(
            "replay_mode",
            sa.String(length=32),
            nullable=True,
        ),
    )
    op.add_column(
        "analysis_runs",
        sa.Column(
            "provenance_metadata",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=True,
        ),
    )

    # 2. Create replay_comparisons table
    op.create_table(
        "replay_comparisons",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            nullable=False,
        ),
        sa.Column("replay_mode", sa.String(length=32), nullable=False),
        sa.Column("parent_run_id", sa.String(length=64), nullable=False),
        sa.Column("child_run_id", sa.String(length=64), nullable=False),
        sa.Column("comparison_status", sa.String(length=32), nullable=False),
        sa.Column("artifact_integrity", sa.String(length=32), nullable=False),
        sa.Column(
            "differences",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=True,
        ),
        sa.Column("summary", sa.Text(), nullable=False, server_default=""),
        sa.Column(
            "metrics",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=True,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.create_index(
        "ix_replay_comparisons_parent_run_id",
        "replay_comparisons",
        ["parent_run_id"],
    )
    op.create_index(
        "ix_replay_comparisons_child_run_id",
        "replay_comparisons",
        ["child_run_id"],
    )
    op.create_index(
        "ix_replay_comparisons_replay_mode",
        "replay_comparisons",
        ["replay_mode"],
    )
    op.create_index(
        "ix_replay_comparisons_comparison_status",
        "replay_comparisons",
        ["comparison_status"],
    )


def downgrade() -> None:
    op.drop_index("ix_replay_comparisons_comparison_status", table_name="replay_comparisons")
    op.drop_index("ix_replay_comparisons_replay_mode", table_name="replay_comparisons")
    op.drop_index("ix_replay_comparisons_child_run_id", table_name="replay_comparisons")
    op.drop_index("ix_replay_comparisons_parent_run_id", table_name="replay_comparisons")
    op.drop_table("replay_comparisons")

    op.drop_column("analysis_runs", "provenance_metadata")
    op.drop_column("analysis_runs", "replay_mode")
    op.drop_index("ix_analysis_runs_parent_analysis_id", table_name="analysis_runs")
    op.drop_column("analysis_runs", "parent_analysis_id")
