"""Stage 5 migration: Datasets, Dataset Versions, Dataset Sessions, Dataset Splits

Revision ID: 0004
Revises: 0003
Create Date: 2026-09-24 00:35:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. Create datasets table
    op.create_table(
        "datasets",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("vpn_technology", sa.String(length=32), nullable=False, server_default="IPSEC_NATIVE"),
        sa.Column("role", sa.String(length=32), nullable=False, server_default="PRIMARY"),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_datasets_name", "datasets", ["name"], unique=True)

    # 2. Create dataset_versions table
    op.create_table(
        "dataset_versions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "dataset_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("datasets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("version_tag", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="DRAFT"),
        sa.Column("manifest_hash", sa.String(length=64), nullable=True),
        sa.Column("session_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column(
            "class_distribution",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=True,
        ),
        sa.Column(
            "coverage_summary",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=True,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_dataset_versions_dataset_id", "dataset_versions", ["dataset_id"])
    op.create_index("ix_dataset_versions_version_tag", "dataset_versions", ["version_tag"])

    # 3. Create dataset_sessions table
    op.create_table(
        "dataset_sessions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "version_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("dataset_versions.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("testbed_run_id", sa.String(length=128), nullable=True),
        sa.Column(
            "capture_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("captures.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "analysis_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("analysis_runs.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("workload_class", sa.String(length=64), nullable=False),
        sa.Column("workload_profile_id", sa.String(length=128), nullable=False),
        sa.Column("workload_seed", sa.Integer(), nullable=False, server_default="42"),
        sa.Column("scenario_id", sa.String(length=128), nullable=False),
        sa.Column("mode", sa.String(length=32), nullable=False, server_default="TUNNEL"),
        sa.Column("ip_version", sa.String(length=16), nullable=False, server_default="IPv4"),
        sa.Column("cipher_suite", sa.String(length=64), nullable=False),
        sa.Column("pfs_status", sa.String(length=32), nullable=False, server_default="ENABLED"),
        sa.Column("is_nat_t", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("network_impairment_profile", sa.String(length=128), nullable=True),
        sa.Column("quality_status", sa.String(length=32), nullable=False, server_default="ACCEPTED"),
        sa.Column("rejection_reason", sa.String(length=255), nullable=True),
        sa.Column("encrypted_capture_sha256", sa.String(length=64), nullable=False),
        sa.Column("duration_seconds", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("packet_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("byte_count", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column(
            "metadata_json",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=True,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_dataset_sessions_version_id", "dataset_sessions", ["version_id"])
    op.create_index("ix_dataset_sessions_workload_class", "dataset_sessions", ["workload_class"])
    op.create_index("ix_dataset_sessions_scenario_id", "dataset_sessions", ["scenario_id"])
    op.create_index("ix_dataset_sessions_capture_sha", "dataset_sessions", ["encrypted_capture_sha256"])

    # 4. Create dataset_splits table
    op.create_table(
        "dataset_splits",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "version_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("dataset_versions.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "session_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("dataset_sessions.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("split_type", sa.String(length=32), nullable=False),
        sa.Column("group_id", sa.String(length=128), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_dataset_splits_version_id", "dataset_splits", ["version_id"])
    op.create_index("ix_dataset_splits_session_id", "dataset_splits", ["session_id"])
    op.create_index("ix_dataset_splits_split_type", "dataset_splits", ["split_type"])
    op.create_index("ix_dataset_splits_group_id", "dataset_splits", ["group_id"])


def downgrade() -> None:
    op.drop_table("dataset_splits")
    op.drop_table("dataset_sessions")
    op.drop_table("dataset_versions")
    op.drop_table("datasets")
