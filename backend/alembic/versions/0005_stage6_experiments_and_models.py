"""Stage 6 migration: Training Experiments and Model Artifacts

Revision ID: 0005
Revises: 0004
Create Date: 2026-09-24 01:10:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. Create training_experiments table
    op.create_table(
        "training_experiments",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("experiment_id", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False, server_default="xgboost_baseline"),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="CREATED"),
        sa.Column(
            "dataset_version_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("dataset_versions.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("dataset_manifest_hash", sa.String(length=64), nullable=True),
        sa.Column("split_manifest_hash", sa.String(length=64), nullable=True),
        sa.Column("feature_schema_hash", sa.String(length=64), nullable=True),
        sa.Column(
            "hyperparameters",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=True,
        ),
        sa.Column(
            "metrics_summary",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=True,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_training_experiments_experiment_id", "training_experiments", ["experiment_id"], unique=True)
    op.create_index("ix_training_experiments_dataset_version_id", "training_experiments", ["dataset_version_id"])

    # 2. Create model_artifacts table
    op.create_table(
        "model_artifacts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "experiment_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("training_experiments.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("model_family", sa.String(length=32), nullable=False, server_default="XGBOOST"),
        sa.Column("model_version", sa.String(length=32), nullable=False, server_default="v1.0.0-baseline"),
        sa.Column("artifact_state", sa.String(length=32), nullable=False, server_default="EXPERIMENTAL"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("storage_path", sa.String(length=256), nullable=False),
        sa.Column("sha256_hash", sa.String(length=64), nullable=False),
        sa.Column(
            "manifest_data",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=True,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_model_artifacts_experiment_id", "model_artifacts", ["experiment_id"])
    op.create_index("ix_model_artifacts_sha256_hash", "model_artifacts", ["sha256_hash"])


def downgrade() -> None:
    op.drop_index("ix_model_artifacts_sha256_hash", table_name="model_artifacts")
    op.drop_index("ix_model_artifacts_experiment_id", table_name="model_artifacts")
    op.drop_table("model_artifacts")

    op.drop_index("ix_training_experiments_dataset_version_id", table_name="training_experiments")
    op.drop_index("ix_training_experiments_experiment_id", table_name="training_experiments")
    op.drop_table("training_experiments")
