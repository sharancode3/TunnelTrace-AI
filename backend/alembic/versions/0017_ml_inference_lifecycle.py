"""ML Inference Lifecycle and Lineage: MLInferenceRun and enriched FlowClassification

Revision ID: 0017
Revises: 0016
Create Date: 2026-09-25 18:45:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0017"
down_revision: str | None = "0016"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. Create ml_inference_runs table
    op.create_table(
        "ml_inference_runs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "analysis_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("analysis_runs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "capture_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("captures.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="NOT_CONFIGURED"),
        sa.Column("status_reason", sa.String(length=256), nullable=True),
        sa.Column("bundle_id", sa.String(length=64), nullable=True),
        sa.Column("bundle_version", sa.String(length=32), nullable=True),
        sa.Column("bundle_hash", sa.String(length=64), nullable=True),
        sa.Column("manifest_digest", sa.String(length=64), nullable=True),
        sa.Column("feature_schema_hash", sa.String(length=64), nullable=True),
        sa.Column("sequence_schema_hash", sa.String(length=64), nullable=True),
        sa.Column("calibration_hash", sa.String(length=64), nullable=True),
        sa.Column("ood_hash", sa.String(length=64), nullable=True),
        sa.Column("anomaly_hash", sa.String(length=64), nullable=True),
        sa.Column("inference_runtime", sa.String(length=64), nullable=True),
        sa.Column(
            "environment_metadata",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=True,
        ),
        sa.Column("attempted_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("classified_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("skipped_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("failed_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("is_current", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_ml_inference_runs_analysis_id", "ml_inference_runs", ["analysis_id"])
    op.create_index("ix_ml_inference_runs_capture_id", "ml_inference_runs", ["capture_id"])
    op.create_index("ix_ml_inference_runs_is_current", "ml_inference_runs", ["is_current"])

    # 2. Additive columns for flow_classifications
    op.add_column(
        "flow_classifications",
        sa.Column(
            "run_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("ml_inference_runs.id", ondelete="CASCADE"),
            nullable=True,
        ),
    )
    op.add_column(
        "flow_classifications",
        sa.Column("input_status", sa.String(length=32), nullable=False, server_default="VALID"),
    )
    op.add_column(
        "flow_classifications",
        sa.Column("supervised_hypothesis", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "flow_classifications",
        sa.Column("accepted_prediction", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "flow_classifications",
        sa.Column("calibration_status", sa.String(length=32), nullable=False, server_default="CALIBRATED"),
    )
    op.create_index("ix_flow_classifications_run_id", "flow_classifications", ["run_id"])


def downgrade() -> None:
    # 1. Drop flow_classifications additions
    op.drop_index("ix_flow_classifications_run_id", table_name="flow_classifications")
    op.drop_column("flow_classifications", "calibration_status")
    op.drop_column("flow_classifications", "accepted_prediction")
    op.drop_column("flow_classifications", "supervised_hypothesis")
    op.drop_column("flow_classifications", "input_status")
    op.drop_column("flow_classifications", "run_id")

    # 2. Drop ml_inference_runs
    op.drop_index("ix_ml_inference_runs_is_current", table_name="ml_inference_runs")
    op.drop_index("ix_ml_inference_runs_capture_id", table_name="ml_inference_runs")
    op.drop_index("ix_ml_inference_runs_analysis_id", table_name="ml_inference_runs")
    op.drop_table("ml_inference_runs")
