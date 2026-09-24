"""Stage 10 migration: Configuration Security Twin and Closed-Loop Remediation

Revision ID: 0009
Revises: 0008
Create Date: 2026-09-24 16:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0009"
down_revision: str | None = "0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. configuration_snapshots
    op.create_table(
        "configuration_snapshots",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "analysis_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("analysis_runs.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("snapshot_type", sa.String(length=32), nullable=False),
        sa.Column("config_format", sa.String(length=16), nullable=False, server_default="SWANCTL"),
        sa.Column("normalized_ir", sa.JSON().with_variant(postgresql.JSONB, "postgresql"), nullable=True),
        sa.Column("config_content", sa.Text(), nullable=True),
        sa.Column("config_hash", sa.String(length=64), nullable=False),
        sa.Column("provenance", sa.JSON().with_variant(postgresql.JSONB, "postgresql"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_configuration_snapshots_analysis_id", "configuration_snapshots", ["analysis_id"])
    op.create_index("ix_configuration_snapshots_snapshot_type", "configuration_snapshots", ["snapshot_type"])
    op.create_index("ix_configuration_snapshots_config_hash", "configuration_snapshots", ["config_hash"])

    # 2. configuration_twins
    op.create_table(
        "configuration_twins",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "analysis_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("analysis_runs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "observed_snapshot_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("configuration_snapshots.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "hardened_snapshot_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("configuration_snapshots.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("proposal_hash", sa.String(length=64), nullable=False),
        sa.Column("projected_score", sa.Numeric(precision=5, scale=2), nullable=True),
        sa.Column("projected_score_delta", sa.Numeric(precision=5, scale=2), nullable=True),
        sa.Column("diff_text", sa.Text(), nullable=True),
        sa.Column("semantic_diff", sa.JSON().with_variant(postgresql.JSONB, "postgresql"), nullable=True),
        sa.Column("projected_regression_audit", sa.JSON().with_variant(postgresql.JSONB, "postgresql"), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="PROJECTED"),
        sa.Column("policy_bundle_version", sa.String(length=64), nullable=False, server_default="1.0.0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_configuration_twins_analysis_id", "configuration_twins", ["analysis_id"])
    op.create_index("ix_configuration_twins_proposal_hash", "configuration_twins", ["proposal_hash"])
    op.create_index("ix_configuration_twins_status", "configuration_twins", ["status"])

    # 3. remediation_runs
    op.create_table(
        "remediation_runs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "twin_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("configuration_twins.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("lab_instance_id", sa.String(length=64), nullable=False, server_default="strongswan-lab-default"),
        sa.Column("proposal_hash", sa.String(length=64), nullable=False),
        sa.Column("operator_id", sa.String(length=64), nullable=False, server_default="analyst-local"),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="CREATED"),
        sa.Column(
            "backup_snapshot_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("configuration_snapshots.id", ondelete="RESTRICT"),
            nullable=True,
        ),
        sa.Column(
            "applied_snapshot_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("configuration_snapshots.id", ondelete="RESTRICT"),
            nullable=True,
        ),
        sa.Column("rollback_state", sa.String(length=32), nullable=False, server_default="NONE"),
        sa.Column("rollback_reason", sa.Text(), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("approval_timestamp", sa.DateTime(timezone=True), nullable=True),
        sa.Column("executed_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_remediation_runs_twin_id", "remediation_runs", ["twin_id"])
    op.create_index("ix_remediation_runs_status", "remediation_runs", ["status"])
    op.create_index("ix_remediation_runs_proposal_hash", "remediation_runs", ["proposal_hash"])

    # 4. remediation_run_steps
    op.create_table(
        "remediation_run_steps",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "remediation_run_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("remediation_runs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("action_type", sa.String(length=64), nullable=False),
        sa.Column("input_hash", sa.String(length=64), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="PENDING"),
        sa.Column("safe_output", sa.JSON().with_variant(postgresql.JSONB, "postgresql"), nullable=True),
        sa.Column("error_code", sa.String(length=64), nullable=True),
        sa.Column("duration_ms", sa.Float(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_remediation_run_steps_run_id", "remediation_run_steps", ["remediation_run_id"])
    op.create_index("ix_remediation_run_steps_action_type", "remediation_run_steps", ["action_type"])

    # 5. remediation_verifications
    op.create_table(
        "remediation_verifications",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "remediation_run_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("remediation_runs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "baseline_analysis_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("analysis_runs.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "post_analysis_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("analysis_runs.id", ondelete="RESTRICT"),
            nullable=True,
        ),
        sa.Column(
            "post_capture_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("captures.id", ondelete="RESTRICT"),
            nullable=True,
        ),
        sa.Column("verification_result", sa.String(length=32), nullable=False),
        sa.Column("security_result", sa.String(length=32), nullable=False, server_default="UNKNOWN"),
        sa.Column("operational_result", sa.String(length=32), nullable=False, server_default="HEALTHY"),
        sa.Column("baseline_score", sa.Numeric(precision=5, scale=2), nullable=True),
        sa.Column("verified_score", sa.Numeric(precision=5, scale=2), nullable=True),
        sa.Column("score_delta", sa.Numeric(precision=5, scale=2), nullable=True),
        sa.Column("finding_diff_summary", sa.JSON().with_variant(postgresql.JSONB, "postgresql"), nullable=True),
        sa.Column("regression_summary", sa.JSON().with_variant(postgresql.JSONB, "postgresql"), nullable=True),
        sa.Column("workload_manifest", sa.JSON().with_variant(postgresql.JSONB, "postgresql"), nullable=True),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_remediation_verifications_run_id", "remediation_verifications", ["remediation_run_id"])
    op.create_index("ix_remediation_verifications_baseline_id", "remediation_verifications", ["baseline_analysis_id"])
    op.create_index("ix_remediation_verifications_post_id", "remediation_verifications", ["post_analysis_id"])
    op.create_index("ix_remediation_verifications_result", "remediation_verifications", ["verification_result"])

    # 6. remediation_verification_claims
    op.create_table(
        "remediation_verification_claims",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "verification_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("remediation_verifications.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("baseline_finding_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("rule_id", sa.String(length=128), nullable=False),
        sa.Column("rule_version", sa.String(length=32), nullable=False),
        sa.Column("root_cause_key", sa.String(length=128), nullable=False),
        sa.Column("baseline_evidence", sa.JSON().with_variant(postgresql.JSONB, "postgresql"), nullable=True),
        sa.Column("proposed_transformation", sa.JSON().with_variant(postgresql.JSONB, "postgresql"), nullable=True),
        sa.Column("expected_condition", sa.Text(), nullable=True),
        sa.Column("post_finding_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("post_evidence", sa.JSON().with_variant(postgresql.JSONB, "postgresql"), nullable=True),
        sa.Column("claim_result", sa.String(length=32), nullable=False),
        sa.Column("reason_code", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_remediation_claims_verification_id", "remediation_verification_claims", ["verification_id"])
    op.create_index("ix_remediation_claims_rule_id", "remediation_verification_claims", ["rule_id"])
    op.create_index("ix_remediation_claims_root_cause_key", "remediation_verification_claims", ["root_cause_key"])


def downgrade() -> None:
    op.drop_table("remediation_verification_claims")
    op.drop_table("remediation_verifications")
    op.drop_table("remediation_run_steps")
    op.drop_table("remediation_runs")
    op.drop_table("configuration_twins")
    op.drop_table("configuration_snapshots")
