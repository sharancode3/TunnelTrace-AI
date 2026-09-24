"""Stage 8 migration: Security, Compliance, Evidence & Scoring

Revision ID: 0007
Revises: 0006
Create Date: 2026-09-24 08:30:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0007"
down_revision: str | None = "0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. Policy Bundles
    op.create_table(
        "policy_bundles",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("bundle_id", sa.String(length=64), nullable=False),
        sa.Column("bundle_version", sa.String(length=32), nullable=False),
        sa.Column("profile_id", sa.String(length=64), nullable=False),
        sa.Column("bundle_hash", sa.String(length=64), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column(
            "manifest_data",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=True,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_policy_bundles_bundle_id", "policy_bundles", ["bundle_id"])
    op.create_index("ix_policy_bundles_profile_id", "policy_bundles", ["profile_id"])

    # 2. Compliance Evaluations
    op.create_table(
        "compliance_evaluations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "analysis_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("analysis_runs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("bundle_id", sa.String(length=64), nullable=False),
        sa.Column("rule_id", sa.String(length=64), nullable=False),
        sa.Column("rule_version", sa.String(length=32), nullable=False),
        sa.Column("subject_type", sa.String(length=32), nullable=False),
        sa.Column("subject_id", sa.String(length=64), nullable=False),
        sa.Column("compliance_state", sa.String(length=32), nullable=False),
        sa.Column("evidence_state", sa.String(length=32), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_compliance_evaluations_analysis_id", "compliance_evaluations", ["analysis_id"])
    op.create_index("ix_compliance_evaluations_rule_id", "compliance_evaluations", ["rule_id"])

    # 3. Security Findings
    op.create_table(
        "security_findings",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("finding_id", sa.String(length=64), nullable=False),
        sa.Column(
            "analysis_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("analysis_runs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("rule_id", sa.String(length=64), nullable=False),
        sa.Column("rule_version", sa.String(length=32), nullable=False),
        sa.Column("profile_id", sa.String(length=64), nullable=False),
        sa.Column("category", sa.String(length=64), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("title", sa.String(length=256), nullable=False),
        sa.Column("technical_description", sa.Text(), nullable=False),
        sa.Column("root_cause_key", sa.String(length=128), nullable=False),
        sa.Column("affected_entity_type", sa.String(length=64), nullable=False),
        sa.Column("affected_entity_id", sa.String(length=64), nullable=False),
        sa.Column(
            "observed_value",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=True,
        ),
        sa.Column(
            "expected_requirement",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=True,
        ),
        sa.Column("evidence_state", sa.String(length=32), nullable=False),
        sa.Column("remediation_guidance", sa.Text(), nullable=True),
        sa.Column("remediation_directive", sa.Text(), nullable=True),
        sa.Column("record_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_security_findings_finding_id", "security_findings", ["finding_id"])
    op.create_index("ix_security_findings_analysis_id", "security_findings", ["analysis_id"])
    op.create_index("ix_security_findings_root_cause_key", "security_findings", ["root_cause_key"])

    # 4. Score Assessments
    op.create_table(
        "score_assessments",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "analysis_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("analysis_runs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("overall_score", sa.Float(), nullable=False),
        sa.Column("raw_score", sa.Float(), nullable=False),
        sa.Column("score_policy_id", sa.String(length=64), nullable=False),
        sa.Column("score_policy_version", sa.String(length=32), nullable=False),
        sa.Column("score_policy_hash", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("coverage_percentage", sa.Float(), nullable=False),
        sa.Column(
            "category_scores",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=True,
        ),
        sa.Column(
            "deduction_audit",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=True,
        ),
        sa.Column(
            "evidence_coverage",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=True,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_score_assessments_analysis_id", "score_assessments", ["analysis_id"])

    # 5. Risk Assessments
    op.create_table(
        "risk_assessments",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "analysis_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("analysis_runs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("risk_policy_id", sa.String(length=64), nullable=False),
        sa.Column("risk_policy_version", sa.String(length=32), nullable=False),
        sa.Column("risk_policy_hash", sa.String(length=64), nullable=False),
        sa.Column("overall_risk_tier", sa.String(length=32), nullable=False),
        sa.Column(
            "items",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=True,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_risk_assessments_analysis_id", "risk_assessments", ["analysis_id"])

    # 6. Threat Instances
    op.create_table(
        "threat_instances",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "analysis_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("analysis_runs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("finding_id", sa.String(length=64), nullable=False),
        sa.Column("threat_id", sa.String(length=64), nullable=False),
        sa.Column("threat_name", sa.String(length=256), nullable=False),
        sa.Column("attack_vector", sa.Text(), nullable=False),
        sa.Column("likelihood", sa.String(length=32), nullable=False),
        sa.Column("impact", sa.String(length=32), nullable=False),
        sa.Column("risk_tier", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_threat_instances_analysis_id", "threat_instances", ["analysis_id"])
    op.create_index("ix_threat_instances_finding_id", "threat_instances", ["finding_id"])
    op.create_index("ix_threat_instances_threat_id", "threat_instances", ["threat_id"])

    # 7. Fingerprintability Assessments
    op.create_table(
        "fingerprintability_assessments",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "analysis_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("analysis_runs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("overall_index", sa.Float(), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("methodology_version", sa.String(length=64), nullable=False),
        sa.Column("methodology_hash", sa.String(length=64), nullable=False),
        sa.Column(
            "components",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=True,
        ),
        sa.Column("flow_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("calibration_status", sa.String(length=32), nullable=False),
        sa.Column("ml_model_bundle_id", sa.String(length=64), nullable=True),
        sa.Column("disclaimer", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_fingerprintability_assessments_analysis_id", "fingerprintability_assessments", ["analysis_id"])

    # 8. Evidence Graphs
    op.create_table(
        "evidence_graphs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "analysis_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("analysis_runs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("capture_sha256", sa.String(length=64), nullable=False),
        sa.Column("nodes_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("edges_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column(
            "graph_data",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=True,
        ),
        sa.Column(
            "manifest_data",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=True,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_evidence_graphs_analysis_id", "evidence_graphs", ["analysis_id"])


def downgrade() -> None:
    op.drop_table("evidence_graphs")
    op.drop_table("fingerprintability_assessments")
    op.drop_table("threat_instances")
    op.drop_table("risk_assessments")
    op.drop_table("score_assessments")
    op.drop_table("security_findings")
    op.drop_table("compliance_evaluations")
    op.drop_table("policy_bundles")
