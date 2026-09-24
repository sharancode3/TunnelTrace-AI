"""Stage 3 migration: IKE/IPsec Negotiation Assessment (IKE-scan & Concordance)

Revision ID: 0012
Revises: 0011
Create Date: 2026-09-24 21:30:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0012"
down_revision: str | None = "0011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. ike_assessment_jobs
    op.create_table(
        "ike_assessment_jobs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("job_name", sa.String(length=128), nullable=False),
        sa.Column("operator_id", sa.String(length=128), nullable=False),
        sa.Column("authorization_reference", sa.String(length=256), nullable=False),
        sa.Column("authorization_attestation", sa.Text(), nullable=False),
        sa.Column("authorized_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("target_ip", sa.String(length=64), nullable=False),
        sa.Column("target_port", sa.Integer(), nullable=False, server_default="500"),
        sa.Column("profile", sa.String(length=64), nullable=False, server_default="IKEV1_MAIN_MODE_DISCOVERY"),
        sa.Column("ike_version_requested", sa.String(length=16), nullable=False, server_default="1"),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="QUEUED"),
        sa.Column("failure_reason", sa.Text(), nullable=True),
        sa.Column("raw_output_sha256", sa.String(length=64), nullable=True),
        sa.Column("output_bytes_count", sa.Integer(), nullable=True),
        sa.Column("tool_version", sa.String(length=64), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_ike_assessment_jobs_operator_id", "ike_assessment_jobs", ["operator_id"])
    op.create_index("ix_ike_assessment_jobs_status", "ike_assessment_jobs", ["status"])
    op.create_index("ix_ike_assessment_jobs_target_ip", "ike_assessment_jobs", ["target_ip"])

    # 2. ike_probe_results
    op.create_table(
        "ike_probe_results",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "job_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("ike_assessment_jobs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("target_ip", sa.String(length=64), nullable=False),
        sa.Column("target_port", sa.Integer(), nullable=False),
        sa.Column("response_category", sa.String(length=32), nullable=False),
        sa.Column("ike_version", sa.String(length=16), nullable=False, server_default="IKEv1"),
        sa.Column("handshake_type", sa.String(length=64), nullable=True),
        sa.Column("notify_code", sa.Integer(), nullable=True),
        sa.Column("notify_message", sa.String(length=128), nullable=True),
        sa.Column("vendor_ids", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("transforms_returned", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("rtt_ms", sa.Float(), nullable=True),
        sa.Column("raw_response_text", sa.Text(), nullable=True),
        sa.Column("is_experimental", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_ike_probe_results_job_id", "ike_probe_results", ["job_id"])
    op.create_index("ix_ike_probe_results_target_ip", "ike_probe_results", ["target_ip"])

    # 3. ike_concordance_records
    op.create_table(
        "ike_concordance_records",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "analysis_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("analysis_runs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "ike_job_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("ike_assessment_jobs.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("target_ip", sa.String(length=64), nullable=False),
        sa.Column("concordance_status", sa.String(length=32), nullable=False),
        sa.Column("passive_ike_versions", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("active_ike_versions", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("passive_selected_cipher", sa.String(length=64), nullable=True),
        sa.Column("active_accepted_cipher", sa.String(length=64), nullable=True),
        sa.Column("concordance_details", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("evaluated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_ike_concordance_records_analysis_id", "ike_concordance_records", ["analysis_id"])
    op.create_index("ix_ike_concordance_records_ike_job_id", "ike_concordance_records", ["ike_job_id"])


def downgrade() -> None:
    op.drop_table("ike_concordance_records")
    op.drop_table("ike_probe_results")
    op.drop_table("ike_assessment_jobs")
