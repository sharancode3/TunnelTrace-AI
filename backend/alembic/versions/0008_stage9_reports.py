"""Stage 9 migration: Report records and artifact provenance

Revision ID: 0008
Revises: 0007
Create Date: 2026-09-24 10:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0008"
down_revision: str | None = "0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "reports",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "analysis_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("analysis_runs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("report_type", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="QUEUED"),
        sa.Column("format", sa.String(length=32), nullable=False, server_default="HTML"),
        sa.Column("template_version", sa.String(length=32), nullable=False, server_default="1.0.0"),
        sa.Column("engine_version", sa.String(length=32), nullable=False, server_default="1.0.0"),
        sa.Column("html_artifact_path", sa.String(length=512), nullable=True),
        sa.Column("html_sha256", sa.String(length=64), nullable=True),
        sa.Column("pdf_artifact_path", sa.String(length=512), nullable=True),
        sa.Column("pdf_sha256", sa.String(length=64), nullable=True),
        sa.Column("snapshot_manifest_sha256", sa.String(length=64), nullable=True),
        sa.Column("metadata_json", sa.JSON().with_variant(postgresql.JSONB, "postgresql"), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("generation_duration_ms", sa.Float(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_reports_analysis_id", "reports", ["analysis_id"])
    op.create_index("ix_reports_report_type", "reports", ["report_type"])
    op.create_index("ix_reports_status", "reports", ["status"])


def downgrade() -> None:
    op.drop_index("ix_reports_status", table_name="reports")
    op.drop_index("ix_reports_report_type", table_name="reports")
    op.drop_index("ix_reports_analysis_id", table_name="reports")
    op.drop_table("reports")
