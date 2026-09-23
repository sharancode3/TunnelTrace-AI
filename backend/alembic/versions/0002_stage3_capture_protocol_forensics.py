"""Stage 3 migration: Captures, Analysis Runs, Protocol Observations, Live Capture Sessions

Revision ID: 0002
Revises: 0001
Create Date: 2026-09-23 23:45:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. Create captures table
    op.create_table(
        "captures",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("capture_source", sa.String(length=32), nullable=False),
        sa.Column("capture_format", sa.String(length=16), nullable=False),
        sa.Column("original_filename", sa.String(length=255), nullable=True),
        sa.Column("storage_path", sa.String(length=512), nullable=False),
        sa.Column("file_size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("sha256_hash", sa.String(length=64), nullable=False),
        sa.Column("packet_count", sa.Integer(), nullable=True),
        sa.Column("first_packet_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_packet_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("duration_sec", sa.Float(), nullable=True),
        sa.Column("link_layer_type", sa.String(length=64), nullable=True),
        sa.Column(
            "interface_metadata",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=True,
        ),
        sa.Column("validation_state", sa.String(length=32), nullable=False, server_default="VALIDATED"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_captures_sha256_hash", "captures", ["sha256_hash"])

    # 2. Create analysis_runs table
    op.create_table(
        "analysis_runs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "capture_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("captures.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="QUEUED"),
        sa.Column("current_stage", sa.String(length=64), nullable=False, server_default="INGESTING"),
        sa.Column("parser_engine", sa.String(length=32), nullable=False, server_default="tshark"),
        sa.Column("parser_version", sa.String(length=32), nullable=False, server_default="unknown"),
        sa.Column("schema_version", sa.String(length=16), nullable=False, server_default="1.0.0"),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_code", sa.String(length=64), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_analysis_runs_capture_id", "analysis_runs", ["capture_id"])
    op.create_index("ix_analysis_runs_status", "analysis_runs", ["status"])

    # 3. Create protocol_observations table
    op.create_table(
        "protocol_observations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "analysis_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("analysis_runs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("frame_number", sa.Integer(), nullable=False),
        sa.Column("frame_offset", sa.BigInteger(), nullable=True),
        sa.Column("packet_time", sa.Float(), nullable=False),
        sa.Column("protocol", sa.String(length=32), nullable=False),
        sa.Column("category", sa.String(length=64), nullable=False),
        sa.Column("field_name", sa.String(length=128), nullable=False),
        sa.Column("normalized_value", sa.Text(), nullable=False),
        sa.Column("raw_value", sa.Text(), nullable=True),
        sa.Column("raw_numeric_id", sa.Integer(), nullable=True),
        sa.Column("source_field", sa.String(length=128), nullable=False),
        sa.Column("source_tool", sa.String(length=32), nullable=False, server_default="tshark"),
        sa.Column("source_tool_version", sa.String(length=32), nullable=False),
        sa.Column("evidence_state", sa.String(length=32), nullable=False, server_default="VERIFIED"),
        sa.Column("src_ip", sa.String(length=64), nullable=True),
        sa.Column("dst_ip", sa.String(length=64), nullable=True),
        sa.Column("src_port", sa.Integer(), nullable=True),
        sa.Column("dst_port", sa.Integer(), nullable=True),
        sa.Column(
            "extra_attributes",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=True,
        ),
    )
    op.create_index("ix_protocol_observations_analysis_id", "protocol_observations", ["analysis_id"])
    op.create_index("ix_protocol_observations_frame_number", "protocol_observations", ["frame_number"])
    op.create_index("ix_protocol_observations_protocol", "protocol_observations", ["protocol"])
    op.create_index("ix_protocol_observations_category", "protocol_observations", ["category"])
    op.create_index("ix_protocol_observations_evidence_state", "protocol_observations", ["evidence_state"])

    # 4. Create live_capture_sessions table
    op.create_table(
        "live_capture_sessions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("interface_name", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="CREATED"),
        sa.Column("capture_profile", sa.String(length=64), nullable=False, server_default="IPSEC_RELEVANT"),
        sa.Column("bpf_filter", sa.String(length=255), nullable=True),
        sa.Column("max_duration_sec", sa.Integer(), nullable=True),
        sa.Column("max_bytes", sa.BigInteger(), nullable=True),
        sa.Column("packet_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("byte_count", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("storage_path", sa.String(length=512), nullable=True),
        sa.Column(
            "capture_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("captures.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("stopped_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_live_capture_sessions_status", "live_capture_sessions", ["status"])


def downgrade() -> None:
    op.drop_table("live_capture_sessions")
    op.drop_table("protocol_observations")
    op.drop_table("analysis_runs")
    op.drop_table("captures")
