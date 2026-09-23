"""Stage 4 migration: IKE Sessions, Security Associations, Traffic Selectors, ESP Flows

Revision ID: 0003
Revises: 0002
Create Date: 2026-09-24 00:10:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. Create ike_sessions table
    op.create_table(
        "ike_sessions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "analysis_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("analysis_runs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("initiator_spi", sa.String(length=32), nullable=False),
        sa.Column("responder_spi", sa.String(length=32), nullable=True),
        sa.Column("ike_version", sa.String(length=16), nullable=False, server_default="IKEv2"),
        sa.Column("initiator_ip", sa.String(length=64), nullable=True),
        sa.Column("responder_ip", sa.String(length=64), nullable=True),
        sa.Column("initiator_port", sa.Integer(), nullable=True),
        sa.Column("responder_port", sa.Integer(), nullable=True),
        sa.Column("first_observed_at", sa.Float(), nullable=False),
        sa.Column("last_observed_at", sa.Float(), nullable=False),
        sa.Column("lifecycle_state", sa.String(length=32), nullable=False, server_default="ACTIVE_INFERRED"),
        sa.Column("is_nat_detected", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("retransmission_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("packet_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("evidence_state", sa.String(length=32), nullable=False, server_default="VERIFIED"),
        sa.Column(
            "frame_numbers",
            sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql"),
            nullable=True,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_ike_sessions_analysis_id", "ike_sessions", ["analysis_id"])
    op.create_index("ix_ike_sessions_initiator_spi", "ike_sessions", ["initiator_spi"])
    op.create_index("ix_ike_sessions_responder_spi", "ike_sessions", ["responder_spi"])

    # 2. Create ike_security_associations table
    op.create_table(
        "ike_security_associations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "session_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("ike_sessions.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("encryption_algorithm", sa.String(length=64), nullable=True),
        sa.Column("key_length_bits", sa.Integer(), nullable=True),
        sa.Column("prf_algorithm", sa.String(length=64), nullable=True),
        sa.Column("integrity_algorithm", sa.String(length=64), nullable=True),
        sa.Column("dh_group", sa.String(length=64), nullable=True),
        sa.Column("selection_evidence_state", sa.String(length=32), nullable=False, server_default="VERIFIED"),
        sa.Column("established_at", sa.Float(), nullable=True),
        sa.Column("evidence_state", sa.String(length=32), nullable=False, server_default="VERIFIED"),
    )
    op.create_index("ix_ike_sa_session_id", "ike_security_associations", ["session_id"])

    # 3. Create child_security_associations table
    op.create_table(
        "child_security_associations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "analysis_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("analysis_runs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "ike_sa_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("ike_security_associations.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("protocol", sa.String(length=8), nullable=False, server_default="ESP"),
        sa.Column("inbound_spi", sa.String(length=32), nullable=False),
        sa.Column("outbound_spi", sa.String(length=32), nullable=True),
        sa.Column("src_ip", sa.String(length=64), nullable=True),
        sa.Column("dst_ip", sa.String(length=64), nullable=True),
        sa.Column("mode", sa.String(length=16), nullable=False, server_default="UNKNOWN"),
        sa.Column("mode_evidence_state", sa.String(length=32), nullable=False, server_default="UNKNOWN"),
        sa.Column("encryption_algorithm", sa.String(length=64), nullable=True),
        sa.Column("integrity_algorithm", sa.String(length=64), nullable=True),
        sa.Column("pfs_status", sa.String(length=32), nullable=False, server_default="UNKNOWN"),
        sa.Column("pfs_dh_group", sa.String(length=64), nullable=True),
        sa.Column("pfs_evidence_state", sa.String(length=32), nullable=False, server_default="UNKNOWN"),
        sa.Column("first_observed_at", sa.Float(), nullable=True),
        sa.Column("last_observed_at", sa.Float(), nullable=True),
        sa.Column("lifecycle_state", sa.String(length=32), nullable=False, server_default="ACTIVE_INFERRED"),
        sa.Column("evidence_state", sa.String(length=32), nullable=False, server_default="VERIFIED"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_child_sa_analysis_id", "child_security_associations", ["analysis_id"])
    op.create_index("ix_child_sa_ike_sa_id", "child_security_associations", ["ike_sa_id"])
    op.create_index("ix_child_sa_inbound_spi", "child_security_associations", ["inbound_spi"])
    op.create_index("ix_child_sa_outbound_spi", "child_security_associations", ["outbound_spi"])

    # 4. Create traffic_selectors table
    op.create_table(
        "traffic_selectors",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "child_sa_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("child_security_associations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("direction", sa.String(length=16), nullable=False),
        sa.Column("ip_subnet", sa.String(length=64), nullable=True),
        sa.Column("start_ip", sa.String(length=64), nullable=True),
        sa.Column("end_ip", sa.String(length=64), nullable=True),
        sa.Column("ip_protocol", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("start_port", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("end_port", sa.Integer(), nullable=False, server_default="65535"),
        sa.Column("evidence_state", sa.String(length=32), nullable=False, server_default="VERIFIED"),
    )
    op.create_index("ix_traffic_selectors_child_sa_id", "traffic_selectors", ["child_sa_id"])

    # 5. Create esp_flows table
    op.create_table(
        "esp_flows",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "analysis_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("analysis_runs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "child_sa_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("child_security_associations.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("spi", sa.String(length=32), nullable=False),
        sa.Column("reverse_spi", sa.String(length=32), nullable=True),
        sa.Column("src_ip", sa.String(length=64), nullable=False),
        sa.Column("dst_ip", sa.String(length=64), nullable=False),
        sa.Column("ip_version", sa.String(length=8), nullable=False, server_default="IPv4"),
        sa.Column("is_nat_t", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("orientation_basis", sa.String(length=32), nullable=False, server_default="FIRST_SEEN"),
        sa.Column("start_time", sa.Float(), nullable=False),
        sa.Column("end_time", sa.Float(), nullable=False),
        sa.Column("duration_seconds", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("packet_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("byte_count", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("forward_packets", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("forward_bytes", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("reverse_packets", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("reverse_bytes", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("association_state", sa.String(length=32), nullable=False, server_default="PAIRED_BIDIRECTIONAL"),
        sa.Column("end_reason", sa.String(length=32), nullable=False, server_default="CAPTURE_ENDED"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_esp_flows_analysis_id", "esp_flows", ["analysis_id"])
    op.create_index("ix_esp_flows_child_sa_id", "esp_flows", ["child_sa_id"])
    op.create_index("ix_esp_flows_spi", "esp_flows", ["spi"])
    op.create_index("ix_esp_flows_reverse_spi", "esp_flows", ["reverse_spi"])


def downgrade() -> None:
    op.drop_table("esp_flows")
    op.drop_table("traffic_selectors")
    op.drop_table("child_security_associations")
    op.drop_table("ike_security_associations")
    op.drop_table("ike_sessions")
