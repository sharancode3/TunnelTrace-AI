"""Continuous Monitoring: Authorized VPN Gateways, Sensors, Events, Health & SA State Projections

Revision ID: 0014
Revises: 0013
Create Date: 2026-09-24 23:10:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0014"
down_revision: str | None = "0013"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. monitored_gateways
    op.create_table(
        "monitored_gateways",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(length=128), nullable=False, unique=True),
        sa.Column("gateway_ip", sa.String(length=64), nullable=False),
        sa.Column("authorized_scope", sa.String(length=256), nullable=False),
        sa.Column("operator_id", sa.String(length=128), nullable=False),
        sa.Column("authorization_reference", sa.String(length=256), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="ACTIVE"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_monitored_gateways_status", "monitored_gateways", ["status"])

    # 2. monitored_sensors
    op.create_table(
        "monitored_sensors",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("sensor_name", sa.String(length=128), nullable=False, unique=True),
        sa.Column("sensor_type", sa.String(length=32), nullable=False),
        sa.Column(
            "gateway_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("monitored_gateways.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("authorized_scope", sa.String(length=256), nullable=False),
        sa.Column("auth_token_hash", sa.String(length=64), nullable=False),
        sa.Column("token_prefix", sa.String(length=16), nullable=False),
        sa.Column("freshness_window_seconds", sa.Integer(), nullable=False, server_default="60"),
        sa.Column("reporting_interval_seconds", sa.Integer(), nullable=False, server_default="30"),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="ACTIVE"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_heartbeat_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_monitored_sensors_gateway_id", "monitored_sensors", ["gateway_id"])
    op.create_index("ix_monitored_sensors_auth_token_hash", "monitored_sensors", ["auth_token_hash"])
    op.create_index("ix_monitored_sensors_status", "monitored_sensors", ["status"])

    # 3. monitoring_events
    op.create_table(
        "monitoring_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("event_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("schema_version", sa.String(length=16), nullable=False, server_default="v1.0.0"),
        sa.Column(
            "sensor_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("monitored_sensors.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "gateway_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("monitored_gateways.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("authorized_scope", sa.String(length=256), nullable=False),
        sa.Column("event_kind", sa.String(length=64), nullable=False),
        sa.Column("source_timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("clock_skew_seconds", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("sequence_number", sa.Integer(), nullable=True),
        sa.Column("source_boot_id", sa.String(length=64), nullable=True),
        sa.Column("source_session_id", sa.String(length=64), nullable=True),
        sa.Column("evidence_grade", sa.String(length=32), nullable=False, server_default="OBSERVED"),
        sa.Column("raw_source_status", sa.Text(), nullable=True),
        sa.Column("ike_version", sa.String(length=16), nullable=True),
        sa.Column("local_endpoint", sa.String(length=64), nullable=True),
        sa.Column("remote_endpoint", sa.String(length=64), nullable=True),
        sa.Column("initiator_spi", sa.String(length=32), nullable=True),
        sa.Column("responder_spi", sa.String(length=32), nullable=True),
        sa.Column("child_spi_in", sa.String(length=32), nullable=True),
        sa.Column("child_spi_out", sa.String(length=32), nullable=True),
        sa.Column("cipher_suite", sa.String(length=128), nullable=True),
        sa.Column("failure_reason", sa.Text(), nullable=True),
        sa.Column("failure_code", sa.String(length=64), nullable=True),
        sa.Column("interface_name", sa.String(length=64), nullable=True),
        sa.Column("packet_count", sa.Integer(), nullable=True),
        sa.Column("drop_count", sa.Integer(), nullable=True),
        sa.Column("byte_count", sa.Integer(), nullable=True),
        sa.Column("artifact_hash", sa.String(length=64), nullable=True),
        sa.Column("collector_version", sa.String(length=64), nullable=True),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.UniqueConstraint("sensor_id", "event_id", name="uq_monitoring_sensor_event"),
    )
    op.create_index("ix_monitoring_events_event_id", "monitoring_events", ["event_id"])
    op.create_index("ix_monitoring_events_sensor_id", "monitoring_events", ["sensor_id"])
    op.create_index("ix_monitoring_events_gateway_id", "monitoring_events", ["gateway_id"])
    op.create_index("ix_monitoring_events_event_kind", "monitoring_events", ["event_kind"])
    op.create_index("ix_monitoring_events_source_timestamp", "monitoring_events", ["source_timestamp"])
    op.create_index("ix_monitoring_events_received_at", "monitoring_events", ["received_at"])
    op.create_index("ix_monitoring_events_initiator_spi", "monitoring_events", ["initiator_spi"])
    op.create_index("ix_monitoring_events_child_spi_in", "monitoring_events", ["child_spi_in"])
    op.create_index("ix_monitoring_events_gw_time", "monitoring_events", ["gateway_id", "source_timestamp"])
    op.create_index("ix_monitoring_events_sn_seq", "monitoring_events", ["sensor_id", "sequence_number"])
    op.create_index("ix_monitoring_events_kind_time", "monitoring_events", ["event_kind", "source_timestamp"])

    # 4. sensor_health_states
    op.create_table(
        "sensor_health_states",
        sa.Column(
            "sensor_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("monitored_sensors.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("current_health", sa.String(length=32), nullable=False, server_default="UNKNOWN"),
        sa.Column("health_reason", sa.Text(), nullable=False, server_default="No events received"),
        sa.Column("last_source_timestamp", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_received_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("total_events_received", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("total_drops_reported", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_sequence_number", sa.Integer(), nullable=True),
        sa.Column("sequence_gaps_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("clock_skew_seconds", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("active_quality_warnings", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default="[]"),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    # 5. monitored_sa_states
    op.create_table(
        "monitored_sa_states",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "gateway_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("monitored_gateways.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "sensor_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("monitored_sensors.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("sa_type", sa.String(length=16), nullable=False),
        sa.Column("initiator_spi", sa.String(length=32), nullable=False),
        sa.Column("responder_spi", sa.String(length=32), nullable=True),
        sa.Column("child_spi_in", sa.String(length=32), nullable=True),
        sa.Column("child_spi_out", sa.String(length=32), nullable=True),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.Column("local_endpoint", sa.String(length=64), nullable=True),
        sa.Column("remote_endpoint", sa.String(length=64), nullable=True),
        sa.Column("cipher_suite", sa.String(length=128), nullable=True),
        sa.Column("established_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_event_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_event_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("is_stale", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("staleness_reason", sa.String(length=256), nullable=True),
        sa.Column("evidence_grade", sa.String(length=32), nullable=False, server_default="OBSERVED"),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("gateway_id", "initiator_spi", "child_spi_in", name="uq_gateway_sa_identity"),
    )
    op.create_index("ix_monitored_sa_states_gateway_id", "monitored_sa_states", ["gateway_id"])
    op.create_index("ix_monitored_sa_states_sensor_id", "monitored_sa_states", ["sensor_id"])
    op.create_index("ix_monitored_sa_states_initiator_spi", "monitored_sa_states", ["initiator_spi"])
    op.create_index("ix_monitored_sa_states_child_spi_in", "monitored_sa_states", ["child_spi_in"])


def downgrade() -> None:
    op.drop_table("monitored_sa_states")
    op.drop_table("sensor_health_states")
    op.drop_table("monitoring_events")
    op.drop_table("monitored_sensors")
    op.drop_table("monitored_gateways")
