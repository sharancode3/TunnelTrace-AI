"""SQLAlchemy models for Continuous Monitoring (Gateways, Sensors, Events, Health & SA State Projections)."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from app.db.base import Base


class MonitoredGateway(Base):
    """Explicitly authorized VPN gateway boundary monitored by TunnelTrace AI."""

    __tablename__ = "monitored_gateways"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    gateway_ip: Mapped[str] = mapped_column(String(64), nullable=False)
    authorized_scope: Mapped[str] = mapped_column(
        String(256), nullable=False
    )  # e.g., "198.51.100.0/24"
    operator_id: Mapped[str] = mapped_column(String(128), nullable=False)
    authorization_reference: Mapped[str] = mapped_column(String(256), nullable=False)
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="ACTIVE"
    )  # ACTIVE, INACTIVE, REVOKED
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    # Relationships
    sensors: Mapped[list[MonitoredSensor]] = relationship(
        "MonitoredSensor", back_populates="gateway", cascade="all, delete-orphan"
    )
    events: Mapped[list[MonitoringEvent]] = relationship(
        "MonitoringEvent", back_populates="gateway", cascade="all, delete-orphan"
    )
    sa_states: Mapped[list[MonitoredSAState]] = relationship(
        "MonitoredSAState", back_populates="gateway", cascade="all, delete-orphan"
    )


class MonitoredSensor(Base):
    """Registered telemetry sensor or collector bound to an authorized gateway and scope."""

    __tablename__ = "monitored_sensors"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    sensor_name: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    sensor_type: Mapped[str] = mapped_column(
        String(32), nullable=False
    )  # GATEWAY_COLLECTOR, CAPTURE_SENSOR
    gateway_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("monitored_gateways.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    authorized_scope: Mapped[str] = mapped_column(String(256), nullable=False)
    auth_token_hash: Mapped[str] = mapped_column(
        String(64), nullable=False, index=True
    )  # SHA-256 hash of secret token
    token_prefix: Mapped[str] = mapped_column(String(16), nullable=False)
    freshness_window_seconds: Mapped[int] = mapped_column(
        Integer, nullable=False, default=60
    )
    reporting_interval_seconds: Mapped[int] = mapped_column(
        Integer, nullable=False, default=30
    )
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="ACTIVE"
    )  # ACTIVE, REVOKED, DISABLED
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_heartbeat_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Relationships
    gateway: Mapped[MonitoredGateway] = relationship(
        "MonitoredGateway", back_populates="sensors"
    )
    events: Mapped[list[MonitoringEvent]] = relationship(
        "MonitoringEvent", back_populates="sensor", cascade="all, delete-orphan"
    )
    health_state: Mapped[SensorHealthState | None] = relationship(
        "SensorHealthState", back_populates="sensor", uselist=False, cascade="all, delete-orphan"
    )
    sa_states: Mapped[list[MonitoredSAState]] = relationship(
        "MonitoredSAState", back_populates="sensor", cascade="all, delete-orphan"
    )


class MonitoringEvent(Base):
    """Append-only immutable event evidence ingested from an authorized sensor."""

    __tablename__ = "monitoring_events"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    event_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), nullable=False, index=True
    )
    schema_version: Mapped[str] = mapped_column(
        String(16), nullable=False, default="v1.0.0"
    )
    sensor_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("monitored_sensors.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    gateway_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("monitored_gateways.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    authorized_scope: Mapped[str] = mapped_column(String(256), nullable=False)
    event_kind: Mapped[str] = mapped_column(
        String(64), nullable=False, index=True
    )  # GATEWAY_IKE_SA_*, GATEWAY_CHILD_SA_*, CAPTURE_*
    source_timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )
    clock_skew_seconds: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    sequence_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    source_boot_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    source_session_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    evidence_grade: Mapped[str] = mapped_column(
        String(32), nullable=False, default="OBSERVED"
    )  # OBSERVED, INFERRED, UNKNOWN, UNAVAILABLE
    raw_source_status: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Normalized IKE / SA attributes
    ike_version: Mapped[str | None] = mapped_column(String(16), nullable=True)
    local_endpoint: Mapped[str | None] = mapped_column(String(64), nullable=True)
    remote_endpoint: Mapped[str | None] = mapped_column(String(64), nullable=True)
    initiator_spi: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    responder_spi: Mapped[str | None] = mapped_column(String(32), nullable=True)
    child_spi_in: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    child_spi_out: Mapped[str | None] = mapped_column(String(32), nullable=True)
    cipher_suite: Mapped[str | None] = mapped_column(String(128), nullable=True)
    failure_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    failure_code: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Normalized Capture attributes
    interface_name: Mapped[str | None] = mapped_column(String(64), nullable=True)
    packet_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    drop_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    byte_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    artifact_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Provenance and sanitized payload (zero secrets)
    collector_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    payload: Mapped[dict | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )

    # Relationships
    gateway: Mapped[MonitoredGateway] = relationship(
        "MonitoredGateway", back_populates="events"
    )
    sensor: Mapped[MonitoredSensor] = relationship(
        "MonitoredSensor", back_populates="events"
    )

    __table_args__ = (
        UniqueConstraint("sensor_id", "event_id", name="uq_monitoring_sensor_event"),
        Index("ix_monitoring_events_gw_time", "gateway_id", "source_timestamp"),
        Index("ix_monitoring_events_sn_seq", "sensor_id", "sequence_number"),
        Index("ix_monitoring_events_kind_time", "event_kind", "source_timestamp"),
    )


class SensorHealthState(Base):
    """Rebuildable projection tracking real-time sensor health, freshness, drops, and sequence gaps."""

    __tablename__ = "sensor_health_states"

    sensor_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("monitored_sensors.id", ondelete="CASCADE"),
        primary_key=True,
    )
    current_health: Mapped[str] = mapped_column(
        String(32), nullable=False, default="UNKNOWN"
    )  # HEALTHY, DEGRADED, STALE, UNAVAILABLE, UNKNOWN, DISABLED
    health_reason: Mapped[str] = mapped_column(Text, nullable=False, default="No events received")
    last_source_timestamp: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_received_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    total_events_received: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    total_drops_reported: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_sequence_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    sequence_gaps_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    clock_skew_seconds: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    active_quality_warnings: Mapped[list[str]] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=False, default=list
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    # Relationships
    sensor: Mapped[MonitoredSensor] = relationship(
        "MonitoredSensor", back_populates="health_state"
    )


class MonitoredSAState(Base):
    """Rebuildable projection tracking current state of IKE and Child SAs across monitored gateways."""

    __tablename__ = "monitored_sa_states"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    gateway_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("monitored_gateways.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    sensor_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("monitored_sensors.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    sa_type: Mapped[str] = mapped_column(
        String(16), nullable=False
    )  # IKE_SA, CHILD_SA
    initiator_spi: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    responder_spi: Mapped[str | None] = mapped_column(String(32), nullable=True)
    child_spi_in: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    child_spi_out: Mapped[str | None] = mapped_column(String(32), nullable=True)
    state: Mapped[str] = mapped_column(
        String(32), nullable=False
    )  # INITIATING, ESTABLISHED, REKEYED, FAILED, EXPIRED, DELETED, STALE
    local_endpoint: Mapped[str | None] = mapped_column(String(64), nullable=True)
    remote_endpoint: Mapped[str | None] = mapped_column(String(64), nullable=True)
    cipher_suite: Mapped[str | None] = mapped_column(String(128), nullable=True)
    established_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_event_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    last_event_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    is_stale: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    staleness_reason: Mapped[str | None] = mapped_column(String(256), nullable=True)
    evidence_grade: Mapped[str] = mapped_column(
        String(32), nullable=False, default="OBSERVED"
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    # Relationships
    gateway: Mapped[MonitoredGateway] = relationship(
        "MonitoredGateway", back_populates="sa_states"
    )
    sensor: Mapped[MonitoredSensor] = relationship(
        "MonitoredSensor", back_populates="sa_states"
    )

    __table_args__ = (
        UniqueConstraint("gateway_id", "initiator_spi", "child_spi_in", name="uq_gateway_sa_identity"),
    )
