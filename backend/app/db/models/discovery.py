"""SQLAlchemy models for Stage 2 Authorized Asset Discovery (Nmap)."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from app.db.base import Base


class DiscoveryJob(Base):
    """Audited, authorized discovery scan job bound to an explicit target scope."""

    __tablename__ = "discovery_jobs"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    job_name: Mapped[str] = mapped_column(String(128), nullable=False)
    operator_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    authorization_reference: Mapped[str] = mapped_column(String(256), nullable=False)
    authorization_attestation: Mapped[str] = mapped_column(Text, nullable=False)
    authorized_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    profile: Mapped[str] = mapped_column(
        String(64), nullable=False, default="IKE_SERVICE_DISCOVERY"
    )
    requested_targets: Mapped[list[str]] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=False
    )
    canonical_targets: Mapped[list[str]] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=False
    )
    exclusions: Mapped[list[str]] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=False
    )
    permitted_ports: Mapped[list[int]] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=False
    )
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="QUEUED", index=True
    )  # QUEUED, VALIDATING, RUNNING, COMPLETED, COMPLETED_WITH_AMBIGUITY, CANCELLED, FAILED, REJECTED, TOOL_UNAVAILABLE
    failure_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    raw_output_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    output_bytes_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    tool_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    target_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    hosts_up_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    services_discovered_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    hosts: Mapped[list[DiscoveredHost]] = relationship(
        "DiscoveredHost", back_populates="job", cascade="all, delete-orphan"
    )
    services: Mapped[list[DiscoveredService]] = relationship(
        "DiscoveredService", back_populates="job", cascade="all, delete-orphan"
    )


class DiscoveredHost(Base):
    """Host discovery evidence normalized from Nmap XML."""

    __tablename__ = "discovered_hosts"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    job_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("discovery_jobs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    ip_address: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    ip_version: Mapped[str] = mapped_column(String(16), nullable=False, default="IPv4")
    state: Mapped[str] = mapped_column(
        String(32), nullable=False, default="UP"
    )  # UP, DOWN, UNKNOWN
    hostnames: Mapped[list[str] | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    job: Mapped[DiscoveryJob] = relationship("DiscoveryJob", back_populates="hosts")
    services: Mapped[list[DiscoveredService]] = relationship(
        "DiscoveredService", back_populates="host", cascade="all, delete-orphan"
    )


class DiscoveredService(Base):
    """Port and service discovery evidence with explicit ambiguity preservation."""

    __tablename__ = "discovered_services"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    job_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("discovery_jobs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    host_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("discovered_hosts.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    protocol: Mapped[str] = mapped_column(String(16), nullable=False)  # TCP, UDP
    port: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    state: Mapped[str] = mapped_column(
        String(32), nullable=False
    )  # OPEN, CLOSED, FILTERED, OPEN_OR_FILTERED, UNFILTERED
    state_reason: Mapped[str | None] = mapped_column(String(64), nullable=True)
    service_name: Mapped[str | None] = mapped_column(String(64), nullable=True)
    product: Mapped[str | None] = mapped_column(String(128), nullable=True)
    version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    extra_info: Mapped[str | None] = mapped_column(String(256), nullable=True)
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    fingerprint: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    job: Mapped[DiscoveryJob] = relationship("DiscoveryJob", back_populates="services")
    host: Mapped[DiscoveredHost] = relationship("DiscoveredHost", back_populates="services")
