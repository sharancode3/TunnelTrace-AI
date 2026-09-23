"""SQLAlchemy declarative models for Stage 4: IKE Sessions, Security Associations, and ESP Flows."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from app.db.base import Base

if TYPE_CHECKING:
    from app.db.models.capture import AnalysisRun


class IKESession(Base):
    """Reconstructed IKE session correlated across IKE_SA_INIT, IKE_AUTH, and child exchanges."""

    __tablename__ = "ike_sessions"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    analysis_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("analysis_runs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    initiator_spi: Mapped[str] = mapped_column(
        String(32), nullable=False, index=True
    )
    responder_spi: Mapped[str | None] = mapped_column(
        String(32), nullable=True, index=True
    )
    ike_version: Mapped[str] = mapped_column(
        String(16), nullable=False, default="IKEv2"
    )  # IKEv1, IKEv2
    initiator_ip: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    responder_ip: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    initiator_port: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )
    responder_port: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )
    first_observed_at: Mapped[float] = mapped_column(
        Float, nullable=False
    )
    last_observed_at: Mapped[float] = mapped_column(
        Float, nullable=False
    )
    lifecycle_state: Mapped[str] = mapped_column(
        String(32), nullable=False, default="ACTIVE_INFERRED"
    )  # INIT_SEEN, AUTH_SEEN, ACTIVE_INFERRED, PARTIAL, TERMINATED, UNKNOWN
    is_nat_detected: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    retransmission_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )
    packet_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )
    evidence_state: Mapped[str] = mapped_column(
        String(32), nullable=False, default="VERIFIED"
    )  # VERIFIED, INFERRED, UNKNOWN

    # Provenance: frame numbers contributing to this session
    frame_numbers: Mapped[list[int] | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    analysis: Mapped[AnalysisRun] = relationship(
        "AnalysisRun", back_populates="ike_sessions"
    )
    ike_sas: Mapped[list[IKESecurityAssociation]] = relationship(
        "IKESecurityAssociation", back_populates="session", cascade="all, delete-orphan"
    )


class IKESecurityAssociation(Base):
    """Reconstructed parent IKE Security Association (IKE SA) governing control plane."""

    __tablename__ = "ike_security_associations"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    session_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("ike_sessions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    encryption_algorithm: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    key_length_bits: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )
    prf_algorithm: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    integrity_algorithm: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    dh_group: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    selection_evidence_state: Mapped[str] = mapped_column(
        String(32), nullable=False, default="VERIFIED"
    )  # VERIFIED, PROPOSED_ONLY, UNKNOWN
    established_at: Mapped[float | None] = mapped_column(
        Float, nullable=True
    )
    evidence_state: Mapped[str] = mapped_column(
        String(32), nullable=False, default="VERIFIED"
    )

    # Relationships
    session: Mapped[IKESession] = relationship(
        "IKESession", back_populates="ike_sas"
    )
    child_sas: Mapped[list[ChildSecurityAssociation]] = relationship(
        "ChildSecurityAssociation", back_populates="ike_sa"
    )


class ChildSecurityAssociation(Base):
    """Reconstructed directional or paired Child Security Association protecting ESP/AH traffic."""

    __tablename__ = "child_security_associations"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    analysis_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("analysis_runs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    ike_sa_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("ike_security_associations.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    protocol: Mapped[str] = mapped_column(
        String(8), nullable=False, default="ESP"
    )  # ESP, AH
    inbound_spi: Mapped[str] = mapped_column(
        String(32), nullable=False, index=True
    )
    outbound_spi: Mapped[str | None] = mapped_column(
        String(32), nullable=True, index=True
    )
    src_ip: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    dst_ip: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    mode: Mapped[str] = mapped_column(
        String(16), nullable=False, default="UNKNOWN"
    )  # TUNNEL, TRANSPORT, UNKNOWN
    mode_evidence_state: Mapped[str] = mapped_column(
        String(32), nullable=False, default="UNKNOWN"
    )  # VERIFIED, INFERRED, UNKNOWN
    encryption_algorithm: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    integrity_algorithm: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    pfs_status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="UNKNOWN"
    )  # ENABLED, DISABLED, UNKNOWN
    pfs_dh_group: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    pfs_evidence_state: Mapped[str] = mapped_column(
        String(32), nullable=False, default="UNKNOWN"
    )  # VERIFIED, INFERRED, UNKNOWN
    first_observed_at: Mapped[float | None] = mapped_column(
        Float, nullable=True
    )
    last_observed_at: Mapped[float | None] = mapped_column(
        Float, nullable=True
    )
    lifecycle_state: Mapped[str] = mapped_column(
        String(32), nullable=False, default="ACTIVE_INFERRED"
    )  # ACTIVE_INFERRED, ORPHAN, REKEYED, TERMINATED, UNKNOWN
    evidence_state: Mapped[str] = mapped_column(
        String(32), nullable=False, default="VERIFIED"
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    analysis: Mapped[AnalysisRun] = relationship(
        "AnalysisRun", back_populates="child_sas"
    )
    ike_sa: Mapped[IKESecurityAssociation | None] = relationship(
        "IKESecurityAssociation", back_populates="child_sas"
    )
    traffic_selectors: Mapped[list[TrafficSelector]] = relationship(
        "TrafficSelector", back_populates="child_sa", cascade="all, delete-orphan"
    )
    flows: Mapped[list[ESPFlow]] = relationship(
        "ESPFlow", back_populates="child_sa"
    )


class TrafficSelector(Base):
    """Traffic Selector negotiated for a Child SA defining permitted subnets and ports."""

    __tablename__ = "traffic_selectors"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    child_sa_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("child_security_associations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    direction: Mapped[str] = mapped_column(
        String(16), nullable=False
    )  # INITIATOR (TSi), RESPONDER (TSr)
    ip_subnet: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    start_ip: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    end_ip: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    ip_protocol: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )
    start_port: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )
    end_port: Mapped[int] = mapped_column(
        Integer, nullable=False, default=65535
    )
    evidence_state: Mapped[str] = mapped_column(
        String(32), nullable=False, default="VERIFIED"
    )

    # Relationships
    child_sa: Mapped[ChildSecurityAssociation] = relationship(
        "ChildSecurityAssociation", back_populates="traffic_selectors"
    )


class ESPFlow(Base):
    """Aggregated directional or bidirectional encrypted ESP packet flow."""

    __tablename__ = "esp_flows"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    analysis_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("analysis_runs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    child_sa_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("child_security_associations.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    spi: Mapped[str] = mapped_column(
        String(32), nullable=False, index=True
    )
    reverse_spi: Mapped[str | None] = mapped_column(
        String(32), nullable=True, index=True
    )
    src_ip: Mapped[str] = mapped_column(
        String(64), nullable=False
    )
    dst_ip: Mapped[str] = mapped_column(
        String(64), nullable=False
    )
    ip_version: Mapped[str] = mapped_column(
        String(8), nullable=False, default="IPv4"
    )  # IPv4, IPv6
    is_nat_t: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    orientation_basis: Mapped[str] = mapped_column(
        String(32), nullable=False, default="FIRST_SEEN"
    )  # PROTOCOL_ROLE, FIRST_SEEN, UNKNOWN
    start_time: Mapped[float] = mapped_column(
        Float, nullable=False
    )
    end_time: Mapped[float] = mapped_column(
        Float, nullable=False
    )
    duration_seconds: Mapped[float] = mapped_column(
        Float, nullable=False, default=0.0
    )
    packet_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )
    byte_count: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=0
    )
    forward_packets: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )
    forward_bytes: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=0
    )
    reverse_packets: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )
    reverse_bytes: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=0
    )
    association_state: Mapped[str] = mapped_column(
        String(32), nullable=False, default="PAIRED_BIDIRECTIONAL"
    )  # PAIRED_BIDIRECTIONAL, UNPAIRED_UNIDIRECTIONAL, ORPHAN
    end_reason: Mapped[str] = mapped_column(
        String(32), nullable=False, default="CAPTURE_ENDED"
    )  # REKEY_OBSERVED, DELETE_OBSERVED, CAPTURE_ENDED, IDLE_TIMEOUT, ACTIVE_TIMEOUT, UNKNOWN

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    analysis: Mapped[AnalysisRun] = relationship(
        "AnalysisRun", back_populates="flows"
    )
    child_sa: Mapped[ChildSecurityAssociation | None] = relationship(
        "ChildSecurityAssociation", back_populates="flows"
    )
