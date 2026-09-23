"""SQLAlchemy declarative models for Stage 5 Dataset Factory, Sessions, and Splits."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from app.db.base import Base

if TYPE_CHECKING:
    pass


class Dataset(Base):
    """Represents a curated dataset family (e.g. TunnelTrace Native IPsec vs external benchmark)."""

    __tablename__ = "datasets"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(
        String(128), nullable=False, unique=True, index=True
    )
    vpn_technology: Mapped[str] = mapped_column(
        String(32), nullable=False, default="IPSEC_NATIVE"
    )  # IPSEC_NATIVE, OPENVPN
    role: Mapped[str] = mapped_column(
        String(32), nullable=False, default="PRIMARY"
    )  # PRIMARY, SUPPORTING_BENCHMARK
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    versions: Mapped[list[DatasetVersion]] = relationship(
        "DatasetVersion", back_populates="dataset", cascade="all, delete-orphan"
    )


class DatasetVersion(Base):
    """An immutable versioned snapshot or active draft partition of a dataset."""

    __tablename__ = "dataset_versions"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    dataset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("datasets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    version_tag: Mapped[str] = mapped_column(
        String(64), nullable=False, index=True
    )  # draft, v0.1.0, v1.0.0
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="DRAFT"
    )  # DRAFT, LOCKED
    manifest_hash: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    session_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )
    class_distribution: Mapped[dict[str, Any] | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )
    coverage_summary: Mapped[dict[str, Any] | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    dataset: Mapped[Dataset] = relationship("Dataset", back_populates="versions")
    sessions: Mapped[list[DatasetSession]] = relationship(
        "DatasetSession", back_populates="version", cascade="all, delete-orphan"
    )
    splits: Mapped[list[DatasetSplit]] = relationship(
        "DatasetSplit", back_populates="version", cascade="all, delete-orphan"
    )


class DatasetSession(Base):
    """An independent, atomic experimental IPsec session with verified ground-truth label."""

    __tablename__ = "dataset_sessions"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    version_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dataset_versions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    testbed_run_id: Mapped[str | None] = mapped_column(
        String(128), nullable=True, index=True
    )
    capture_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("captures.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    analysis_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("analysis_runs.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # Ground-truth label and workload provenance
    workload_class: Mapped[str] = mapped_column(
        String(64), nullable=False, index=True
    )  # Web, Video Streaming, VoIP, Chat/Messaging, Email, ICMP, File Transfer, OOD_HOLDOUT
    workload_profile_id: Mapped[str] = mapped_column(
        String(128), nullable=False
    )
    workload_seed: Mapped[int] = mapped_column(
        Integer, nullable=False, default=42
    )

    # IPsec scenario ground-truth dimensions (anti-shortcut)
    scenario_id: Mapped[str] = mapped_column(
        String(128), nullable=False, index=True
    )
    mode: Mapped[str] = mapped_column(
        String(32), nullable=False, default="TUNNEL"
    )  # TUNNEL, TRANSPORT
    ip_version: Mapped[str] = mapped_column(
        String(16), nullable=False, default="IPv4"
    )  # IPv4, IPv6
    cipher_suite: Mapped[str] = mapped_column(
        String(64), nullable=False
    )
    pfs_status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="ENABLED"
    )  # ENABLED, DISABLED
    is_nat_t: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    network_impairment_profile: Mapped[str | None] = mapped_column(
        String(128), nullable=True
    )

    # Quality Gate & Artifact Tracking
    quality_status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="ACCEPTED"
    )  # ACCEPTED, REJECTED, PARTIAL
    rejection_reason: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )
    encrypted_capture_sha256: Mapped[str] = mapped_column(
        String(64), nullable=False, index=True
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
    metadata_json: Mapped[dict[str, Any] | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    version: Mapped[DatasetVersion] = relationship("DatasetVersion", back_populates="sessions")
    splits: Mapped[list[DatasetSplit]] = relationship(
        "DatasetSplit", back_populates="session", cascade="all, delete-orphan"
    )


class DatasetSplit(Base):
    """Assignment of a session to an ML partition enforcing session-level isolation."""

    __tablename__ = "dataset_splits"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    version_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dataset_versions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    session_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dataset_sessions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    split_type: Mapped[str] = mapped_column(
        String(32), nullable=False, index=True
    )  # TRAIN, VALIDATION, TEST, OOD_HOLDOUT
    group_id: Mapped[str] = mapped_column(
        String(128), nullable=False, index=True
    )  # Group ID for GroupKFold

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    version: Mapped[DatasetVersion] = relationship("DatasetVersion", back_populates="splits")
    session: Mapped[DatasetSession] = relationship("DatasetSession", back_populates="splits")
