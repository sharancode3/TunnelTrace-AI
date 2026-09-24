"""SQLAlchemy models for IKE/IPsec Negotiation Assessment (IKE-scan & TShark Concordance)."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
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


class IkeAssessmentJob(Base):
    """Audited, authorized IKE negotiation probe job bound to an explicit target endpoint."""

    __tablename__ = "ike_assessment_jobs"

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
    target_ip: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    target_port: Mapped[int] = mapped_column(Integer, nullable=False, default=500)
    profile: Mapped[str] = mapped_column(
        String(64), nullable=False, default="IKEV1_MAIN_MODE_DISCOVERY"
    )
    ike_version_requested: Mapped[str] = mapped_column(
        String(16), nullable=False, default="1"
    )  # "1", "2"
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="QUEUED", index=True
    )  # QUEUED, VALIDATING, RUNNING, COMPLETED, CANCELLED, FAILED, TOOL_UNAVAILABLE
    failure_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    raw_output_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    output_bytes_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    tool_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
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
    results: Mapped[list[IkeProbeResult]] = relationship(
        "IkeProbeResult", back_populates="job", cascade="all, delete-orphan"
    )


class IkeProbeResult(Base):
    """Normalized evidence from an authorized IKE-scan execution."""

    __tablename__ = "ike_probe_results"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    job_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("ike_assessment_jobs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    target_ip: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    target_port: Mapped[int] = mapped_column(Integer, nullable=False)
    response_category: Mapped[str] = mapped_column(
        String(32), nullable=False
    )  # RESPONDED_HANDSHAKE, RESPONDED_NOTIFY, NO_RESPONSE, TOOL_ERROR, TOOL_UNAVAILABLE
    ike_version: Mapped[str] = mapped_column(String(16), nullable=False, default="IKEv1")
    handshake_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    notify_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    notify_message: Mapped[str | None] = mapped_column(String(128), nullable=True)
    vendor_ids: Mapped[list[str] | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )
    transforms_returned: Mapped[list[dict[str, Any]] | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )
    rtt_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    raw_response_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_experimental: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )  # Flag for IKEv2 experimental probes
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    job: Mapped[IkeAssessmentJob] = relationship("IkeAssessmentJob", back_populates="results")


class IkeConcordanceRecord(Base):
    """Triangulated concordance between passive TShark dissection and active IKE probes."""

    __tablename__ = "ike_concordance_records"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    analysis_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("analysis_runs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    ike_job_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("ike_assessment_jobs.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    target_ip: Mapped[str] = mapped_column(String(64), nullable=False)
    concordance_status: Mapped[str] = mapped_column(
        String(32), nullable=False
    )  # CONSISTENT, CONFLICT, INSUFFICIENT_EVIDENCE, NOT_COMPARABLE
    passive_ike_versions: Mapped[list[str]] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=False
    )
    active_ike_versions: Mapped[list[str]] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=False
    )
    passive_selected_cipher: Mapped[str | None] = mapped_column(String(64), nullable=True)
    active_accepted_cipher: Mapped[str | None] = mapped_column(String(64), nullable=True)
    concordance_details: Mapped[dict[str, Any]] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=False
    )
    evaluated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
