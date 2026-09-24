"""Database model for Stage 9 Report records and metadata tracking."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import JSON, DateTime, Float, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class ReportModel(Base):
    """Database record for generated Executive and Technical reports."""

    __tablename__ = "reports"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    analysis_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("analysis_runs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    report_type: Mapped[str] = mapped_column(
        String(32), nullable=False, index=True
    )  # EXECUTIVE, TECHNICAL
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="QUEUED", index=True
    )  # QUEUED, GENERATING, COMPLETED, FAILED
    format: Mapped[str] = mapped_column(
        String(32), nullable=False, default="HTML"
    )  # HTML, PDF, BOTH
    template_version: Mapped[str] = mapped_column(
        String(32), nullable=False, default="1.0.0"
    )
    engine_version: Mapped[str] = mapped_column(
        String(32), nullable=False, default="1.0.0"
    )
    html_artifact_path: Mapped[str | None] = mapped_column(
        String(512), nullable=True
    )
    html_sha256: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    pdf_artifact_path: Mapped[str | None] = mapped_column(
        String(512), nullable=True
    )
    pdf_sha256: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    snapshot_manifest_sha256: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    metadata_json: Mapped[dict | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )
    error_message: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )
    generation_duration_ms: Mapped[float | None] = mapped_column(
        Float, nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
