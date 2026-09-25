"""Database models for Replay Provenance and Comparison Lineage."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import DateTime, JSON, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class ReplayComparisonModel(Base):
    """Stores deterministic forensic re-analysis or semantic scenario replay comparisons."""

    __tablename__ = "replay_comparisons"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    replay_mode: Mapped[str] = mapped_column(
        String(32), nullable=False, index=True
    )  # FORENSIC_REANALYSIS, SCENARIO_REPLAY
    parent_run_id: Mapped[str] = mapped_column(
        String(64), nullable=False, index=True
    )
    child_run_id: Mapped[str] = mapped_column(
        String(64), nullable=False, index=True
    )
    comparison_status: Mapped[str] = mapped_column(
        String(32), nullable=False, index=True
    )  # EXACT_MATCH, SEMANTIC_MATCH, DISCREPANCY_DETECTED, ENVIRONMENT_MISMATCH, FAILED
    artifact_integrity: Mapped[str] = mapped_column(
        String(32), nullable=False
    )  # VERIFIED, MISMATCH, UNAVAILABLE
    differences: Mapped[dict[str, Any] | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )
    summary: Mapped[str] = mapped_column(
        Text, nullable=False, default=""
    )
    metrics: Mapped[dict[str, Any] | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
