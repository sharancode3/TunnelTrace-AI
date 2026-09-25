"""Database Models for ML Training Experiments and Model Artifacts."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class TrainingExperiment(Base):
    """Tracks a reproducible machine learning experiment execution and provenance."""

    __tablename__ = "training_experiments"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    experiment_id: Mapped[str] = mapped_column(
        String(64), unique=True, nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(
        String(128), nullable=False, default="xgboost_baseline"
    )
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="CREATED"
    )  # CREATED, TRAINING, COMPLETED, FAILED, CANCELLED
    dataset_version_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dataset_versions.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    dataset_manifest_hash: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    split_manifest_hash: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    feature_schema_hash: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    hyperparameters: Mapped[dict | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )
    metrics_summary: Mapped[dict | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Relationships
    artifacts: Mapped[list[ModelArtifact]] = relationship(
        "ModelArtifact", back_populates="experiment", cascade="all, delete-orphan"
    )


class ModelArtifact(Base):
    """Persisted, versioned machine learning model artifact with cryptographic checksum."""

    __tablename__ = "model_artifacts"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    experiment_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("training_experiments.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    model_family: Mapped[str] = mapped_column(
        String(32), nullable=False, default="XGBOOST"
    )
    model_version: Mapped[str] = mapped_column(
        String(32), nullable=False, default="v1.0.0-baseline"
    )
    artifact_state: Mapped[str] = mapped_column(
        String(32), nullable=False, default="EXPERIMENTAL"
    )  # EXPERIMENTAL, BASELINE_VALIDATED (strictly never automatically ACTIVE)
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    storage_path: Mapped[str] = mapped_column(
        String(256), nullable=False
    )
    sha256_hash: Mapped[str] = mapped_column(
        String(64), nullable=False
    )
    manifest_data: Mapped[dict | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    experiment: Mapped[TrainingExperiment] = relationship(
        "TrainingExperiment", back_populates="artifacts"
    )
    classifications: Mapped[list[FlowClassification]] = relationship(
        "FlowClassification", back_populates="artifact", cascade="all, delete-orphan"
    )


class MLInferenceRun(Base):
    """Tracks an ML inference execution run and its complete provenance and artifact lineage."""

    __tablename__ = "ml_inference_runs"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    analysis_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("analysis_runs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    capture_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("captures.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="NOT_CONFIGURED"
    )  # NOT_CONFIGURED, BUNDLE_INVALID, RUNNING, COMPLETED, PARTIAL, NO_FLOWS, INSUFFICIENT_INPUT, FAILED
    status_reason: Mapped[str | None] = mapped_column(
        String(256), nullable=True
    )
    bundle_id: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    bundle_version: Mapped[str | None] = mapped_column(
        String(32), nullable=True
    )
    bundle_hash: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    manifest_digest: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    feature_schema_hash: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    sequence_schema_hash: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    calibration_hash: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    ood_hash: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    anomaly_hash: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    inference_runtime: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    environment_metadata: Mapped[dict | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )
    attempted_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )
    classified_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )
    skipped_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )
    failed_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )
    is_current: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, index=True
    )
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    classifications: Mapped[list[FlowClassification]] = relationship(
        "FlowClassification", back_populates="run", cascade="all, delete-orphan"
    )


class FlowClassification(Base):
    """Stores inference predictions and transparency records for encrypted ESP flows."""

    __tablename__ = "flow_classifications"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    flow_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("esp_flows.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    run_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("ml_inference_runs.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    artifact_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("model_artifacts.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    input_status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="VALID"
    )  # VALID, INSUFFICIENT_INPUT
    supervised_hypothesis: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    accepted_prediction: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    calibration_status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="CALIBRATED"
    )  # CALIBRATED, DEGRADED, UNAVAILABLE
    known_class: Mapped[str] = mapped_column(
        String(64), nullable=False
    )
    final_class: Mapped[str] = mapped_column(
        String(64), nullable=False
    )
    calibrated_confidence: Mapped[float] = mapped_column(
        Float, nullable=False, default=0.0
    )
    entropy: Mapped[float] = mapped_column(
        Float, nullable=False, default=0.0
    )
    normalized_entropy: Mapped[float] = mapped_column(
        Float, nullable=False, default=0.0
    )
    ood_status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="KNOWN_ACCEPTED"
    )
    rejection_reason: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    is_degraded: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    degraded_reason: Mapped[str | None] = mapped_column(
        String(128), nullable=True
    )
    behavioral_anomaly_status: Mapped[str] = mapped_column(
        String(64), nullable=False, default="NORMAL_BEHAVIOR"
    )
    anomaly_score: Mapped[float] = mapped_column(
        Float, nullable=False, default=0.0
    )
    transparency_data: Mapped[dict | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    artifact: Mapped[ModelArtifact | None] = relationship(
        "ModelArtifact", back_populates="classifications"
    )
    run: Mapped[MLInferenceRun | None] = relationship(
        "MLInferenceRun", back_populates="classifications"
    )

