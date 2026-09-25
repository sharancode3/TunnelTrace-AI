"""Database models for Stage 10 Configuration Security Twin & Closed-Loop Remediation."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, Numeric, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class ConfigurationSnapshotModel(Base):
    """Immutable representation of a VPN configuration state (observed, proposed, backup, or post-remediation)."""

    __tablename__ = "configuration_snapshots"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    analysis_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("analysis_runs.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    snapshot_type: Mapped[str] = mapped_column(
        String(32), nullable=False, index=True
    )  # OBSERVED_CURRENT, USER_PROPOSED, POLICY_GENERATED_PROPOSED, LAB_BACKUP, LAB_APPLIED, VERIFIED_POST_REMEDIATION
    config_format: Mapped[str] = mapped_column(
        String(16), nullable=False, default="SWANCTL"
    )  # SWANCTL, IPSEC_CONF, OBSERVED_MODEL
    normalized_ir: Mapped[dict | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )
    config_content: Mapped[str | None] = mapped_column(Text, nullable=True)
    config_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    provenance: Mapped[dict | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )


class ConfigurationTwinModel(Base):
    """Configuration Security Twin modeling counterfactual policy projections."""

    __tablename__ = "configuration_twins"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    analysis_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("analysis_runs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    observed_snapshot_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("configuration_snapshots.id", ondelete="RESTRICT"),
        nullable=False,
    )
    hardened_snapshot_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("configuration_snapshots.id", ondelete="RESTRICT"),
        nullable=False,
    )
    proposal_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    projected_score: Mapped[float | None] = mapped_column(Numeric(5, 2), nullable=True)
    projected_score_delta: Mapped[float | None] = mapped_column(Numeric(5, 2), nullable=True)
    diff_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    semantic_diff: Mapped[list | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )
    projected_regression_audit: Mapped[dict | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="PROJECTED", index=True
    )  # PROJECTED, APPROVED, SUPERSEDED, APPLIED
    policy_bundle_version: Mapped[str] = mapped_column(String(64), nullable=False, default="1.0.0")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )


class RemediationRunModel(Base):
    """Tracks the closed-loop execution of configuration fixes applied to the isolated strongSwan testbed."""

    __tablename__ = "remediation_runs"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    twin_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("configuration_twins.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    lab_instance_id: Mapped[str] = mapped_column(String(64), nullable=False, default="strongswan-lab-default")
    proposal_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    operator_id: Mapped[str] = mapped_column(String(64), nullable=False, default="analyst-local")
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="CREATED", index=True
    )  # CREATED, AWAITING_APPROVAL, PREFLIGHT, BACKUP_CREATED, APPLYING, CONFIG_APPLIED, RELOADING, REESTABLISHING, VERIFYING_CONNECTIVITY, CAPTURING, REANALYZING, COMPARING, COMPLETED, ROLLING_BACK, ROLLED_BACK, FAILED, CANCELLED
    backup_snapshot_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("configuration_snapshots.id", ondelete="RESTRICT"),
        nullable=True,
    )
    applied_snapshot_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("configuration_snapshots.id", ondelete="RESTRICT"),
        nullable=True,
    )
    rollback_state: Mapped[str] = mapped_column(
        String(32), nullable=False, default="NONE"
    )  # NONE, NOT_TRIGGERED, TRIGGERED, IN_PROGRESS, COMPLETED, FAILED
    rollback_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    approval_timestamp: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    approval_metadata: Mapped[dict | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )
    pre_apply_spis: Mapped[list | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )
    post_capture_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    executed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class RemediationRunStepModel(Base):
    """Append-only atomic remediation step journal entry for forensic auditability."""

    __tablename__ = "remediation_run_steps"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    remediation_run_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("remediation_runs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    action_type: Mapped[str] = mapped_column(String(64), nullable=False)
    input_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="PENDING"
    )  # PENDING, RUNNING, SUCCESS, FAILED, SKIPPED
    safe_output: Mapped[dict | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )
    error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    duration_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )


class RemediationVerificationModel(Base):
    """Dual-axis empirical outcome of post-remediation traffic capture and full reanalysis."""

    __tablename__ = "remediation_verifications"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    remediation_run_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("remediation_runs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    baseline_analysis_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("analysis_runs.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    post_analysis_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("analysis_runs.id", ondelete="RESTRICT"),
        nullable=True,
        index=True,
    )
    post_capture_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("captures.id", ondelete="RESTRICT"),
        nullable=True,
    )
    verification_result: Mapped[str] = mapped_column(
        String(32), nullable=False, index=True
    )  # VERIFIED_RESOLVED, VERIFIED_NOT_RESOLVED, PARTIALLY_VERIFIED, VERIFICATION_FAILED, UNKNOWN
    security_result: Mapped[str] = mapped_column(
        String(32), nullable=False, default="UNKNOWN"
    )  # RESOLVED, NOT_RESOLVED, PARTIAL, UNKNOWN, FAILED
    operational_result: Mapped[str] = mapped_column(
        String(32), nullable=False, default="HEALTHY"
    )  # HEALTHY, DEGRADED, FAILED
    baseline_score: Mapped[float | None] = mapped_column(Numeric(5, 2), nullable=True)
    verified_score: Mapped[float | None] = mapped_column(Numeric(5, 2), nullable=True)
    score_delta: Mapped[float | None] = mapped_column(Numeric(5, 2), nullable=True)
    finding_diff_summary: Mapped[dict | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )
    regression_summary: Mapped[dict | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )
    workload_manifest: Mapped[dict | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )
    verified_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )


class RemediationVerificationClaimModel(Base):
    """Granular, finding-level Verification Claim Ledger entry tying resolution to evidence."""

    __tablename__ = "remediation_verification_claims"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    verification_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("remediation_verifications.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    baseline_finding_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True, index=True
    )
    rule_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    rule_version: Mapped[str] = mapped_column(String(32), nullable=False)
    root_cause_key: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    baseline_evidence: Mapped[dict | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )
    proposed_transformation: Mapped[dict | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )
    expected_condition: Mapped[str | None] = mapped_column(Text, nullable=True)
    post_finding_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    post_evidence: Mapped[dict | None] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=True
    )
    claim_result: Mapped[str] = mapped_column(
        String(32), nullable=False
    )  # VERIFIED_RESOLVED, VERIFIED_NOT_RESOLVED, UNKNOWN, NOT_APPLICABLE
    reason_code: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
