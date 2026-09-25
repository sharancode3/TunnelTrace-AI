"""Database models for Configuration and Certificate Inventory subsystem.

Maintains immutable records of configured intent, runtime active state,
and certificate evidence for authorized strongSwan VPN gateways and lab assets.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class GatewayConfigurationSnapshot(Base):
    """Immutable evidence snapshot of a gateway configuration state."""

    __tablename__ = "gateway_configuration_snapshots"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    # Optional foreign key to monitored_gateways when registered
    gateway_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("monitored_gateways.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    # Logical gateway identity (FQDN, IP, or lab asset identifier)
    gateway_identity: Mapped[str] = mapped_column(
        String(128), nullable=False, index=True
    )
    # Authorized CIDR or lab network scope
    authorized_scope: Mapped[str] = mapped_column(
        String(256), nullable=False, default="0.0.0.0/0"
    )
    # Epistemic source type: CONFIGURED_FILE, RUNTIME_ACTIVE, PACKET_OBSERVED, LAB_CONTROLLED
    source_type: Mapped[str] = mapped_column(
        String(32), nullable=False, index=True
    )
    # Collection method: OFFLINE_IMPORT, LAB_AGENT, GATEWAY_EXPORT
    collection_method: Mapped[str] = mapped_column(
        String(64), nullable=False, default="OFFLINE_IMPORT"
    )
    collector_version: Mapped[str] = mapped_column(
        String(32), nullable=False, default="1.0.0"
    )
    parser_version: Mapped[str] = mapped_column(
        String(32), nullable=False, default="swanctl-6.0.4"
    )
    schema_version: Mapped[str] = mapped_column(
        String(32), nullable=False, default="1.0.0"
    )
    # Deterministic SHA-256 digest of normalized, redacted, non-secret representation
    canonical_digest: Mapped[str] = mapped_column(
        String(64), nullable=False, index=True
    )
    # Redacted typed configuration IR (no plaintext secrets)
    normalized_ir: Mapped[dict] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=False
    )
    # List of any directives encountered that were unmodeled or unsupported
    unsupported_directives: Mapped[list] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=False, default=list
    )
    # Baseline designation flags
    is_baseline: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, index=True
    )
    baseline_version: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )
    approved_by: Mapped[str | None] = mapped_column(
        String(128), nullable=True
    )
    approval_reference: Mapped[str | None] = mapped_column(
        String(256), nullable=True
    )
    # Source-observed timestamp (e.g. file mtime or runtime query time if reported)
    source_observed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # Provenance information (supplier, method, operator reference)
    provenance: Mapped[dict] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=False, default=dict
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )

    # Relationships
    certificates: Mapped[list[GatewayCertificate]] = relationship(
        "GatewayCertificate", back_populates="snapshot", cascade="all, delete-orphan"
    )


class GatewayConfigurationDrift(Base):
    """Evidence comparison between a baseline snapshot and an observed snapshot."""

    __tablename__ = "gateway_configuration_drifts"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    gateway_identity: Mapped[str] = mapped_column(
        String(128), nullable=False, index=True
    )
    baseline_snapshot_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("gateway_configuration_snapshots.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    observed_snapshot_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("gateway_configuration_snapshots.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # Comparison status: MATCHED, DRIFT_DETECTED, INCOMPARABLE
    comparison_status: Mapped[str] = mapped_column(
        String(32), nullable=False, index=True
    )
    # Summary counters (total, matched, changed, missing, new, not_comparable)
    drift_summary: Mapped[dict] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=False
    )
    # Granular field-level drift items
    field_drifts: Mapped[list] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )


class GatewayCertificate(Base):
    """Inventory record for a public X.509 certificate associated with a gateway."""

    __tablename__ = "gateway_certificates"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    gateway_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("monitored_gateways.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    gateway_identity: Mapped[str] = mapped_column(
        String(128), nullable=False, index=True
    )
    snapshot_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("gateway_configuration_snapshots.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    # SHA-256 fingerprint of the DER encoded public certificate
    sha256_fingerprint: Mapped[str] = mapped_column(
        String(64), nullable=False, index=True
    )
    serial_number: Mapped[str] = mapped_column(
        String(128), nullable=False
    )
    subject_dn: Mapped[str] = mapped_column(
        String(512), nullable=False
    )
    issuer_dn: Mapped[str] = mapped_column(
        String(512), nullable=False
    )
    # SANs dict: {"dns": [...], "ip": [...], "email": [...], "directory_name": [...]}
    subject_alt_names: Mapped[dict] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=False, default=dict
    )
    not_valid_before: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    not_valid_after: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    # Validity: VALID, EXPIRED, NOT_YET_VALID, EXPIRING_SOON
    validity_status: Mapped[str] = mapped_column(
        String(32), nullable=False, index=True
    )
    days_until_expiry: Mapped[int] = mapped_column(
        Integer, nullable=False
    )
    public_key_algorithm: Mapped[str] = mapped_column(
        String(64), nullable=False
    )
    public_key_bits: Mapped[int] = mapped_column(
        Integer, nullable=False
    )
    signature_algorithm: Mapped[str] = mapped_column(
        String(64), nullable=False
    )
    is_ca: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    key_usages: Mapped[list] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=False, default=list
    )
    extended_key_usages: Mapped[list] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"), nullable=False, default=list
    )
    # Deterministic mapping to strongSwan connection
    associated_connection: Mapped[str | None] = mapped_column(
        String(128), nullable=True
    )
    # Identity association state: MATCHED, AMBIGUOUS, UNASSOCIATED
    identity_association_status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="UNASSOCIATED"
    )
    # Chain validation: VALIDATED, FAILED, UNCHECKED
    chain_validation_status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="UNCHECKED"
    )
    trust_store_identifier: Mapped[str | None] = mapped_column(
        String(128), nullable=True
    )
    trust_store_digest: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    # Revocation: REVOKED, GOOD, UNCHECKED
    revocation_status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="UNCHECKED"
    )
    # Redacted source path or alias
    source_alias: Mapped[str] = mapped_column(
        String(256), nullable=False, default="x509_certificate"
    )
    # Epistemic source: CONFIGURED, RUNTIME_LOADED, OBSERVED_IN_PACKET
    epistemic_status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="CONFIGURED"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )

    # Relationships
    snapshot: Mapped[GatewayConfigurationSnapshot | None] = relationship(
        "GatewayConfigurationSnapshot", back_populates="certificates"
    )
