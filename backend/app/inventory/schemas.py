"""Pydantic V2 schemas for Configuration and Certificate Inventory."""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class SourceType(str, Enum):
    CONFIGURED_FILE = "CONFIGURED_FILE"
    RUNTIME_ACTIVE = "RUNTIME_ACTIVE"
    PACKET_OBSERVED = "PACKET_OBSERVED"
    LAB_CONTROLLED = "LAB_CONTROLLED"


class ValidityStatus(str, Enum):
    VALID = "VALID"
    EXPIRED = "EXPIRED"
    NOT_YET_VALID = "NOT_YET_VALID"
    EXPIRING_SOON = "EXPIRING_SOON"


class IdentityAssociationStatus(str, Enum):
    MATCHED = "MATCHED"
    AMBIGUOUS = "AMBIGUOUS"
    UNASSOCIATED = "UNASSOCIATED"


class ChainValidationStatus(str, Enum):
    VALIDATED = "VALIDATED"
    FAILED = "FAILED"
    UNCHECKED = "UNCHECKED"


class RevocationStatus(str, Enum):
    REVOKED = "REVOKED"
    GOOD = "GOOD"
    UNCHECKED = "UNCHECKED"


class ComparisonStatus(str, Enum):
    MATCHED = "MATCHED"
    DRIFT_DETECTED = "DRIFT_DETECTED"
    INCOMPARABLE = "INCOMPARABLE"


class FieldDriftStatus(str, Enum):
    MATCHED = "MATCHED"
    CHANGED = "CHANGED"
    MISSING_IN_OBSERVED = "MISSING_IN_OBSERVED"
    NEW_IN_OBSERVED = "NEW_IN_OBSERVED"
    NOT_COMPARABLE = "NOT_COMPARABLE"
    UNKNOWN = "UNKNOWN"
    UNSUPPORTED = "UNSUPPORTED"


# ==============================================================================
# Request Schemas
# ==============================================================================

class ConfigurationImportRequest(BaseModel):
    """Request to import a strongSwan configuration snapshot."""

    model_config = ConfigDict(extra="forbid")

    gateway_identity: str = Field(..., min_length=1, max_length=128, description="Logical gateway identifier or FQDN")
    authorized_scope: str = Field("0.0.0.0/0", max_length=256, description="Authorized CIDR or network scope")
    source_type: SourceType = Field(SourceType.CONFIGURED_FILE, description="Observational source type")
    config_text: str = Field(..., min_length=1, max_length=1_000_000, description="Raw swanctl.conf configuration text to parse in-memory")
    collection_method: str = Field("OFFLINE_IMPORT", max_length=64)
    operator_id: str = Field(..., min_length=1, max_length=128, description="Operator identifier")
    authorization_reference: str = Field(..., min_length=1, max_length=256, description="Change ticket or approval reference")
    source_observed_at: datetime | None = Field(None, description="Optional timestamp when source was observed")


class BaselineDesignateRequest(BaseModel):
    """Request to designate an existing snapshot as the authoritative baseline."""

    model_config = ConfigDict(extra="forbid")

    operator_id: str = Field(..., min_length=1, max_length=128)
    approval_reference: str = Field(..., min_length=1, max_length=256)
    baseline_version: int = Field(1, ge=1)


class DriftCompareRequest(BaseModel):
    """Request to perform an evidence-based drift comparison between baseline and observed snapshots."""

    model_config = ConfigDict(extra="forbid")

    baseline_snapshot_id: uuid.UUID
    observed_snapshot_id: uuid.UUID


class CertificateImportRequest(BaseModel):
    """Request to import one or more X.509 public certificates."""

    model_config = ConfigDict(extra="forbid")

    gateway_identity: str = Field(..., min_length=1, max_length=128)
    snapshot_id: uuid.UUID | None = Field(None, description="Optional snapshot to associate certificates with")
    certificate_pem: str = Field(..., min_length=10, max_length=2_000_000, description="PEM formatted X.509 certificate data (public only)")
    trust_store_pem: str | None = Field(None, max_length=2_000_000, description="Optional CA trust store PEM for chain validation")
    source_alias: str = Field("x509_certificate", max_length=256)
    epistemic_status: str = Field("CONFIGURED", max_length=32)
    operator_id: str = Field(..., min_length=1, max_length=128)
    authorization_reference: str = Field(..., min_length=1, max_length=256)


# ==============================================================================
# Response Schemas
# ==============================================================================

class FieldDriftItem(BaseModel):
    """Detailed record of a single configuration field comparison."""

    field_path: str
    baseline_value: Any
    observed_value: Any
    status: FieldDriftStatus
    description: str


class ConfigurationSnapshotResponse(BaseModel):
    """Snapshot representation for API clients."""

    id: uuid.UUID
    gateway_id: uuid.UUID | None = None
    gateway_identity: str
    authorized_scope: str
    source_type: str
    collection_method: str
    collector_version: str
    parser_version: str
    schema_version: str
    canonical_digest: str
    normalized_ir: dict[str, Any]
    unsupported_directives: list[dict[str, Any]]
    is_baseline: bool
    baseline_version: int | None = None
    approved_by: str | None = None
    approval_reference: str | None = None
    source_observed_at: datetime | None = None
    provenance: dict[str, Any]
    created_at: datetime


class ConfigurationDriftResponse(BaseModel):
    """Drift evaluation report between baseline and observed snapshots."""

    id: uuid.UUID
    gateway_identity: str
    baseline_snapshot_id: uuid.UUID
    observed_snapshot_id: uuid.UUID
    comparison_status: str
    drift_summary: dict[str, Any]
    field_drifts: list[FieldDriftItem]
    created_at: datetime


class CertificateResponse(BaseModel):
    """Public certificate inventory representation."""

    id: uuid.UUID
    gateway_id: uuid.UUID | None = None
    gateway_identity: str
    snapshot_id: uuid.UUID | None = None
    sha256_fingerprint: str
    serial_number: str
    subject_dn: str
    issuer_dn: str
    subject_alt_names: dict[str, list[str]]
    not_valid_before: datetime
    not_valid_after: datetime
    validity_status: str
    days_until_expiry: int
    public_key_algorithm: str
    public_key_bits: int
    signature_algorithm: str
    is_ca: bool
    key_usages: list[str]
    extended_key_usages: list[str]
    associated_connection: str | None = None
    identity_association_status: str
    chain_validation_status: str
    trust_store_identifier: str | None = None
    trust_store_digest: str | None = None
    revocation_status: str
    source_alias: str
    epistemic_status: str
    created_at: datetime


class GatewayInventorySummaryResponse(BaseModel):
    """High-level summary of an authorized gateway's inventory state."""

    gateway_identity: str
    authorized_scope: str
    has_baseline: bool
    baseline_snapshot_id: uuid.UUID | None = None
    baseline_version: int | None = None
    latest_snapshot_id: uuid.UUID | None = None
    latest_snapshot_digest: str | None = None
    latest_snapshot_created_at: datetime | None = None
    latest_drift_status: str | None = None
    certificate_count: int = 0
    expiring_soon_certificates: int = 0
    expired_certificates: int = 0
