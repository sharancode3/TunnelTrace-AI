"""Pydantic schemas and DTOs for Stage 5 Dataset Factory API."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

# ==============================================================================
# Dataset Family DTOs
# ==============================================================================


class DatasetCreateRequest(BaseModel):
    name: str = Field(..., max_length=128, description="Unique dataset family name")
    vpn_technology: str = Field(
        default="IPSEC_NATIVE",
        description="Encapsulation technology (IPSEC_NATIVE, OPENVPN)",
    )
    role: str = Field(
        default="PRIMARY",
        description="Dataset role (PRIMARY, SUPPORTING_BENCHMARK)",
    )
    description: str | None = Field(default=None, description="Detailed dataset description")


class DatasetResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    vpn_technology: str
    role: str
    description: str | None
    created_at: datetime
    version_count: int = 0


# ==============================================================================
# Dataset Version DTOs
# ==============================================================================


class DatasetVersionCreateRequest(BaseModel):
    version_tag: str = Field(
        ..., max_length=64, description="Release version tag (e.g. draft, v0.1.0, v1.0.0)"
    )


class DatasetVersionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    dataset_id: UUID
    version_tag: str
    status: str
    manifest_hash: str | None
    session_count: int
    class_distribution: dict[str, Any] | None
    coverage_summary: dict[str, Any] | None
    created_at: datetime


# ==============================================================================
# Dataset Session DTOs
# ==============================================================================


class DatasetSessionCreateRequest(BaseModel):
    testbed_run_id: str | None = None
    capture_id: UUID | None = None
    analysis_id: UUID | None = None

    workload_class: str = Field(..., description="7 supervised classes or OOD_HOLDOUT")
    workload_profile_id: str
    workload_seed: int = 42

    scenario_id: str
    mode: str = "TUNNEL"
    ip_version: str = "IPv4"
    cipher_suite: str
    pfs_status: str = "ENABLED"
    is_nat_t: bool = False
    network_impairment_profile: str | None = None

    encrypted_capture_sha256: str
    duration_seconds: float = 0.0
    packet_count: int = 0
    byte_count: int = 0
    metadata_json: dict[str, Any] | None = None


class DatasetSessionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    version_id: UUID
    testbed_run_id: str | None
    capture_id: UUID | None
    analysis_id: UUID | None
    workload_class: str
    workload_profile_id: str
    workload_seed: int
    scenario_id: str
    mode: str
    ip_version: str
    cipher_suite: str
    pfs_status: str
    is_nat_t: bool
    network_impairment_profile: str | None
    quality_status: str
    rejection_reason: str | None
    encrypted_capture_sha256: str
    duration_seconds: float
    packet_count: int
    byte_count: int
    metadata_json: dict[str, Any] | None
    created_at: datetime


# ==============================================================================
# Partition & Split DTOs
# ==============================================================================


class PartitionRequest(BaseModel):
    train_ratio: float = Field(default=0.70, ge=0.0, le=1.0)
    val_ratio: float = Field(default=0.15, ge=0.0, le=1.0)
    test_ratio: float = Field(default=0.15, ge=0.0, le=1.0)
    random_seed: int = Field(default=42)


class PartitionResponse(BaseModel):
    version_id: UUID
    is_clean: bool
    total_assigned: int
    split_counts: dict[str, int]
    class_distribution_per_split: dict[str, dict[str, int]]
    leakage_errors: list[str] = Field(default_factory=list)


class SplitSummaryResponse(BaseModel):
    version_id: UUID
    total_splits: int
    split_counts: dict[str, int]
    is_clean: bool
    audit_message: str


# ==============================================================================
# Coverage & External Benchmark DTOs
# ==============================================================================


class CoverageReportResponse(BaseModel):
    total_planned_scenarios: int
    active_sessions_analyzed: int
    dimension_coverage: dict[str, Any]
    uncovered_scenarios: list[str]


class ExternalItemResponse(BaseModel):
    filename: str
    absolute_path: str
    size_bytes: int
    sha256_hash: str
    vpn_technology: str
    role: str
    application_hint: str
    modified_at: str


class ExternalInventoryResponse(BaseModel):
    dataset_name: str
    vpn_technology: str
    role: str
    scanned_at: str
    total_files: int
    total_bytes: int
    domain_shift_notice: str
    files: list[ExternalItemResponse]
