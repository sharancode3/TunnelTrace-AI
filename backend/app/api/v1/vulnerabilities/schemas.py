"""Pydantic schemas for External Vulnerability Assessment Reports API."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class VulnerabilityReportPreviewResponse(BaseModel):
    """Preflight summary of an uploaded Greenbone XML report before committing import."""

    model_config = ConfigDict(from_attributes=True)

    report_id: str
    format_id: str | None = None
    format_version: str | None = None
    task_id: str | None = None
    task_name: str | None = None
    scan_config: str | None = None
    scanner_name: str | None = None
    scanner_version: str | None = None
    feed_status: str = "UNKNOWN"
    feed_type: str | None = None
    scan_started_at: str | None = None
    scan_ended_at: str | None = None
    raw_sha256: str
    raw_bytes_count: int
    total_findings_count: int
    unique_hosts_count: int
    host_mapping_summary: dict[str, int]
    host_mapping_details: list[dict[str, Any]]
    severity_breakdown: dict[str, int]
    correlation_breakdown: dict[str, int]
    findings_sample: list[dict[str, Any]]


class VulnerabilityReportDTO(BaseModel):
    """Normalized metadata for a persisted external vulnerability report artifact."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    report_source_id: str
    source_system: str
    report_format: str
    report_format_version: str | None = None
    task_id: str | None = None
    task_name: str | None = None
    scan_config: str | None = None
    port_list: str | None = None
    scanner_name: str | None = None
    scanner_version: str | None = None
    feed_type: str | None = None
    feed_version: str | None = None
    feed_status: str
    engagement_scope: str
    authorization_reference: str
    operator_id: str
    operator_attestation: str
    is_local_attestation: bool
    status: str
    failure_reason: str | None = None
    raw_artifact_sha256: str
    raw_artifact_bytes: int
    storage_path: str | None = None
    duplicate_of_id: uuid.UUID | None = None
    scan_started_at: datetime | None = None
    scan_ended_at: datetime | None = None
    imported_at: datetime
    hosts_count: int
    results_count: int


class VulnerabilityFindingDTO(BaseModel):
    """Normalized scanner-reported finding with asset and product/version correlation state."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    report_id: uuid.UUID
    source_result_id: str
    host_ip: str
    host_name: str | None = None
    ip_version: str
    port: int | None = None
    protocol: str | None = None
    service_name: str | None = None
    nvt_oid: str
    nvt_name: str
    nvt_family: str | None = None
    cvss_version: str | None = None
    cvss_base_score: float | None = None
    cvss_vector: str | None = None
    source_severity: str
    qod_value: int | None = None
    qod_type: str | None = None
    detection_method: str | None = None
    reported_cves: list[str] = Field(default_factory=list)
    reported_cpes: list[str] = Field(default_factory=list)
    source_product_claim: str | None = None
    source_version_claim: str | None = None
    description: str | None = None
    summary: str | None = None
    solution: str | None = None
    solution_type: str | None = None
    source_timestamp: datetime | None = None
    status: str
    mapped_discovered_host_id: uuid.UUID | None = None
    asset_link_state: str
    asset_link_rationale: str
    correlation_status: str
    correlation_method: str
    cve_applicability_state: str
    correlation_rationale: str
    created_at: datetime


class VulnerabilityReportListResponse(BaseModel):
    reports: list[VulnerabilityReportDTO]
    total: int
    skip: int
    limit: int


class VulnerabilityFindingListResponse(BaseModel):
    findings: list[VulnerabilityFindingDTO]
    total: int
    skip: int
    limit: int
