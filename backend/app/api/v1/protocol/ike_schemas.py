"""Pydantic schemas for IKE/IPsec Negotiation Assessment API."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class IkeAssessmentStatusResponse(BaseModel):
    enabled: bool
    ike_scan_available: bool
    ike_scan_version: str | None = None
    ike_scan_path: str | None = None
    timeout_sec: float
    allow_experimental_v2: bool
    available_profiles: list[dict[str, Any]]


class IkeAssessmentJobCreateRequest(BaseModel):
    job_name: str = Field(default="IKE Negotiation Probe", max_length=128)
    operator_id: str = Field(..., min_length=1, max_length=128)
    authorization_reference: str = Field(..., min_length=1, max_length=256)
    authorization_attestation: str = Field(..., min_length=10)
    profile_name: str = Field(default="IKEV1_MAIN_MODE_DISCOVERY")
    target: str = Field(..., min_length=1, max_length=256)
    port: int = Field(default=500, ge=1, le=65535)
    analysis_id: uuid.UUID | None = None


class IkeProbeResultResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    target_ip: str
    target_port: int
    response_category: str
    ike_version: str
    handshake_type: str | None = None
    notify_code: int | None = None
    notify_message: str | None = None
    vendor_ids: list[str] | None = None
    transforms_returned: list[dict[str, Any]] | None = None
    rtt_ms: float | None = None
    is_experimental: bool
    created_at: datetime


class IkeAssessmentJobResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    job_name: str
    operator_id: str
    authorization_reference: str
    target_ip: str
    target_port: int
    profile: str
    ike_version_requested: str
    status: str
    failure_reason: str | None = None
    raw_output_sha256: str | None = None
    output_bytes_count: int | None = None
    tool_version: str | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    created_at: datetime
    results: list[IkeProbeResultResponse] = []


class IkeConcordanceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    analysis_id: uuid.UUID
    ike_job_id: uuid.UUID | None = None
    target_ip: str
    concordance_status: str
    passive_ike_versions: list[str]
    active_ike_versions: list[str]
    passive_selected_cipher: str | None = None
    active_accepted_cipher: str | None = None
    concordance_details: dict[str, Any]
    evaluated_at: datetime
