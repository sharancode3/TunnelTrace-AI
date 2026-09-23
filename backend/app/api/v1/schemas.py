"""Pydantic request and response schemas for Stage 3 REST endpoints."""

import uuid
from datetime import datetime

from pydantic import BaseModel, Field


class CaptureResponseDTO(BaseModel):
    """Metadata response for an ingested packet capture."""

    capture_id: uuid.UUID
    capture_source: str
    capture_format: str
    original_filename: str | None
    file_size_bytes: int
    sha256: str
    packet_count: int | None = None
    duration_sec: float | None = None
    first_packet_at: datetime | None = None
    last_packet_at: datetime | None = None
    link_layer_type: str | None = None
    validation_state: str
    created_at: datetime


class CreateAnalysisRequestDTO(BaseModel):
    """Request payload to initiate protocol analysis."""

    capture_id: uuid.UUID = Field(..., description="Target capture UUID to analyze")


class AnalysisRunResponseDTO(BaseModel):
    """Response payload detailing analysis run status and stage."""

    analysis_id: uuid.UUID
    capture_id: uuid.UUID
    status: str
    current_stage: str
    parser_engine: str
    parser_version: str
    schema_version: str
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error_code: str | None = None
    error_message: str | None = None
    created_at: datetime


class InterfaceMetadataDTO(BaseModel):
    """Authorized network interface for live capture."""

    interface_id: str
    display_name: str
    type: str
    capture_allowed: bool
    lab_owned: bool
    operstate: str = "UNKNOWN"


class StartLiveCaptureRequestDTO(BaseModel):
    """Request payload to initiate authorized live packet capture."""

    interface_id: str = Field(..., description="Target network interface (must be in allowlist)")
    duration_sec: int | None = Field(None, description="Optional maximum capture duration in seconds")
    capture_profile: str = Field(default="IPSEC_RELEVANT", description="Capture profile preset")
    bpf_filter: str | None = Field(None, description="Optional BPF filter expression")


class LiveCaptureSessionResponseDTO(BaseModel):
    """Response payload for a live capture session."""

    session_id: uuid.UUID
    interface_name: str
    status: str
    capture_profile: str
    packet_count: int
    byte_count: int
    duration_sec: float | None = None
    capture_id: uuid.UUID | None = None
    started_at: datetime | None = None
    stopped_at: datetime | None = None
    created_at: datetime


class StopLiveCaptureResponseDTO(BaseModel):
    """Response payload after stopping and finalizing a live capture."""

    session_id: uuid.UUID
    capture_id: uuid.UUID
    analysis_id: uuid.UUID | None = None
    status: str
    file_size_bytes: int
    packet_count: int
    sha256: str
