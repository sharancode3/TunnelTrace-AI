"""Pydantic request and response schemas for Stage 4 Reconstruction APIs."""

from __future__ import annotations

import uuid
from typing import Any

from pydantic import BaseModel, Field


class TrafficSelectorDTO(BaseModel):
    """Traffic Selector details."""

    id: uuid.UUID
    direction: str
    ip_subnet: str | None = None
    start_ip: str | None = None
    end_ip: str | None = None
    ip_protocol: int = 0
    start_port: int = 0
    end_port: int = 65535
    evidence_state: str = "VERIFIED"


class IKESecurityAssociationDTO(BaseModel):
    """Parent IKE SA details."""

    id: uuid.UUID
    session_id: uuid.UUID
    encryption_algorithm: str | None = None
    key_length_bits: int | None = None
    prf_algorithm: str | None = None
    integrity_algorithm: str | None = None
    dh_group: str | None = None
    selection_evidence_state: str = "VERIFIED"
    established_at: float | None = None
    evidence_state: str = "VERIFIED"


class ChildSecurityAssociationDTO(BaseModel):
    """Child SA details."""

    id: uuid.UUID
    analysis_id: uuid.UUID
    ike_sa_id: uuid.UUID | None = None
    protocol: str = "ESP"
    inbound_spi: str
    outbound_spi: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    mode: str = "UNKNOWN"
    mode_evidence_state: str = "UNKNOWN"
    encryption_algorithm: str | None = None
    integrity_algorithm: str | None = None
    pfs_status: str = "UNKNOWN"
    pfs_dh_group: str | None = None
    pfs_evidence_state: str = "UNKNOWN"
    first_observed_at: float | None = None
    last_observed_at: float | None = None
    lifecycle_state: str = "ACTIVE_INFERRED"
    evidence_state: str = "VERIFIED"
    traffic_selectors: list[TrafficSelectorDTO] = Field(default_factory=list)


class IKESessionResponseDTO(BaseModel):
    """IKE session summary response."""

    id: uuid.UUID
    analysis_id: uuid.UUID
    initiator_spi: str
    responder_spi: str | None = None
    ike_version: str
    initiator_ip: str | None = None
    responder_ip: str | None = None
    initiator_port: int | None = None
    responder_port: int | None = None
    first_observed_at: float
    last_observed_at: float
    lifecycle_state: str
    is_nat_detected: bool = False
    retransmission_count: int = 0
    packet_count: int = 0
    evidence_state: str = "VERIFIED"
    frame_numbers: list[int] | None = None


class IKESessionDetailDTO(IKESessionResponseDTO):
    """IKE session detailed response with nested parent SA and Child SAs."""

    parent_sa: IKESecurityAssociationDTO | None = None
    child_sas: list[ChildSecurityAssociationDTO] = Field(default_factory=list)


class FlowResponseDTO(BaseModel):
    """Statistical encrypted ESP flow."""

    id: uuid.UUID
    analysis_id: uuid.UUID
    child_sa_id: uuid.UUID | None = None
    spi: str
    reverse_spi: str | None = None
    src_ip: str
    dst_ip: str
    ip_version: str
    is_nat_t: bool
    orientation_basis: str
    start_time: float
    end_time: float
    duration_seconds: float
    packet_count: int
    byte_count: int
    forward_packets: int
    forward_bytes: int
    reverse_packets: int
    reverse_bytes: int
    association_state: str
    end_reason: str


class FlowListResponseDTO(BaseModel):
    """Paginated list of encrypted flows."""

    analysis_id: uuid.UUID
    total_flows: int
    items: list[FlowResponseDTO]


class SAGraphNodeDTO(BaseModel):
    """React Flow-compatible graph node representing a reconstructed protocol entity."""

    id: str
    type: str  # peer, session, ike_sa, child_sa, flow, unmapped_sa
    label: str
    data: dict[str, Any] = Field(default_factory=dict)


class SAGraphEdgeDTO(BaseModel):
    """React Flow-compatible graph edge representing relationship between entities."""

    id: str
    source: str
    target: str
    label: str  # PARTICIPATES_IN, NEGOTIATES, PARENT_OF, PROTECTS, REKEYS_TO


class SAGraphResponseDTO(BaseModel):
    """Topology graph of reconstructed IKE sessions, SAs, and Flows."""

    analysis_id: uuid.UUID
    nodes: list[SAGraphNodeDTO]
    edges: list[SAGraphEdgeDTO]
