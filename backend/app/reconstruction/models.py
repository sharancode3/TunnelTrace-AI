"""Domain models, enums, and data transfer structures for Stage 4 Reconstruction."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum


class EvidenceState(str, Enum):
    """Analytical certainty level."""

    VERIFIED = "VERIFIED"
    INFERRED = "INFERRED"
    UNKNOWN = "UNKNOWN"
    MISCONFIGURATION_OBSERVED = "MISCONFIGURATION_OBSERVED"


class Mode(str, Enum):
    """IPsec operational encapsulation mode."""

    TUNNEL = "TUNNEL"
    TRANSPORT = "TRANSPORT"
    UNKNOWN = "UNKNOWN"


class PFSStatus(str, Enum):
    """Perfect Forward Secrecy negotiation status."""

    ENABLED = "ENABLED"
    DISABLED = "DISABLED"
    UNKNOWN = "UNKNOWN"


class OrientationBasis(str, Enum):
    """Basis used for directional stream orientation."""

    PROTOCOL_ROLE = "PROTOCOL_ROLE"  # Initiator vs Responder
    FIRST_SEEN = "FIRST_SEEN"        # First observed packet defines forward
    UNKNOWN = "UNKNOWN"


class FlowAssociationState(str, Enum):
    """Level of bidirectional flow association."""

    PAIRED_BIDIRECTIONAL = "PAIRED_BIDIRECTIONAL"
    UNPAIRED_UNIDIRECTIONAL = "UNPAIRED_UNIDIRECTIONAL"
    ORPHAN = "ORPHAN"


class FlowEndReason(str, Enum):
    """Defensible reason for flow boundary termination."""

    REKEY_OBSERVED = "REKEY_OBSERVED"
    DELETE_OBSERVED = "DELETE_OBSERVED"
    CAPTURE_ENDED = "CAPTURE_ENDED"
    IDLE_TIMEOUT = "IDLE_TIMEOUT"
    ACTIVE_TIMEOUT = "ACTIVE_TIMEOUT"
    UNKNOWN = "UNKNOWN"


class LifecycleState(str, Enum):
    """Lifecycle state of session or SA."""

    INIT_SEEN = "INIT_SEEN"
    AUTH_SEEN = "AUTH_SEEN"
    ACTIVE_INFERRED = "ACTIVE_INFERRED"
    PARTIAL = "PARTIAL"
    ORPHAN = "ORPHAN"
    REKEYED = "REKEYED"
    TERMINATED = "TERMINATED"
    UNKNOWN = "UNKNOWN"


# Reconstructed In-Memory Entities


@dataclass
class IKEMessageEvent:
    """Represents a single parsed IKE packet event for state-machine correlation."""

    frame_number: int
    packet_time: float
    ike_version: str
    initiator_spi: str
    responder_spi: str | None
    exchange_type: str
    exchange_id: int | None
    message_id: int
    is_response: bool
    src_ip: str | None
    dst_ip: str | None
    src_port: int | None
    dst_port: int | None
    is_natt: bool = False
    transforms: list[dict] = field(default_factory=list)
    notifies: list[str] = field(default_factory=list)
    traffic_selectors: list[dict] = field(default_factory=list)


@dataclass
class ReconstructedIKESession:
    """Correlated logical IKE negotiation session."""

    id: uuid.UUID = field(default_factory=uuid.uuid4)
    analysis_id: uuid.UUID = field(default_factory=uuid.uuid4)
    initiator_spi: str = ""
    responder_spi: str | None = None
    ike_version: str = "IKEv2"
    initiator_ip: str | None = None
    responder_ip: str | None = None
    initiator_port: int | None = None
    responder_port: int | None = None
    first_observed_at: float = 0.0
    last_observed_at: float = 0.0
    lifecycle_state: LifecycleState = LifecycleState.ACTIVE_INFERRED
    is_nat_detected: bool = False
    retransmission_count: int = 0
    packet_count: int = 0
    evidence_state: EvidenceState = EvidenceState.VERIFIED
    frame_numbers: list[int] = field(default_factory=list)

    # Sub-entities
    parent_sa: ReconstructedParentIKESA | None = None
    child_sas: list[ReconstructedChildSA] = field(default_factory=list)


@dataclass
class ReconstructedParentIKESA:
    """Negotiated parent IKE Security Association."""

    id: uuid.UUID = field(default_factory=uuid.uuid4)
    session_id: uuid.UUID = field(default_factory=uuid.uuid4)
    encryption_algorithm: str | None = None
    key_length_bits: int | None = None
    prf_algorithm: str | None = None
    integrity_algorithm: str | None = None
    dh_group: str | None = None
    selection_evidence_state: EvidenceState = EvidenceState.VERIFIED
    established_at: float | None = None
    evidence_state: EvidenceState = EvidenceState.VERIFIED


@dataclass
class ReconstructedChildSA:
    """Child Security Association protecting ESP/AH data traffic."""

    id: uuid.UUID = field(default_factory=uuid.uuid4)
    analysis_id: uuid.UUID = field(default_factory=uuid.uuid4)
    ike_sa_id: uuid.UUID | None = None
    protocol: str = "ESP"
    inbound_spi: str = ""
    outbound_spi: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    mode: Mode = Mode.UNKNOWN
    mode_evidence_state: EvidenceState = EvidenceState.UNKNOWN
    encryption_algorithm: str | None = None
    integrity_algorithm: str | None = None
    pfs_status: PFSStatus = PFSStatus.UNKNOWN
    pfs_dh_group: str | None = None
    pfs_evidence_state: EvidenceState = EvidenceState.UNKNOWN
    first_observed_at: float | None = None
    last_observed_at: float | None = None
    lifecycle_state: LifecycleState = LifecycleState.ACTIVE_INFERRED
    evidence_state: EvidenceState = EvidenceState.VERIFIED
    traffic_selectors: list[ReconstructedTrafficSelector] = field(default_factory=list)


@dataclass
class ReconstructedTrafficSelector:
    """Negotiated Traffic Selector entry."""

    id: uuid.UUID = field(default_factory=uuid.uuid4)
    child_sa_id: uuid.UUID = field(default_factory=uuid.uuid4)
    direction: str = "INITIATOR"
    ip_subnet: str | None = None
    start_ip: str | None = None
    end_ip: str | None = None
    ip_protocol: int = 0
    start_port: int = 0
    end_port: int = 65535
    evidence_state: EvidenceState = EvidenceState.VERIFIED


@dataclass
class ReconstructedESPStream:
    """Unidirectional stream of ESP packets sharing (src_ip, dst_ip, spi)."""

    spi: str
    src_ip: str
    dst_ip: str
    ip_version: str
    is_nat_t: bool
    start_time: float
    end_time: float
    packet_count: int
    byte_count: int
    sequence_numbers: list[int] = field(default_factory=list)
    frame_numbers: list[int] = field(default_factory=list)


@dataclass
class ReconstructedESPFlow:
    """Aggregated directional or paired bidirectional encrypted flow."""

    id: uuid.UUID = field(default_factory=uuid.uuid4)
    analysis_id: uuid.UUID = field(default_factory=uuid.uuid4)
    child_sa_id: uuid.UUID | None = None
    spi: str = ""
    reverse_spi: str | None = None
    src_ip: str = ""
    dst_ip: str = ""
    ip_version: str = "IPv4"
    is_nat_t: bool = False
    orientation_basis: OrientationBasis = OrientationBasis.FIRST_SEEN
    start_time: float = 0.0
    end_time: float = 0.0
    duration_seconds: float = 0.0
    packet_count: int = 0
    byte_count: int = 0
    forward_packets: int = 0
    forward_bytes: int = 0
    reverse_packets: int = 0
    reverse_bytes: int = 0
    association_state: FlowAssociationState = FlowAssociationState.PAIRED_BIDIRECTIONAL
    end_reason: FlowEndReason = FlowEndReason.CAPTURE_ENDED


@dataclass
class ReconstructionSummary:
    """Summary metrics of the reconstruction phase."""

    analysis_id: uuid.UUID
    ike_sessions_count: int
    ike_sas_count: int
    child_sas_count: int
    orphan_child_sas_count: int
    directional_streams_count: int
    paired_flows_count: int
    unpaired_flows_count: int
    mode_verified_count: int
    mode_inferred_count: int
    mode_unknown_count: int
    pfs_known_count: int
    pfs_unknown_count: int
    retransmissions_detected: int
