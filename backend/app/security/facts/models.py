"""Typed Data Models for Normalized Security Facts."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class SubjectType(str, Enum):
    """Categorization of entities to which security facts attach."""

    IKE_SESSION = "IKE_SESSION"
    IKE_SA = "IKE_SA"
    CHILD_SA = "CHILD_SA"
    ESP_FLOW = "ESP_FLOW"
    CAPTURE = "CAPTURE"


class EvidenceState(str, Enum):
    """Rigorous epistemic state model for observable protocol facts."""

    VERIFIED = "VERIFIED"  # Directly observed in cleartext headers or deterministic handshakes
    INFERRED = "INFERRED"  # Deduced through rigorous deterministic contextual correlation
    UNKNOWN = "UNKNOWN"  # Required protocol evidence is absent / unobserved in capture window
    MISCONFIGURATION_OBSERVED = "MISCONFIGURATION_OBSERVED"  # Directly observed fact violates valid RFC/standards


class DerivationType(str, Enum):
    """Lineage classification of how the fact was obtained."""

    DIRECT = "DIRECT"  # Extracted directly from a single frame/payload observation
    DETERMINISTIC_DERIVATION = "DETERMINISTIC_DERIVATION"  # Derived via deterministic state-machine or aggregator
    INFERENCE = "INFERENCE"  # Inferred via contextual heuristic (e.g. Tunnel mode from outer IP header)


@dataclass(frozen=True)
class SecurityFact:
    """Immutable, typed normalized security fact serving as input to Policy-as-Code.

    Maintains strict cryptographic and observational provenance back to Stage 3 frames
    and Stage 4 reconstructed entities.
    """

    key: str
    value: Any
    data_type: str  # "string", "integer", "float", "boolean", "list_string", "list_int"
    subject_type: SubjectType
    subject_id: str
    evidence_state: EvidenceState
    analysis_id: str
    capture_sha256: str
    fact_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    source_observation_ids: tuple[str, ...] = field(default_factory=tuple)
    source_reconstruction_ids: tuple[str, ...] = field(default_factory=tuple)
    source_frame_numbers: tuple[int, ...] = field(default_factory=tuple)
    derivation_type: DerivationType = DerivationType.DIRECT
    derivation_rule: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def canonical_key(self) -> str:
        return self.key

    def __init__(
        self,
        key: str | None = None,
        value: Any = None,
        data_type: str = "string",
        subject_type: SubjectType = SubjectType.IKE_SESSION,
        subject_id: str = "",
        evidence_state: EvidenceState = EvidenceState.VERIFIED,
        analysis_id: str = "",
        capture_sha256: str = "",
        fact_id: str | None = None,
        source_observation_ids: tuple[str, ...] | list[str] = (),
        source_reconstruction_ids: tuple[str, ...] | list[str] = (),
        source_frame_numbers: tuple[int, ...] | list[int] = (),
        derivation_type: DerivationType = DerivationType.DIRECT,
        derivation_rule: str | None = None,
        created_at: datetime | None = None,
        canonical_key: str | None = None,
    ) -> None:
        object.__setattr__(self, "key", canonical_key if key is None else key)
        object.__setattr__(self, "value", value)
        object.__setattr__(self, "data_type", data_type)
        object.__setattr__(self, "subject_type", subject_type)
        object.__setattr__(self, "subject_id", subject_id)
        object.__setattr__(self, "evidence_state", evidence_state)
        object.__setattr__(self, "analysis_id", analysis_id)
        object.__setattr__(self, "capture_sha256", capture_sha256)
        object.__setattr__(self, "fact_id", fact_id or str(uuid.uuid4()))
        object.__setattr__(self, "source_observation_ids", tuple(source_observation_ids))
        object.__setattr__(self, "source_reconstruction_ids", tuple(source_reconstruction_ids))
        object.__setattr__(self, "source_frame_numbers", tuple(source_frame_numbers))
        object.__setattr__(self, "derivation_type", derivation_type)
        object.__setattr__(self, "derivation_rule", derivation_rule)
        object.__setattr__(self, "created_at", created_at or datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        """Convert fact to serializable dictionary representation."""
        return {
            "fact_id": self.fact_id,
            "analysis_id": self.analysis_id,
            "subject_type": self.subject_type.value,
            "subject_id": self.subject_id,
            "key": self.key,
            "value": self.value,
            "data_type": self.data_type,
            "evidence_state": self.evidence_state.value,
            "source_observation_ids": list(self.source_observation_ids),
            "source_reconstruction_ids": list(self.source_reconstruction_ids),
            "source_frame_numbers": list(self.source_frame_numbers),
            "capture_sha256": self.capture_sha256,
            "derivation_type": self.derivation_type.value,
            "derivation_rule": self.derivation_rule,
            "created_at": self.created_at.isoformat(),
        }
