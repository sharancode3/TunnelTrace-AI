"""Sequence Schema Definition for Stage 7 1D-CNN Encrypted Flow Representation."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class SequenceSchema:
    """Defines the deterministic sequence representation for 1D-CNN encrypted traffic inference.

    Channels:
        1. direction: +1.0 for forward (initiator-to-responder), -1.0 for reverse, 0.0 for padding.
        2. packet_length: outer encrypted packet length normalized by length_norm_factor.
        3. delta_time: nonnegative inter-arrival time from previous packet, clipped at delta_time_clip.
    """

    version: str = "1.0.0"
    channels: list[str] = field(default_factory=lambda: ["direction", "packet_length", "delta_time"])
    candidate_horizons: list[int] = field(default_factory=lambda: [32, 64, 128])
    default_horizon: int = 64
    length_norm_factor: float = 1500.0
    delta_time_clip: float = 5.0  # seconds
    padding_value: float = 0.0
    direction_forward: float = 1.0
    direction_reverse: float = -1.0
    min_cnn_packets: int = 3
    dtype: str = "float32"

    def to_dict(self) -> dict[str, Any]:
        """Convert sequence schema to serializable dictionary."""
        return asdict(self)

    def to_json(self) -> str:
        """Convert sequence schema to canonical sorted JSON string."""
        return json.dumps(self.to_dict(), sort_keys=True, indent=2)

    def schema_hash(self) -> str:
        """Compute authoritative SHA-256 digest of the canonical sequence schema."""
        canonical_bytes = json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(canonical_bytes).hexdigest()

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SequenceSchema:
        """Instantiate sequence schema from dictionary."""
        valid_keys = cls.__dataclass_fields__.keys()
        filtered = {k: v for k, v in data.items() if k in valid_keys}
        return cls(**filtered)

    @classmethod
    def canonical_schema(cls) -> SequenceSchema:
        """Authoritative canonical SequenceSchema instance."""
        return cls()
