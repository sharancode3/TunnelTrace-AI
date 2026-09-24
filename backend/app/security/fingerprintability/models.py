"""Domain models and data structures for Metadata Fingerprintability.

Quantifies behavioral side-channel distinguishability from outer packet metadata
and encrypted flow timing/size patterns.

STRICT DISCLAIMER:
This is NOT plaintext leakage percentage.
This is NOT data exfiltration percentage.
This is NOT probability of compromise.
This is NOT a NIST compliance failure.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from enum import Enum


class FingerprintabilityStatus(str, Enum):
    """Methodological validation status of fingerprintability index."""

    EXPERIMENTAL = "EXPERIMENTAL"
    VALIDATED = "VALIDATED"
    UNAVAILABLE = "UNAVAILABLE"


class CalibrationStatus(str, Enum):
    """Stage 7 calibration state for model-based distinguishability."""

    CALIBRATED = "CALIBRATED"
    UNAVAILABLE = "UNAVAILABLE"
    RAW_UNACCEPTED = "RAW_UNACCEPTED"


@dataclass(frozen=True)
class FingerprintabilityComponent:
    """Individual normalized side-channel distinguishability component."""

    name: str
    score: float  # [0.0, 100.0]
    weight: float
    unit: str = "index_0_100"
    is_available: bool = True
    rationale: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class MetadataFingerprintabilityAssessment:
    """Comprehensive side-channel behavioral distinguishability assessment."""

    analysis_id: str
    flow_id: str | None
    overall_index: float | None  # [0.0, 100.0] composite index if available
    status: FingerprintabilityStatus
    methodology_version: str
    methodology_hash: str
    components: dict[str, FingerprintabilityComponent]
    flow_count: int
    ml_model_bundle_id: str | None
    calibration_status: CalibrationStatus
    disclaimer: str = (
        "Behavioral metadata fingerprintability / side-channel distinguishability index. "
        "This metric quantifies how distinguishably encrypted flow timing, packet sizing, "
        "and directionality behave compared to isotropic background traffic without decrypting ESP. "
        "It is NOT plaintext leakage percentage, data exfiltration percentage, or a NIST compliance failure."
    )

    def to_dict(self) -> dict:
        data = asdict(self)
        data["status"] = self.status.value
        data["calibration_status"] = self.calibration_status.value
        return data

    @classmethod
    def compute_methodology_hash(cls, version: str, component_weights: dict[str, float]) -> str:
        """Compute deterministic SHA-256 fingerprint for methodology version and weights."""
        raw = json.dumps({"version": version, "weights": component_weights}, sort_keys=True)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()
