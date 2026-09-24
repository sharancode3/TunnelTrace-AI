"""Metadata Fingerprintability Subsystem.

Evaluates behavioral side-channel distinguishability from outer packet metadata
and encrypted flow timing/size patterns.
"""

from app.security.fingerprintability.components import (
    compute_burst_distinguishability,
    compute_classifier_distinguishability,
    compute_directional_asymmetry,
    compute_packet_size_regularity,
    compute_predictive_entropy_complement,
    compute_timing_regularity,
)
from app.security.fingerprintability.engine import MetadataFingerprintabilityEngine
from app.security.fingerprintability.models import (
    CalibrationStatus,
    FingerprintabilityComponent,
    FingerprintabilityStatus,
    MetadataFingerprintabilityAssessment,
)

__all__ = [
    "CalibrationStatus",
    "FingerprintabilityComponent",
    "FingerprintabilityStatus",
    "MetadataFingerprintabilityAssessment",
    "MetadataFingerprintabilityEngine",
    "compute_burst_distinguishability",
    "compute_classifier_distinguishability",
    "compute_directional_asymmetry",
    "compute_packet_size_regularity",
    "compute_predictive_entropy_complement",
    "compute_timing_regularity",
]
