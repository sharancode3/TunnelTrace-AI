"""Stage 8: Security, Compliance, Evidence & Scoring Engine.

Deterministic security analysis, Policy-as-Code, posture scoring, risk modeling,
threat matrix mapping, metadata fingerprintability, and forensic provenance graph.
"""

from app.security.manifest import AssessmentManifest
from app.security.service import SecurityAssessmentResult, SecurityAssessmentService

__all__ = [
    "AssessmentManifest",
    "SecurityAssessmentResult",
    "SecurityAssessmentService",
]
