"""Replay and Evidence Chain Subsystem.

Provides controlled scenario replay and deterministic forensic re-analysis capabilities.
"""

from app.replay.comparator import ForensicReplayComparator, ReplayStatus, ScenarioReplayComparator
from app.replay.models import (
    CaptureIntegrityError,
    EnvironmentMismatchError,
    ForensicReanalysisRequestDTO,
    ReplayComparisonDTO,
    ReplayLineageDTO,
)
from app.replay.redaction import (
    canonicalize_config,
    compute_canonical_config_digest,
    redact_secrets_dict,
    redact_secrets_text,
)
from app.replay.service import ReplayService

__all__ = [
    "ReplayService",
    "ReplayStatus",
    "ForensicReplayComparator",
    "ScenarioReplayComparator",
    "redact_secrets_text",
    "redact_secrets_dict",
    "canonicalize_config",
    "compute_canonical_config_digest",
    "CaptureIntegrityError",
    "EnvironmentMismatchError",
    "ForensicReanalysisRequestDTO",
    "ReplayComparisonDTO",
    "ReplayLineageDTO",
]
