"""Data Models for Deterministic Risk Engine.

Binds canonical methodology definitions, itemized risk factor breakdowns,
and transparent aggregate evaluations without black-box scores or unevidenced safety claims.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from app.security.facts.models import EvidenceState
from app.security.policy.schema import Severity


class RiskTier(str, Enum):
    """Categorical composite risk levels with honest empty and unevidenced states."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NO_FINDINGS_UNDER_THIS_POLICY = "NO_FINDINGS_UNDER_THIS_POLICY"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    UNKNOWN = "UNKNOWN"


class Likelihood(str, Enum):
    """Exploitation likelihood tier."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class Impact(str, Enum):
    """Exploitation impact tier."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


@dataclass(frozen=True)
class RiskFactorDetail:
    """Individual inspectable factor contributing to or contextualizing an item's risk."""

    factor_name: str
    factor_value: str
    scale: str
    evidence_state: str = "VERIFIED"
    source: str = ""
    source_time: str = ""
    contributes_to_aggregate: bool = True
    aggregation_role: str = "PRIMARY_DRIVER"
    rationale: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "factor_name": self.factor_name,
            "factor_value": self.factor_value,
            "scale": self.scale,
            "evidence_state": self.evidence_state,
            "source": self.source,
            "source_time": self.source_time,
            "contributes_to_aggregate": self.contributes_to_aggregate,
            "aggregation_role": self.aggregation_role,
            "rationale": self.rationale,
        }


@dataclass(frozen=True)
class RiskItem:
    """Itemized risk record bound to a specific SecurityFinding with factor-level transparency."""

    finding_id: str
    rule_id: str
    severity: Severity
    evidence_state: EvidenceState
    likelihood: Likelihood
    impact: Impact
    risk_tier: RiskTier
    rationale: str
    factors: list[RiskFactorDetail] = field(default_factory=list)
    contributes_to_aggregate: bool = True
    aggregation_role: str = "PRIMARY_DRIVER"
    root_cause_key: str = ""
    policy_version: str = "1.0.0"
    policy_hash: str = ""
    methodology_type: str = "DETERMINISTIC_PRIORITIZATION_HEURISTIC"

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "evidence_state": self.evidence_state.value,
            "likelihood": self.likelihood.value,
            "impact": self.impact.value,
            "risk_tier": self.risk_tier.value,
            "rationale": self.rationale,
            "factors": [f.to_dict() for f in self.factors],
            "contributes_to_aggregate": self.contributes_to_aggregate,
            "aggregation_role": self.aggregation_role,
            "root_cause_key": self.root_cause_key,
            "policy_version": self.policy_version,
            "policy_hash": self.policy_hash,
            "methodology_type": self.methodology_type,
        }


# Canonical default severity mapping matrix: (Severity, is_verified) -> (Likelihood, Impact, RiskTier)
DEFAULT_SEVERITY_MAPPING: dict[str, dict[str, tuple[str, str, str]]] = {
    "CRITICAL": {
        "VERIFIED": ("HIGH", "HIGH", "CRITICAL"),
        "UNVERIFIED": ("HIGH", "HIGH", "HIGH"),
    },
    "HIGH": {
        "VERIFIED": ("MEDIUM", "HIGH", "HIGH"),
        "UNVERIFIED": ("LOW", "MEDIUM", "MEDIUM"),
    },
    "MEDIUM": {
        "VERIFIED": ("LOW", "LOW", "MEDIUM"),
        "UNVERIFIED": ("LOW", "LOW", "MEDIUM"),
    },
    "LOW": {
        "VERIFIED": ("LOW", "LOW", "LOW"),
        "UNVERIFIED": ("LOW", "LOW", "LOW"),
    },
    "INFORMATIONAL": {
        "VERIFIED": ("LOW", "LOW", "LOW"),
        "UNVERIFIED": ("LOW", "LOW", "LOW"),
    },
}


@dataclass(frozen=True)
class RiskPolicy:
    """Versioned, canonical risk assessment methodology definition.

    Binds all mappings, thresholds, aggregation rules, and fallbacks into a
    deterministic SHA-256 hash.
    """

    policy_id: str = "risk_policy_canonical_v1"
    policy_version: str = "1.0.0"
    methodology_type: str = "DETERMINISTIC_PRIORITIZATION_HEURISTIC"
    insufficient_evidence_threshold: float = 50.0
    empty_findings_behavior: str = "NO_FINDINGS_UNDER_THIS_POLICY"
    root_cause_deduplication: bool = True
    missing_data_rule: str = "UNASSESSED_EXPLICIT_GAP"
    aggregation_hierarchy: tuple[str, ...] = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
    severity_mapping: dict[str, dict[str, tuple[str, str, str]]] = field(
        default_factory=lambda: {k: dict(v) for k, v in DEFAULT_SEVERITY_MAPPING.items()}
    )
    disclaimer: str = (
        "Internal product-defined deterministic prioritization heuristic. "
        "Evaluated from protocol policy findings, evidence state, and rule mappings. "
        "NOT an empirically calibrated attack probability or official safety certification."
    )
    policy_hash: str = field(default="")

    def compute_hash(self) -> str:
        """Compute canonical SHA-256 hash binding the complete methodology."""
        # Convert severity mapping to a canonical sorted structure
        canonical_mapping = {
            sev: {
                ev: list(triplet)
                for ev, triplet in sorted(submap.items())
            }
            for sev, submap in sorted(self.severity_mapping.items())
        }

        data = {
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "methodology_type": self.methodology_type,
            "insufficient_evidence_threshold": self.insufficient_evidence_threshold,
            "empty_findings_behavior": self.empty_findings_behavior,
            "root_cause_deduplication": self.root_cause_deduplication,
            "missing_data_rule": self.missing_data_rule,
            "aggregation_hierarchy": list(self.aggregation_hierarchy),
            "severity_mapping": canonical_mapping,
        }
        serialized = json.dumps(data, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class RiskAssessment:
    """Aggregate risk assessment outcome for an analysis run."""

    analysis_id: str
    risk_policy_id: str
    risk_policy_version: str
    risk_policy_hash: str
    overall_risk_tier: RiskTier
    risk_items: list[RiskItem]
    evidence_coverage: float | None = None
    evidence_gaps_count: int = 0
    methodology_type: str = "DETERMINISTIC_PRIORITIZATION_HEURISTIC"
    disclaimer: str = (
        "Internal product-defined deterministic prioritization heuristic. "
        "Evaluated from protocol policy findings, evidence state, and rule mappings. "
        "NOT an empirically calibrated attack probability or official safety certification."
    )
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def items(self) -> list[RiskItem]:
        return self.risk_items

    def to_dict(self) -> dict[str, Any]:
        return {
            "analysis_id": self.analysis_id,
            "risk_policy_id": self.risk_policy_id,
            "risk_policy_version": self.risk_policy_version,
            "risk_policy_hash": self.risk_policy_hash,
            "overall_risk_tier": self.overall_risk_tier.value,
            "risk_items": [item.to_dict() for item in self.risk_items],
            "evidence_coverage": round(self.evidence_coverage, 2) if self.evidence_coverage is not None else None,
            "evidence_gaps_count": self.evidence_gaps_count,
            "methodology_type": self.methodology_type,
            "disclaimer": self.disclaimer,
            "created_at": self.created_at.isoformat(),
        }
