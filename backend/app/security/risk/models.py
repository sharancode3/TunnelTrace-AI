"""Data Models for Deterministic Risk Engine."""

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
    """Categorical composite risk levels."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


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
class RiskItem:
    """Itemized risk record bound to a specific SecurityFinding."""

    finding_id: str
    rule_id: str
    severity: Severity
    evidence_state: EvidenceState
    likelihood: Likelihood
    impact: Impact
    risk_tier: RiskTier
    rationale: str

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
        }


@dataclass(frozen=True)
class RiskPolicy:
    """Versioned risk assessment methodology definition."""

    policy_id: str = "risk_policy_canonical_v1"
    policy_version: str = "1.0.0"
    policy_hash: str = field(default="")

    def compute_hash(self) -> str:
        data = {"policy_id": self.policy_id, "policy_version": self.policy_version}
        return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()


@dataclass(frozen=True)
class RiskAssessment:
    """Aggregate risk assessment outcome for an analysis run."""

    analysis_id: str
    risk_policy_id: str
    risk_policy_version: str
    risk_policy_hash: str
    overall_risk_tier: RiskTier
    risk_items: list[RiskItem]
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
            "created_at": self.created_at.isoformat(),
        }
