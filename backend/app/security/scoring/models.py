"""Data Models for Versioned Security Scoring and Deduction Audits."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from app.security.policy.schema import Severity


class ScorePolicyStatus(str, Enum):
    """Maturity and validation state of a scoring policy."""

    DRAFT = "DRAFT"
    EXPERIMENTAL = "EXPERIMENTAL"
    VALIDATED = "VALIDATED"
    ACTIVE = "ACTIVE"


@dataclass(frozen=True)
class ScoreDeduction:
    """Individual itemized deduction applied to the baseline score."""

    finding_id: str
    rule_id: str
    category: str
    severity: Severity
    root_cause_key: str
    raw_deduction: float
    applied_deduction: float
    is_deduplicated: bool  # True if suppressed by root-cause collapse
    rationale: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "category": self.category,
            "severity": self.severity.value,
            "root_cause_key": self.root_cause_key,
            "raw_deduction": self.raw_deduction,
            "applied_deduction": self.applied_deduction,
            "is_deduplicated": self.is_deduplicated,
            "rationale": self.rationale,
        }


@dataclass(frozen=True)
class ScorePolicy:
    """Immutable, versioned scoring policy governing deductions and category allocations."""

    policy_id: str = "score_policy_canonical_v1"
    policy_version: str = "1.0.0"
    status: ScorePolicyStatus = ScorePolicyStatus.VALIDATED
    base_score: float = 100.0
    min_score: float = 0.0
    max_score: float = 100.0
    severity_deductions: dict[Severity, float] = field(
        default_factory=lambda: {
            Severity.CRITICAL: 25.0,
            Severity.HIGH: 15.0,
            Severity.MEDIUM: 5.0,
            Severity.LOW: 2.0,
            Severity.INFORMATIONAL: 0.0,
        }
    )
    root_cause_deduplication: bool = True
    policy_hash: str = field(default="")

    def compute_policy_hash(self) -> str:
        """Compute SHA-256 digest of scoring configuration."""
        data = {
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "base_score": self.base_score,
            "severity_deductions": {k.value: v for k, v in self.severity_deductions.items()},
            "root_cause_dedup": self.root_cause_deduplication,
        }
        serialized = json.dumps(data, sort_keys=True)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class EvidenceCoverage:
    """Quantitative measurement of how much applicable protocol evidence was observable.

    Reported separately from the Security Posture Score to prevent hiding unknowns behind a high score.
    """

    applicable_rules: int
    evaluated_rules: int  # PASS + FAIL
    unknown_rules: int    # UNKNOWN
    not_applicable_rules: int
    coverage_percentage: float  # (evaluated / applicable) * 100

    def to_dict(self) -> dict[str, Any]:
        return {
            "applicable_rules": self.applicable_rules,
            "evaluated_rules": self.evaluated_rules,
            "unknown_rules": self.unknown_rules,
            "not_applicable_rules": self.not_applicable_rules,
            "coverage_percentage": round(self.coverage_percentage, 2),
        }


@dataclass(frozen=True)
class ScoreAssessment:
    """Complete, transparent outcome of the security scoring engine."""

    analysis_id: str
    overall_score: float  # Clamped to [min_score, max_score]
    raw_score: float
    score_policy_id: str
    score_policy_version: str
    score_policy_hash: str
    status: ScorePolicyStatus
    category_scores: dict[str, float]
    deduction_audit: list[ScoreDeduction]
    evidence_coverage: EvidenceCoverage
    disclaimer: str = (
        "Internal product diagnostic metric only. NOT an official NIST, government, "
        "FIPS, ISO, or Common Criteria certification."
    )
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        return {
            "analysis_id": self.analysis_id,
            "overall_score": round(self.overall_score, 1),
            "raw_score": round(self.raw_score, 1),
            "score_policy_id": self.score_policy_id,
            "score_policy_version": self.score_policy_version,
            "score_policy_hash": self.score_policy_hash,
            "status": self.status.value,
            "category_scores": {k: round(v, 1) for k, v in self.category_scores.items()},
            "deduction_audit": [d.to_dict() for d in self.deduction_audit],
            "evidence_coverage": self.evidence_coverage.to_dict(),
            "disclaimer": self.disclaimer,
            "created_at": self.created_at.isoformat(),
        }
