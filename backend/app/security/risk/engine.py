"""Deterministic Risk Engine.

Computes repeatable risk tiers based on Finding Severity, Exploitation Likelihood,
Impact, and Observational Evidence State without generative hallucination.
"""

from __future__ import annotations

from app.security.facts.models import EvidenceState
from app.security.findings.models import SecurityFinding
from app.security.policy.schema import Severity
from app.security.risk.models import (
    Impact,
    Likelihood,
    RiskAssessment,
    RiskItem,
    RiskPolicy,
    RiskTier,
)


class DeterministicRiskEngine:
    """Evaluates risk deterministically per finding from structured factors."""

    def __init__(self, policy: RiskPolicy | None = None) -> None:
        self.policy = policy or RiskPolicy()
        if not self.policy.policy_hash:
            p_hash = self.policy.compute_hash()
            object.__setattr__(self.policy, "policy_hash", p_hash)

    def assess_risks(
        self,
        analysis_id: str,
        findings: list[SecurityFinding],
    ) -> RiskAssessment:
        """Alias for evaluate_risk."""
        return self.evaluate_risk(analysis_id, findings)

    def evaluate_risk(
        self,
        analysis_id: str,
        findings: list[SecurityFinding],
    ) -> RiskAssessment:
        """Compute structured risk items and aggregate risk tier."""
        risk_items: list[RiskItem] = []

        for finding in findings:
            likelihood, impact, tier = self._map_factors(finding)
            risk_items.append(
                RiskItem(
                    finding_id=finding.finding_id,
                    rule_id=finding.rule_id,
                    severity=finding.severity,
                    evidence_state=finding.evidence_state,
                    likelihood=likelihood,
                    impact=impact,
                    risk_tier=tier,
                    rationale=(
                        f"Evaluated from {finding.severity.value} severity, "
                        f"{likelihood.value} likelihood, {impact.value} impact under {finding.evidence_state.value} evidence."
                    ),
                )
            )

        # Aggregate overall risk tier
        if any(item.risk_tier == RiskTier.CRITICAL for item in risk_items):
            overall = RiskTier.CRITICAL
        elif any(item.risk_tier == RiskTier.HIGH for item in risk_items):
            overall = RiskTier.HIGH
        elif any(item.risk_tier == RiskTier.MEDIUM for item in risk_items):
            overall = RiskTier.MEDIUM
        else:
            overall = RiskTier.LOW

        return RiskAssessment(
            analysis_id=analysis_id,
            risk_policy_id=self.policy.policy_id,
            risk_policy_version=self.policy.policy_version,
            risk_policy_hash=self.policy.policy_hash,
            overall_risk_tier=overall,
            risk_items=risk_items,
        )

    def _map_factors(self, finding: SecurityFinding) -> tuple[Likelihood, Impact, RiskTier]:
        """Deterministic mapping matrix."""
        sev = finding.severity
        ev = finding.evidence_state

        if sev == Severity.CRITICAL:
            likelihood = Likelihood.HIGH
            impact = Impact.HIGH
            tier = RiskTier.CRITICAL if ev == EvidenceState.VERIFIED else RiskTier.HIGH
            return likelihood, impact, tier

        if sev == Severity.HIGH:
            if ev == EvidenceState.VERIFIED:
                likelihood = Likelihood.MEDIUM
                impact = Impact.HIGH
                tier = RiskTier.HIGH
            else:
                likelihood = Likelihood.LOW
                impact = Impact.MEDIUM
                tier = RiskTier.MEDIUM
            return likelihood, impact, tier

        if sev == Severity.MEDIUM:
            likelihood = Likelihood.LOW
            impact = Impact.LOW
            tier = RiskTier.MEDIUM
            return likelihood, impact, tier

        # LOW or INFORMATIONAL
        return Likelihood.LOW, Impact.LOW, RiskTier.LOW
