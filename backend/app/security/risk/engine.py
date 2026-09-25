"""Deterministic Risk Engine.

Computes repeatable risk tiers based on Finding Severity, Exploitation Likelihood,
Impact, and Observational Evidence State without generative hallucination.
Provides transparent factor breakdown and honest unevidenced / empty-findings states.
"""

from __future__ import annotations

from datetime import datetime, timezone

from app.security.facts.models import EvidenceState
from app.security.findings.models import SecurityFinding
from app.security.policy.schema import Severity
from app.security.risk.models import (
    Impact,
    Likelihood,
    RiskAssessment,
    RiskFactorDetail,
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
        evidence_coverage: float | None = None,
        evidence_gaps_count: int = 0,
    ) -> RiskAssessment:
        """Alias for evaluate_risk."""
        return self.evaluate_risk(
            analysis_id=analysis_id,
            findings=findings,
            evidence_coverage=evidence_coverage,
            evidence_gaps_count=evidence_gaps_count,
        )

    def evaluate_risk(
        self,
        analysis_id: str,
        findings: list[SecurityFinding],
        evidence_coverage: float | None = None,
        evidence_gaps_count: int = 0,
    ) -> RiskAssessment:
        """Compute structured risk items, factor breakdowns, and aggregate risk tier."""
        # 1. Honest handling of zero findings / empty evidence
        if not findings:
            if evidence_coverage is None or evidence_coverage < self.policy.insufficient_evidence_threshold:
                overall = RiskTier.INSUFFICIENT_EVIDENCE
            else:
                overall = RiskTier.NO_FINDINGS_UNDER_THIS_POLICY

            return RiskAssessment(
                analysis_id=analysis_id,
                risk_policy_id=self.policy.policy_id,
                risk_policy_version=self.policy.policy_version,
                risk_policy_hash=self.policy.policy_hash,
                overall_risk_tier=overall,
                risk_items=[],
                evidence_coverage=evidence_coverage,
                evidence_gaps_count=evidence_gaps_count,
                methodology_type=self.policy.methodology_type,
                disclaimer=self.policy.disclaimer,
            )

        # 2. Evaluate itemized risk and build transparent factor breakdowns
        risk_items: list[RiskItem] = []
        seen_root_causes: set[str] = set()
        now_iso = datetime.now(timezone.utc).isoformat()

        for finding in findings:
            likelihood, impact, tier = self._map_factors(finding)

            # Root-cause deduplication: determine whether this finding drives the aggregate
            is_duplicate = False
            if self.policy.root_cause_deduplication and finding.root_cause_key:
                if finding.root_cause_key in seen_root_causes:
                    is_duplicate = True
                else:
                    seen_root_causes.add(finding.root_cause_key)

            contributes = not is_duplicate
            agg_role = "PRIMARY_DRIVER" if contributes else "DEDUPLICATED_BY_ROOT_CAUSE"

            # Construct transparent, inspectable factor breakdown
            factors = [
                RiskFactorDetail(
                    factor_name="Policy Severity",
                    factor_value=finding.severity.value,
                    scale="INFORMATIONAL..CRITICAL",
                    evidence_state=finding.evidence_state.value,
                    source=f"PolicyRule({finding.rule_id})",
                    source_time=now_iso,
                    contributes_to_aggregate=contributes,
                    aggregation_role=agg_role,
                    rationale=f"Normative severity assigned by rule {finding.rule_id}.",
                ),
                RiskFactorDetail(
                    factor_name="Evidence Strength",
                    factor_value=finding.evidence_state.value,
                    scale="ASSUMED..VERIFIED",
                    source="ObservationNormalizer",
                    source_time=now_iso,
                    contributes_to_aggregate=contributes,
                    aggregation_role=agg_role,
                    rationale=f"Observed evidence state {finding.evidence_state.value} from packet capture facts.",
                ),
                RiskFactorDetail(
                    factor_name="Exploitation Likelihood",
                    factor_value=likelihood.value,
                    scale="LOW..HIGH",
                    evidence_state=finding.evidence_state.value,
                    source="DeterministicRiskMatrix",
                    source_time=now_iso,
                    contributes_to_aggregate=contributes,
                    aggregation_role=agg_role,
                    rationale=f"Mapped from {finding.severity.value} severity and {finding.evidence_state.value} evidence.",
                ),
                RiskFactorDetail(
                    factor_name="Technical Impact",
                    factor_value=impact.value,
                    scale="LOW..HIGH",
                    evidence_state=finding.evidence_state.value,
                    source="DeterministicRiskMatrix",
                    source_time=now_iso,
                    contributes_to_aggregate=contributes,
                    aggregation_role=agg_role,
                    rationale=f"Estimated technical impact under policy {self.policy.policy_id}.",
                ),
                RiskFactorDetail(
                    factor_name="Asset Criticality",
                    factor_value="NOT_ASSESSED",
                    scale="LOW..CRITICAL",
                    evidence_state="NOT_ASSESSED",
                    source="ENVIRONMENT_INVENTORY",
                    source_time=now_iso,
                    contributes_to_aggregate=False,
                    aggregation_role="UNASSESSED_EXPLICIT_GAP",
                    rationale="Asset criticality not configured; explicit unassessed gap.",
                ),
                RiskFactorDetail(
                    factor_name="External Exposure",
                    factor_value="OBSERVED_WAN" if finding.affected_entity_type in ("CHILD_SA", "IKE_SA", "IKE_SESSION") else "NOT_ASSESSED",
                    scale="INTERNAL..INTERNET_FACING",
                    evidence_state=finding.evidence_state.value,
                    source="SessionReconstruction",
                    source_time=now_iso,
                    contributes_to_aggregate=False,
                    aggregation_role="CONTEXT_ONLY",
                    rationale="Exposure derived from network observation context.",
                ),
                RiskFactorDetail(
                    factor_name="Vulnerability Applicability",
                    factor_value="NOT_ASSESSED",
                    scale="UNKNOWN..CONFIRMED",
                    evidence_state="NOT_ASSESSED",
                    source="VULNERABILITY_CORRELATION",
                    source_time=now_iso,
                    contributes_to_aggregate=False,
                    aggregation_role="UNASSESSED_EXPLICIT_GAP",
                    rationale="External CVE applicability unassessed for this protocol finding.",
                ),
                RiskFactorDetail(
                    factor_name="Compensating Controls",
                    factor_value="NOT_ASSESSED",
                    scale="NONE..VERIFIED",
                    evidence_state="NOT_ASSESSED",
                    source="CONTROLS_INVENTORY",
                    source_time=now_iso,
                    contributes_to_aggregate=False,
                    aggregation_role="UNASSESSED_EXPLICIT_GAP",
                    rationale="No compensating controls attested for this entity.",
                ),
            ]

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
                    factors=factors,
                    contributes_to_aggregate=contributes,
                    aggregation_role=agg_role,
                    root_cause_key=finding.root_cause_key,
                    policy_version=self.policy.policy_version,
                    policy_hash=self.policy.policy_hash,
                    methodology_type=self.policy.methodology_type,
                )
            )

        # 3. Aggregate overall risk tier strictly from contributing items
        contributing_items = [it for it in risk_items if it.contributes_to_aggregate]
        if not contributing_items:
            contributing_items = risk_items

        if any(item.risk_tier == RiskTier.CRITICAL for item in contributing_items):
            overall = RiskTier.CRITICAL
        elif any(item.risk_tier == RiskTier.HIGH for item in contributing_items):
            overall = RiskTier.HIGH
        elif any(item.risk_tier == RiskTier.MEDIUM for item in contributing_items):
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
            evidence_coverage=evidence_coverage,
            evidence_gaps_count=evidence_gaps_count,
            methodology_type=self.policy.methodology_type,
            disclaimer=self.policy.disclaimer,
        )

    def _map_factors(self, finding: SecurityFinding) -> tuple[Likelihood, Impact, RiskTier]:
        """Deterministic mapping matrix bound to RiskPolicy."""
        sev_name = finding.severity.value
        ev_subkey = "VERIFIED" if finding.evidence_state == EvidenceState.VERIFIED else "UNVERIFIED"

        mapping = self.policy.severity_mapping.get(sev_name)
        if mapping and ev_subkey in mapping:
            lh_str, imp_str, tier_str = mapping[ev_subkey]
            return Likelihood(lh_str), Impact(imp_str), RiskTier(tier_str)

        # Fallback to defaults if custom rule key is unknown
        sev = finding.severity
        ev = finding.evidence_state
        if sev == Severity.CRITICAL:
            tier = RiskTier.CRITICAL if ev == EvidenceState.VERIFIED else RiskTier.HIGH
            return Likelihood.HIGH, Impact.HIGH, tier
        if sev == Severity.HIGH:
            if ev == EvidenceState.VERIFIED:
                return Likelihood.MEDIUM, Impact.HIGH, RiskTier.HIGH
            return Likelihood.LOW, Impact.MEDIUM, RiskTier.MEDIUM
        if sev == Severity.MEDIUM:
            return Likelihood.LOW, Impact.LOW, RiskTier.MEDIUM

        return Likelihood.LOW, Impact.LOW, RiskTier.LOW
