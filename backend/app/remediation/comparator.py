"""Deterministic Finding & Rule Comparator for Closed-Loop Verification.

Compares baseline forensic evidence and findings against post-remediation evidence.
Evaluates formal VerificationProofObligations to determine verified resolution,
strictly preventing score heuristics or unobserved absences (FAIL -> UNKNOWN)
from generating false resolution claims.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from app.remediation.proof import ProofOutcome, ProofReasonCode, VerificationProofObligation
from app.security.findings.models import SecurityFinding

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class EvaluatedClaim:
    """Evaluated Verification Claim linking baseline finding to post evidence."""

    claim_id: str
    target_finding_id: str
    rule_id: str
    rule_version: str
    root_cause_key: str
    baseline_evidence: dict[str, Any]
    proposed_transformation: dict[str, Any]
    expected_condition: str
    post_finding_id: str | None
    post_evidence: dict[str, Any]
    claim_result: ProofOutcome
    reason_code: ProofReasonCode
    explanation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "claim_id": self.claim_id,
            "target_finding_id": self.target_finding_id,
            "rule_id": self.rule_id,
            "rule_version": self.rule_version,
            "root_cause_key": self.root_cause_key,
            "baseline_evidence": self.baseline_evidence,
            "proposed_transformation": self.proposed_transformation,
            "expected_condition": self.expected_condition,
            "post_finding_id": self.post_finding_id,
            "post_evidence": self.post_evidence,
            "claim_result": self.claim_result.value,
            "reason_code": self.reason_code.value,
            "explanation": self.explanation,
        }


@dataclass(frozen=True)
class VerificationComparisonResult:
    """Complete finding-level verification and regression analysis."""

    overall_verification_result: ProofOutcome
    security_result: str  # RESOLVED | NOT_RESOLVED | PARTIAL | UNKNOWN | FAILED
    operational_result: str  # HEALTHY | DEGRADED | FAILED
    claims: list[EvaluatedClaim]
    resolved_count: int
    unresolved_count: int
    unknown_count: int
    new_regressions: list[dict[str, Any]]
    has_security_regression: bool
    summary_explanation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "overall_verification_result": self.overall_verification_result.value,
            "security_result": self.security_result,
            "operational_result": self.operational_result,
            "claims": [c.to_dict() for c in self.claims],
            "resolved_count": self.resolved_count,
            "unresolved_count": self.unresolved_count,
            "unknown_count": self.unknown_count,
            "new_regressions": self.new_regressions,
            "has_security_regression": self.has_security_regression,
            "summary_explanation": self.summary_explanation,
        }


class VerificationComparator:
    """Compares baseline vs post-remediation analyses against formal proof obligations."""

    @classmethod
    def compare(
        cls,
        proof_obligations: list[VerificationProofObligation],
        baseline_findings: list[SecurityFinding],
        post_findings: list[SecurityFinding],
        post_facts: dict[str, Any],
        operational_healthy: bool = True,
        analysis_succeeded: bool = True,
    ) -> VerificationComparisonResult:
        """Deterministically evaluate each proof obligation and detect regressions."""
        post_findings_by_rule = {f.rule_id: f for f in post_findings}
        baseline_findings_by_id = {f.finding_id: f for f in baseline_findings}

        evaluated_claims: list[EvaluatedClaim] = []
        resolved_count = 0
        unresolved_count = 0
        unknown_count = 0

        for obl in proof_obligations:
            b_finding = baseline_findings_by_id.get(obl.target_finding_id)
            p_finding = post_findings_by_rule.get(obl.target_rule_id)

            # Fact value observed in post-analysis
            post_fact_entry = post_facts.get(obl.baseline_observed_fact_key, {})
            post_fact_val = post_fact_entry.get("value")
            post_ev_state = post_fact_entry.get("evidence_state", "UNKNOWN")

            # Determine post-compliance state
            if p_finding:
                post_comp_state = "FAIL"
            elif post_ev_state == "UNKNOWN" and post_fact_val is None:
                post_comp_state = "UNKNOWN"
            else:
                post_comp_state = "PASS"

            outcome, reason, explanation = obl.evaluate_post_evidence(
                post_compliance_state=post_comp_state,
                post_observed_fact_value=post_fact_val,
                post_evidence_state=post_ev_state,
                analysis_succeeded=analysis_succeeded,
            )

            if outcome == ProofOutcome.RESOLVED:
                resolved_count += 1
            elif outcome == ProofOutcome.NOT_RESOLVED:
                unresolved_count += 1
            elif outcome == ProofOutcome.UNKNOWN:
                unknown_count += 1

            claim = EvaluatedClaim(
                claim_id=f"claim-{obl.obligation_id}",
                target_finding_id=obl.target_finding_id,
                rule_id=obl.target_rule_id,
                rule_version=obl.target_rule_version,
                root_cause_key=obl.root_cause_key,
                baseline_evidence={
                    "observed_value": b_finding.observed_value if b_finding else obl.baseline_observed_value,
                    "evidence_state": b_finding.evidence_state.value if b_finding else "VERIFIED",
                },
                proposed_transformation={"expected_value": obl.proposed_expected_value},
                expected_condition=obl.resolution_criteria,
                post_finding_id=p_finding.finding_id if p_finding else None,
                post_evidence={
                    "observed_value": post_fact_val,
                    "evidence_state": post_ev_state,
                    "rule_passed": p_finding is None,
                },
                claim_result=outcome,
                reason_code=reason,
                explanation=explanation,
            )
            evaluated_claims.append(claim)

        # Regression Detection: findings in post that were NOT in baseline!
        baseline_rules = {f.rule_id for f in baseline_findings}
        new_regressions: list[dict[str, Any]] = []
        for pf in post_findings:
            if pf.rule_id not in baseline_rules:
                new_regressions.append(
                    {
                        "finding_id": pf.finding_id,
                        "rule_id": pf.rule_id,
                        "title": pf.title,
                        "severity": pf.severity.value,
                        "root_cause_key": pf.root_cause_key,
                        "description": pf.technical_description,
                    }
                )

        has_security_regression = any(r["severity"] in ("CRITICAL", "HIGH") for r in new_regressions)

        # Operational Result
        op_result = "HEALTHY" if operational_healthy else "FAILED"

        # Determine Overall Security Result
        if not analysis_succeeded or not operational_healthy:
            sec_result = "FAILED"
            overall = ProofOutcome.VERIFICATION_FAILED
        elif has_security_regression:
            sec_result = "REGRESSION_DETECTED"
            overall = ProofOutcome.NOT_RESOLVED
        elif resolved_count > 0 and unresolved_count == 0 and unknown_count == 0:
            sec_result = "RESOLVED"
            overall = ProofOutcome.RESOLVED
        elif resolved_count > 0 and (unresolved_count > 0 or unknown_count > 0):
            sec_result = "PARTIAL"
            overall = ProofOutcome.PARTIALLY_VERIFIED
        elif unresolved_count > 0:
            sec_result = "NOT_RESOLVED"
            overall = ProofOutcome.NOT_RESOLVED
        else:
            sec_result = "UNKNOWN"
            overall = ProofOutcome.UNKNOWN

        # Summary Explanation
        if overall == ProofOutcome.RESOLVED:
            summary = f"All {resolved_count} targeted findings successfully verified resolved against fresh post-remediation wire evidence."
        elif overall == ProofOutcome.PARTIALLY_VERIFIED:
            summary = f"Partial remediation verified: {resolved_count} resolved, {unresolved_count} unresolved, {unknown_count} unevidenced."
        elif has_security_regression:
            summary = f"Security regression detected! Proposed fix resolved target but introduced {len(new_regressions)} new policy violations."
        elif overall == ProofOutcome.NOT_RESOLVED:
            summary = f"Remediation unverified: {unresolved_count} targeted findings persist under fresh wire analysis."
        elif overall == ProofOutcome.UNKNOWN:
            summary = "Remediation outcome unverified: required post-remediation evidence was unobserved in capture window."
        else:
            summary = "Operational failure prevented complete verification."

        return VerificationComparisonResult(
            overall_verification_result=overall,
            security_result=sec_result,
            operational_result=op_result,
            claims=evaluated_claims,
            resolved_count=resolved_count,
            unresolved_count=unresolved_count,
            unknown_count=unknown_count,
            new_regressions=new_regressions,
            has_security_regression=has_security_regression,
            summary_explanation=summary,
        )
