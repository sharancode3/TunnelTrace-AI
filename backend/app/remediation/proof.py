"""Verification Proof Obligations for Evidence-Backed Closed-Loop Remediation.

Formulates explicit, deterministic proof criteria for every targeted security finding.
Guarantees that remediation resolution is judged purely against observable post-remediation
forensic evidence, explicitly rejecting score heuristics or unevidenced absences.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ProofOutcome(str, Enum):
    """Deterministic proof outcome resulting from evidence comparison."""

    RESOLVED = "VERIFIED_RESOLVED"
    NOT_RESOLVED = "VERIFIED_NOT_RESOLVED"
    PARTIALLY_VERIFIED = "PARTIALLY_VERIFIED"
    UNKNOWN = "UNKNOWN"
    VERIFICATION_FAILED = "VERIFICATION_FAILED"


class ProofReasonCode(str, Enum):
    """Categorical explanation of proof obligation evaluation."""

    RULE_NOW_PASS = "RULE_NOW_PASS"
    RULE_STILL_FAIL = "RULE_STILL_FAIL"
    RULE_NOW_UNKNOWN = "RULE_NOW_UNKNOWN"
    RULE_BECAME_NOT_APPLICABLE_VALIDLY = "RULE_BECAME_NOT_APPLICABLE_VALIDLY"
    POST_ENTITY_NOT_OBSERVED = "POST_ENTITY_NOT_OBSERVED"
    EVIDENCE_INSUFFICIENT = "EVIDENCE_INSUFFICIENT"
    NEW_REGRESSION = "NEW_REGRESSION"
    EXECUTION_ERROR = "EXECUTION_ERROR"


@dataclass(frozen=True)
class VerificationProofObligation:
    """Formal proof obligation binding a targeted finding to concrete verification criteria."""

    obligation_id: str
    target_finding_id: str
    target_rule_id: str
    target_rule_version: str
    root_cause_key: str
    baseline_observed_fact_key: str
    baseline_observed_value: Any
    proposed_expected_value: Any
    assertion_operator: str  # in_set | not_in_set | equals | greater_or_equal

    # Proof criteria descriptions
    resolution_criteria: str
    non_resolution_criteria: str
    insufficient_evidence_criteria: str

    def evaluate_post_evidence(
        self,
        post_compliance_state: str,  # PASS | FAIL | UNKNOWN | NOT_APPLICABLE
        post_observed_fact_value: Any,
        post_evidence_state: str,  # VERIFIED | INFERRED | UNKNOWN
        analysis_succeeded: bool = True,
    ) -> tuple[ProofOutcome, ProofReasonCode, str]:
        """Deterministically evaluate if fresh post-remediation evidence satisfies the obligation."""
        if not analysis_succeeded:
            return (
                ProofOutcome.VERIFICATION_FAILED,
                ProofReasonCode.EXECUTION_ERROR,
                "Post-remediation analysis did not complete successfully.",
            )

        # Rule 145: FAIL -> UNKNOWN is NOT resolution!
        if post_evidence_state == "UNKNOWN" or post_compliance_state == "UNKNOWN":
            return (
                ProofOutcome.UNKNOWN,
                ProofReasonCode.RULE_NOW_UNKNOWN,
                f"Required post-remediation evidence for rule '{self.target_rule_id}' was unobserved in fresh capture (epistemic state: UNKNOWN).",
            )

        # Rule 146: FAIL -> NOT_APPLICABLE requires evidence that applicability changed validly
        if post_compliance_state == "NOT_APPLICABLE":
            return (
                ProofOutcome.RESOLVED,
                ProofReasonCode.RULE_BECAME_NOT_APPLICABLE_VALIDLY,
                f"Rule '{self.target_rule_id}' is no longer applicable under the validated hardened profile.",
            )

        # Still failing?
        if post_compliance_state == "FAIL":
            return (
                ProofOutcome.NOT_RESOLVED,
                ProofReasonCode.RULE_STILL_FAIL,
                f"Post-remediation capture observed fact value '{post_observed_fact_value}', which still violates rule '{self.target_rule_id}'.",
            )

        # Passed!
        if post_compliance_state == "PASS":
            return (
                ProofOutcome.RESOLVED,
                ProofReasonCode.RULE_NOW_PASS,
                f"Post-remediation capture verified fact value '{post_observed_fact_value}' satisfies rule '{self.target_rule_id}'. Old failing condition is absent.",
            )

        return (
            ProofOutcome.UNKNOWN,
            ProofReasonCode.EVIDENCE_INSUFFICIENT,
            f"Ambiguous post-remediation state '{post_compliance_state}' for rule '{self.target_rule_id}'.",
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "obligation_id": self.obligation_id,
            "target_finding_id": self.target_finding_id,
            "target_rule_id": self.target_rule_id,
            "target_rule_version": self.target_rule_version,
            "root_cause_key": self.root_cause_key,
            "baseline_observed_fact_key": self.baseline_observed_fact_key,
            "baseline_observed_value": self.baseline_observed_value,
            "proposed_expected_value": self.proposed_expected_value,
            "assertion_operator": self.assertion_operator,
            "resolution_criteria": self.resolution_criteria,
            "non_resolution_criteria": self.non_resolution_criteria,
            "insufficient_evidence_criteria": self.insufficient_evidence_criteria,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> VerificationProofObligation:
        return cls(
            obligation_id=data["obligation_id"],
            target_finding_id=data["target_finding_id"],
            target_rule_id=data["target_rule_id"],
            target_rule_version=data["target_rule_version"],
            root_cause_key=data["root_cause_key"],
            baseline_observed_fact_key=data["baseline_observed_fact_key"],
            baseline_observed_value=data["baseline_observed_value"],
            proposed_expected_value=data["proposed_expected_value"],
            assertion_operator=data["assertion_operator"],
            resolution_criteria=data["resolution_criteria"],
            non_resolution_criteria=data["non_resolution_criteria"],
            insufficient_evidence_criteria=data["insufficient_evidence_criteria"],
        )
