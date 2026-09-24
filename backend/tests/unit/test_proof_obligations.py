"""Unit tests for Formal Verification Proof Obligations and Comparator Guards."""

from __future__ import annotations

import pytest

from app.remediation.comparator import VerificationComparator
from app.remediation.proof import ProofOutcome, ProofReasonCode, VerificationProofObligation
from app.security.findings.models import SecurityFinding
from app.security.policy.schema import FindingCategory, Severity


def test_proof_obligation_evaluation_matrix():
    """Verify formal proof obligations evaluate strictly against empirical post-remediation evidence."""
    obl = VerificationProofObligation(
        obligation_id="obl-dh-1",
        target_finding_id="find-dh-1",
        target_rule_id="POL-NIST-004",
        target_rule_version="1.0.0",
        root_cause_key="DH_GROUP_WEAK_LOGJAM",
        baseline_observed_fact_key="ike_sa.diffie_hellman_group",
        baseline_observed_value=2,
        proposed_expected_value=19,
        assertion_operator="in_set",
        resolution_criteria="Post-remediation capture shows DH group >= 14.",
        non_resolution_criteria="Post-remediation capture shows DH group < 14.",
        insufficient_evidence_criteria="Post-remediation capture lacks DH exchange.",
    )

    # 1. Post-remediation evidence proves rule PASS
    outcome, reason, _ = obl.evaluate_post_evidence(
        post_compliance_state="PASS",
        post_observed_fact_value=19,
        post_evidence_state="VERIFIED",
    )
    assert outcome == ProofOutcome.RESOLVED
    assert reason == ProofReasonCode.RULE_NOW_PASS

    # 2. Post-remediation evidence shows rule FAIL (persisting weakness)
    outcome, reason, _ = obl.evaluate_post_evidence(
        post_compliance_state="FAIL",
        post_observed_fact_value=2,
        post_evidence_state="VERIFIED",
    )
    assert outcome == ProofOutcome.NOT_RESOLVED
    assert reason == ProofReasonCode.RULE_STILL_FAIL

    # 3. RULE 145 GUARD: FAIL -> UNKNOWN is NOT resolution!
    outcome, reason, _ = obl.evaluate_post_evidence(
        post_compliance_state="UNKNOWN",
        post_observed_fact_value=None,
        post_evidence_state="UNKNOWN",
    )
    assert outcome == ProofOutcome.UNKNOWN
    assert reason == ProofReasonCode.RULE_NOW_UNKNOWN

    # 4. RULE 146 GUARD: FAIL -> NOT_APPLICABLE with verified applicability change
    outcome, reason, _ = obl.evaluate_post_evidence(
        post_compliance_state="NOT_APPLICABLE",
        post_observed_fact_value=None,
        post_evidence_state="VERIFIED",
    )
    assert outcome == ProofOutcome.RESOLVED
    assert reason == ProofReasonCode.RULE_BECAME_NOT_APPLICABLE_VALIDLY

    # 5. Analysis execution failure
    outcome, reason, _ = obl.evaluate_post_evidence(
        post_compliance_state="PASS",
        post_observed_fact_value=19,
        post_evidence_state="VERIFIED",
        analysis_succeeded=False,
    )
    assert outcome == ProofOutcome.VERIFICATION_FAILED
    assert reason == ProofReasonCode.EXECUTION_ERROR


def test_score_guard_score_increase_is_not_proof():
    """Verify that score increase while targeted finding persists does NOT result in VERIFIED_RESOLVED."""
    obl = VerificationProofObligation(
        obligation_id="obl-3des-1",
        target_finding_id="find-3des-1",
        target_rule_id="POL-NIST-001",
        target_rule_version="1.0.0",
        root_cause_key="CIPHER_DEPRECATED_DES",
        baseline_observed_fact_key="ike_sa.encryption_algorithm",
        baseline_observed_value="3DES",
        proposed_expected_value="AES256-GCM",
        assertion_operator="not_in_set",
        resolution_criteria="3DES absent in post capture",
        non_resolution_criteria="3DES persists in post capture",
        insufficient_evidence_criteria="Post capture lacks cipher facts",
    )

    baseline_finding = SecurityFinding.create(
        finding_id="find-3des-1",
        analysis_id="an-1",
        rule_id="POL-NIST-001",
        rule_version="1.0.0",
        profile_id="profile_nist_sp800_77",
        category=FindingCategory.CRYPTOGRAPHY,
        severity=Severity.CRITICAL,
        title="3DES Prohibition",
        technical_description="3DES used",
        root_cause_key="CIPHER_DEPRECATED_DES",
        affected_entity_type="IKE_SA",
        affected_entity_id="sa-1",
        observed_value="3DES",
        expected_requirement="AES-GCM",
    )

    # Post analysis still contains the finding!
    post_finding = baseline_finding

    post_facts = {
        "ike_sa.encryption_algorithm": {
            "value": "3DES",
            "evidence_state": "VERIFIED",
        }
    }

    comp = VerificationComparator.compare(
        proof_obligations=[obl],
        baseline_findings=[baseline_finding],
        post_findings=[post_finding],
        post_facts=post_facts,
        operational_healthy=True,
    )

    # Target finding persisted -> MUST be NOT_RESOLVED regardless of hypothetical score
    assert comp.overall_verification_result == ProofOutcome.NOT_RESOLVED
    assert comp.security_result == "NOT_RESOLVED"
    assert comp.unresolved_count == 1
    assert comp.resolved_count == 0


def test_regression_guard_blocks_clean_success():
    """Verify that a newly introduced critical security regression blocks clean hardening claim."""
    obl = VerificationProofObligation(
        obligation_id="obl-des-1",
        target_finding_id="find-des-1",
        target_rule_id="POL-NIST-001",
        target_rule_version="1.0.0",
        root_cause_key="CIPHER_DEPRECATED_DES",
        baseline_observed_fact_key="ike_sa.encryption_algorithm",
        baseline_observed_value="3DES",
        proposed_expected_value="AES256-GCM",
        assertion_operator="not_in_set",
        resolution_criteria="3DES absent",
        non_resolution_criteria="3DES persists",
        insufficient_evidence_criteria="Cipher fact unobserved",
    )

    baseline_finding = SecurityFinding.create(
        finding_id="find-des-1",
        analysis_id="an-1",
        rule_id="POL-NIST-001",
        rule_version="1.0.0",
        profile_id="profile_nist_sp800_77",
        category=FindingCategory.CRYPTOGRAPHY,
        severity=Severity.CRITICAL,
        title="3DES Prohibition",
        technical_description="3DES used",
        root_cause_key="CIPHER_DEPRECATED_DES",
        affected_entity_type="IKE_SA",
        affected_entity_id="sa-1",
        observed_value="3DES",
        expected_requirement="AES-GCM",
    )

    # Targeted 3DES resolved, BUT a new critical NULL encryption regression appeared!
    regression_finding = SecurityFinding.create(
        finding_id="find-reg-null",
        analysis_id="an-2",
        rule_id="POL-RFC-8221-01",
        rule_version="1.0.0",
        profile_id="profile_nist_sp800_77",
        category=FindingCategory.CIPHER_SUITE,
        severity=Severity.CRITICAL,
        title="NULL Encryption Prohibition",
        technical_description="Cleartext NULL ESP encryption observed",
        root_cause_key="CIPHER_NULL_CLEARTEXT",
        affected_entity_type="CHILD_SA",
        affected_entity_id="csa-1",
        observed_value="NULL",
        expected_requirement="AES-GCM",
    )

    post_facts = {
        "ike_sa.encryption_algorithm": {
            "value": "AES256-GCM",
            "evidence_state": "VERIFIED",
        }
    }

    comp = VerificationComparator.compare(
        proof_obligations=[obl],
        baseline_findings=[baseline_finding],
        post_findings=[regression_finding],
        post_facts=post_facts,
        operational_healthy=True,
    )

    # Even though target resolved, regression guard blocks clean success!
    assert comp.has_security_regression is True
    assert comp.security_result == "REGRESSION_DETECTED"
    assert comp.overall_verification_result == ProofOutcome.NOT_RESOLVED
    assert len(comp.new_regressions) == 1
    assert comp.new_regressions[0]["rule_id"] == "POL-RFC-8221-01"
