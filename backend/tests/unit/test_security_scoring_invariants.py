"""Unit tests verifying mathematical invariants of the Security Scoring Engine."""

from __future__ import annotations

import pytest

from app.security.findings.models import (
    FindingCategory,
    FindingSeverity,
    SecurityFinding,
)
from app.security.policy.evaluator import ComplianceState, EvaluationRecord
from app.security.scoring.engine import SecurityScoringEngine


class TestSecurityScoringInvariants:
    """Rigorous tests for scoring monotonicity, range bounds, and deduction audit."""

    @pytest.fixture
    def scoring_engine(self):
        return SecurityScoringEngine()

    def test_clean_session_perfect_score(self, scoring_engine) -> None:
        """With zero violations and all PASS evaluations, score must be 100.0."""
        evals = [
            EvaluationRecord(
                rule_id="POL-1",
                rule_version="v1.0.0",
                profile_id="prof-1",
                subject_type="IKE_SA",
                subject_id="sa-1",
                compliance_state=ComplianceState.PASS,
                evidence_state="VERIFIED",
                rationale="Pass",
            ),
            EvaluationRecord(
                rule_id="POL-2",
                rule_version="v1.0.0",
                profile_id="prof-1",
                subject_type="CHILD_SA",
                subject_id="child-1",
                compliance_state=ComplianceState.PASS,
                evidence_state="VERIFIED",
                rationale="Pass",
            ),
        ]
        res = scoring_engine.calculate_score("analysis-1", findings=[], eval_records=evals)
        assert res.overall_score == 100.0
        assert res.evidence_coverage.coverage_percentage == 100.0
        assert len(res.deduction_audit) == 0

    def test_unknown_causes_zero_deduction(self, scoring_engine) -> None:
        """UNKNOWN compliance results must NEVER penalize the security score."""
        evals = [
            EvaluationRecord(
                rule_id="POL-PFS-001",
                rule_version="v1.0.0",
                profile_id="prof-1",
                subject_type="CHILD_SA",
                subject_id="child-1",
                compliance_state=ComplianceState.UNKNOWN,
                evidence_state="UNKNOWN",
                rationale="Missing rekey exchange",
            )
        ]
        res = scoring_engine.calculate_score("analysis-1", findings=[], eval_records=evals)
        assert res.overall_score == 100.0, "UNKNOWN must not cause a score deduction"
        assert res.evidence_coverage.unknown_rules == 1
        assert res.evidence_coverage.coverage_percentage == 0.0

    def test_root_cause_deduplication(self, scoring_engine) -> None:
        """Two findings sharing the same root_cause_key must deduct only once."""
        f1 = SecurityFinding.create(
            finding_id="FND-1",
            analysis_id="analysis-1",
            rule_id="POL-NIST-001",
            rule_version="v1.0.0",
            profile_id="prof-1",
            category=FindingCategory.CRYPTOGRAPHY,
            severity=FindingSeverity.HIGH,  # -15
            title="3DES Cipher Disallowed",
            technical_description="3DES is deprecated",
            root_cause_key="RC_CIPHER_3DES",
            affected_entity_type="IKE_SA",
            affected_entity_id="sa-1",
            observed_value="3DES",
            expected_requirement="AES-GCM",
            evidence_node_links=["fact-1"],
        )
        f2 = SecurityFinding.create(
            finding_id="FND-2",
            analysis_id="analysis-1",
            rule_id="POL-NIST-002",
            rule_version="v1.0.0",
            profile_id="prof-1",
            category=FindingCategory.CRYPTOGRAPHY,
            severity=FindingSeverity.MEDIUM,  # -8
            title="Key Length Sub-128",
            technical_description="Key length 64 bits",
            root_cause_key="RC_CIPHER_3DES",  # Same root cause!
            affected_entity_type="IKE_SA",
            affected_entity_id="sa-1",
            observed_value=64,
            expected_requirement=128,
            evidence_node_links=["fact-2"],
        )

        res = scoring_engine.calculate_score("analysis-1", findings=[f1, f2], eval_records=[])
        # Base = 100. Primary HIGH (-15) applied. Secondary MEDIUM (-8) deduplicated (0 applied).
        assert res.overall_score == 85.0
        assert len(res.deduction_audit) == 2
        applied_deductions = [d.applied_deduction for d in res.deduction_audit]
        assert 15.0 in applied_deductions
        assert 0.0 in applied_deductions

    def test_score_monotonicity(self, scoring_engine) -> None:
        """Adding a new violation cannot increase score; removing one cannot decrease score."""
        f_crit = SecurityFinding.create(
            finding_id="FND-CRIT",
            analysis_id="analysis-1",
            rule_id="POL-NULL-CIPHER",
            rule_version="v1.0.0",
            profile_id="prof-1",
            category=FindingCategory.CRYPTOGRAPHY,
            severity=FindingSeverity.CRITICAL,
            title="Null cipher",
            technical_description="Cleartext",
            root_cause_key="RC_NULL",
            affected_entity_type="CHILD_SA",
            affected_entity_id="child-1",
            observed_value="NULL",
            expected_requirement="AES-GCM",
            evidence_node_links=["fact-null"],
        )
        f_high = SecurityFinding.create(
            finding_id="FND-HIGH",
            analysis_id="analysis-1",
            rule_id="POL-NIST-004",
            rule_version="v1.0.0",
            profile_id="prof-1",
            category=FindingCategory.KEY_EXCHANGE,
            severity=FindingSeverity.HIGH,
            title="DH Group 2",
            technical_description="DH 1024",
            root_cause_key="RC_DH_WEAK",
            affected_entity_type="IKE_SA",
            affected_entity_id="sa-1",
            observed_value="MODP_1024",
            expected_requirement="MODP_2048",
            evidence_node_links=["fact-dh"],
        )

        score_empty = scoring_engine.calculate_score("analysis-1", [], []).overall_score
        score_one = scoring_engine.calculate_score("analysis-1", [f_high], []).overall_score
        score_two = scoring_engine.calculate_score("analysis-1", [f_high, f_crit], []).overall_score

        assert score_empty >= score_one >= score_two
        assert score_two >= 0.0
