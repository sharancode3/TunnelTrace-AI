"""Unit tests for SafePolicyLoader, PolicyEvaluator, and rule lifecycle."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.security.facts.models import DerivationType, EvidenceState, SecurityFact, SubjectType
from app.security.policy.evaluator import ComplianceState, PolicyEvaluator
from app.security.policy.loader import SafePolicyLoader
from app.security.policy.registry import PolicyRegistry


class TestSafePolicyLoader:
    """Tests for safe declarative Policy YAML loading and validation."""

    def test_load_all_canonical_rules(self) -> None:
        rules_dir = Path(__file__).resolve().parent.parent.parent.parent / "policies" / "rules"
        assert rules_dir.exists(), f"Policies directory {rules_dir} must exist."

        loader = SafePolicyLoader(rules_dir)
        rules = loader.load_all_rules()
        assert len(rules) >= 8, f"Expected at least 8 canonical rules, got {len(rules)}."

        rule_ids = {r.rule_id for r in rules}
        assert "POL-NIST-001" in rule_ids
        assert "POL-NIST-002" in rule_ids
        assert "POL-NIST-003" in rule_ids
        assert "POL-NIST-004" in rule_ids
        assert "POL-RFC-7296-01" in rule_ids
        assert "POL-RFC-8221-01" in rule_ids
        assert "POL-PFS-001" in rule_ids
        assert "POL-REPLAY-001" in rule_ids

        # Every canonical rule must have valid authority references and active status
        for r in rules:
            assert r.status.value == "ACTIVE"
            assert r.authority_tier.value in ("NATIONAL_STANDARD", "IETF_STANDARD")
            assert len(r.authoritative_references) >= 1

    def test_bundle_compilation_and_hashing(self) -> None:
        rules_dir = Path(__file__).resolve().parent.parent.parent.parent / "policies" / "rules"
        loader = SafePolicyLoader(rules_dir)
        rules = loader.load_all_rules()

        registry = PolicyRegistry()
        bundle = registry.compile_bundle(
            bundle_id="bundle-nist-sp800-77",
            profile_id="profile_nist_sp800_77",
            rules=rules,
        )
        assert bundle.bundle_hash, "Bundle hash must be computed"
        assert len(bundle.bundle_hash) == 64  # SHA-256
        assert len(bundle.rules) == len(rules)


class TestPolicyEvaluator:
    """Tests for deterministic policy assertion and Kleene compliance evaluations."""

    @pytest.fixture
    def active_bundle(self):
        rules_dir = Path(__file__).resolve().parent.parent.parent.parent / "policies" / "rules"
        loader = SafePolicyLoader(rules_dir)
        rules = loader.load_all_rules()
        registry = PolicyRegistry()
        return registry.compile_bundle(
            bundle_id="bundle-nist-sp800-77",
            profile_id="profile_nist_sp800_77",
            rules=rules,
        )

    def test_positive_control_compliant_ike(self, active_bundle) -> None:
        """Compliant modern IKEv2 session with AES-256-GCM and DH Group 14 should PASS."""
        evaluator = PolicyEvaluator(active_bundle)
        facts = [
            SecurityFact(
                fact_id="fact-1",
                analysis_id="analysis-1",
                subject_type=SubjectType.IKE_SESSION,
                subject_id="sess-1",
                canonical_key="ike_session.ike_version",
                value="IKEv2",
                data_type="string",
                evidence_state=EvidenceState.VERIFIED,
                derivation_type=DerivationType.DIRECT,
            ),
            SecurityFact(
                fact_id="fact-2",
                analysis_id="analysis-1",
                subject_type=SubjectType.IKE_SA,
                subject_id="sa-1",
                canonical_key="ike_sa.encryption_algorithm",
                value="AES-256-GCM-16",
                data_type="string",
                evidence_state=EvidenceState.VERIFIED,
                derivation_type=DerivationType.DIRECT,
            ),
            SecurityFact(
                fact_id="fact-3",
                analysis_id="analysis-1",
                subject_type=SubjectType.IKE_SA,
                subject_id="sa-1",
                canonical_key="ike_sa.key_length_bits",
                value=256,
                data_type="integer",
                evidence_state=EvidenceState.VERIFIED,
                derivation_type=DerivationType.DIRECT,
            ),
            SecurityFact(
                fact_id="fact-4",
                analysis_id="analysis-1",
                subject_type=SubjectType.IKE_SA,
                subject_id="sa-1",
                canonical_key="ike_sa.diffie_hellman_group",
                value=14,
                data_type="integer",
                evidence_state=EvidenceState.VERIFIED,
                derivation_type=DerivationType.DIRECT,
            ),
        ]

        records = evaluator.evaluate_all("analysis-1", facts)
        rec_by_rule = {r.rule_id: r for r in records}

        # POL-RFC-7296-01 (IKEv2) should PASS
        assert rec_by_rule["POL-RFC-7296-01"].compliance_state == ComplianceState.PASS

        # POL-NIST-001 (No 3DES) should PASS
        assert rec_by_rule["POL-NIST-001"].compliance_state == ComplianceState.PASS

        # POL-NIST-002 (Key length >= 128) should PASS
        assert rec_by_rule["POL-NIST-002"].compliance_state == ComplianceState.PASS

        # POL-NIST-004 (DH Group >= 2048) should PASS
        assert rec_by_rule["POL-NIST-004"].compliance_state == ComplianceState.PASS

    def test_negative_control_weak_cipher_fails(self, active_bundle) -> None:
        """Deprecated 3DES cipher should trigger a clear FAIL finding."""
        evaluator = PolicyEvaluator(active_bundle)
        facts = [
            SecurityFact(
                fact_id="fact-3des",
                analysis_id="analysis-1",
                subject_type=SubjectType.IKE_SA,
                subject_id="sa-weak",
                canonical_key="ike_sa.encryption_algorithm",
                value="3DES-CBC",
                data_type="string",
                evidence_state=EvidenceState.VERIFIED,
                derivation_type=DerivationType.DIRECT,
            ),
            SecurityFact(
                fact_id="fact-len",
                analysis_id="analysis-1",
                subject_type=SubjectType.IKE_SA,
                subject_id="sa-weak",
                canonical_key="ike_sa.key_length_bits",
                value=64,
                data_type="integer",
                evidence_state=EvidenceState.VERIFIED,
                derivation_type=DerivationType.DIRECT,
            ),
        ]

        records = evaluator.evaluate_all("analysis-1", facts)
        rec_by_rule = {r.rule_id: r for r in records}

        # POL-NIST-001 should FAIL
        assert rec_by_rule["POL-NIST-001"].compliance_state == ComplianceState.FAIL
        assert "VIOLATED" in rec_by_rule["POL-NIST-001"].rationale

        # POL-NIST-002 should FAIL (key length < 128)
        assert rec_by_rule["POL-NIST-002"].compliance_state == ComplianceState.FAIL

    def test_pfs_unknown_honesty(self, active_bundle) -> None:
        """When PFS is UNKNOWN due to missing rekey KE exchange, rule evaluates to UNKNOWN, not FAIL."""
        evaluator = PolicyEvaluator(active_bundle)
        facts = [
            SecurityFact(
                fact_id="fact-child-pfs",
                analysis_id="analysis-1",
                subject_type=SubjectType.CHILD_SA,
                subject_id="child-1",
                canonical_key="child_sa.pfs_status",
                value="UNKNOWN",
                data_type="string",
                evidence_state=EvidenceState.UNKNOWN,
                derivation_type=DerivationType.INFERENCE,
            ),
        ]

        records = evaluator.evaluate_all("analysis-1", facts)
        pfs_record = next(r for r in records if r.rule_id == "POL-PFS-001")
        assert pfs_record.compliance_state == ComplianceState.UNKNOWN
        assert "UNKNOWN" in pfs_record.rationale
