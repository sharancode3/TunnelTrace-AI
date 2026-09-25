"""Unit tests for Evidence-Based Risk and Policy Engine (Stage 16).

Verifies:
1. Canonical RiskPolicy methodology binding and hash sensitivity.
2. Honest handling of zero findings and insufficient evidence states.
3. Transparent factor breakdown per risk item with inspectable roles.
4. Root-cause deduplication semantics for aggregate risk computation.
5. Canonical Threat Catalog hash digest and verified MITRE ATT&CK mappings.
6. Offline Threat Intelligence (CISA KEV & FIRST EPSS) context and freshness.
7. Epistemic boundaries: external context never mutates deterministic policy scores.
"""

from __future__ import annotations

import copy
import pytest

from app.security.facts.models import EvidenceState
from app.security.findings.models import FindingCategory, FindingSeverity, SecurityFinding
from app.security.policy.schema import Severity
from app.security.risk.engine import DeterministicRiskEngine
from app.security.risk.models import (
    DEFAULT_SEVERITY_MAPPING,
    Impact,
    Likelihood,
    RiskItem,
    RiskPolicy,
    RiskTier,
)
from app.security.threat_intel.schemas import FeedStatus
from app.security.threat_intel.service import ThreatIntelService
from app.security.threats.catalog import (
    THREAT_CATALOG,
    THREAT_CATALOG_CANONICAL_HASH,
    compute_catalog_hash,
    get_threat_by_id,
)
from app.security.threats.mapper import ThreatMatrixEngine


class TestRiskPolicyCanonicalBinding:
    """Verifies that RiskPolicy.compute_hash() binds the complete methodology."""

    def test_identical_policies_yield_identical_hashes(self) -> None:
        p1 = RiskPolicy()
        p2 = RiskPolicy()
        assert p1.compute_hash() == p2.compute_hash()
        assert len(p1.compute_hash()) == 64

    def test_hash_sensitivity_to_threshold_change(self) -> None:
        p_base = RiskPolicy(insufficient_evidence_threshold=50.0)
        p_altered = RiskPolicy(insufficient_evidence_threshold=75.0)
        assert p_base.compute_hash() != p_altered.compute_hash()

    def test_hash_sensitivity_to_empty_findings_rule(self) -> None:
        p_base = RiskPolicy(empty_findings_behavior="NO_FINDINGS_UNDER_THIS_POLICY")
        p_altered = RiskPolicy(empty_findings_behavior="ASSUME_UNKNOWN")
        assert p_base.compute_hash() != p_altered.compute_hash()

    def test_hash_sensitivity_to_root_cause_deduplication(self) -> None:
        p_base = RiskPolicy(root_cause_deduplication=True)
        p_altered = RiskPolicy(root_cause_deduplication=False)
        assert p_base.compute_hash() != p_altered.compute_hash()

    def test_hash_sensitivity_to_severity_mapping_matrix(self) -> None:
        p_base = RiskPolicy()
        altered_mapping = copy.deepcopy(DEFAULT_SEVERITY_MAPPING)
        altered_mapping["HIGH"]["VERIFIED"] = ("HIGH", "HIGH", "CRITICAL")
        p_altered = RiskPolicy(severity_mapping=altered_mapping)
        assert p_base.compute_hash() != p_altered.compute_hash()

    def test_hash_sensitivity_to_policy_version_and_id(self) -> None:
        p_base = RiskPolicy(policy_version="1.0.0")
        p_altered = RiskPolicy(policy_version="1.1.0")
        assert p_base.compute_hash() != p_altered.compute_hash()


class TestDeterministicRiskEngineTruthfulness:
    """Verifies honest empty findings, factor breakdowns, and deduplication."""

    @pytest.fixture
    def engine(self) -> DeterministicRiskEngine:
        return DeterministicRiskEngine()

    def test_empty_findings_with_low_coverage_yields_insufficient_evidence(
        self, engine: DeterministicRiskEngine
    ) -> None:
        """When evidence coverage is below 50%, zero findings must NEVER be called LOW risk."""
        assessment = engine.evaluate_risk(
            analysis_id="analysis-empty-1",
            findings=[],
            evidence_coverage=25.0,
            evidence_gaps_count=6,
        )
        assert assessment.overall_risk_tier == RiskTier.INSUFFICIENT_EVIDENCE
        assert assessment.evidence_coverage == 25.0
        assert assessment.evidence_gaps_count == 6
        assert len(assessment.risk_items) == 0

    def test_empty_findings_with_none_coverage_yields_insufficient_evidence(
        self, engine: DeterministicRiskEngine
    ) -> None:
        assessment = engine.evaluate_risk(
            analysis_id="analysis-empty-none",
            findings=[],
            evidence_coverage=None,
        )
        assert assessment.overall_risk_tier == RiskTier.INSUFFICIENT_EVIDENCE

    def test_empty_findings_with_adequate_coverage_yields_no_findings_tier(
        self, engine: DeterministicRiskEngine
    ) -> None:
        """High evidence coverage with zero findings yields NO_FINDINGS_UNDER_THIS_POLICY."""
        assessment = engine.evaluate_risk(
            analysis_id="analysis-empty-good",
            findings=[],
            evidence_coverage=92.5,
            evidence_gaps_count=0,
        )
        assert assessment.overall_risk_tier == RiskTier.NO_FINDINGS_UNDER_THIS_POLICY
        assert assessment.evidence_coverage == 92.5
        assert len(assessment.risk_items) == 0

    def test_valid_low_finding_preserves_genuine_low_risk(
        self, engine: DeterministicRiskEngine
    ) -> None:
        """When findings exist and resolve to LOW, valid LOW tier is preserved."""
        f_low = SecurityFinding.create(
            finding_id="FND-LOW-1",
            analysis_id="analysis-low",
            rule_id="POL-INFO-001",
            rule_version="1.0.0",
            profile_id="profile_nist_sp800_77",
            category=FindingCategory.SA_MANAGEMENT,
            severity=FindingSeverity.LOW,
            title="Non-optimal rekey lifetime",
            technical_description="Soft lifetime setting slightly below normative guidance",
            root_cause_key="RC_REKEY_SOFT_LIFETIME",
            affected_entity_type="IKE_SA",
            affected_entity_id="sa-low-1",
            observed_value="1800s",
            expected_requirement="3600s",
            evidence_state=EvidenceState.VERIFIED,
        )

        assessment = engine.evaluate_risk(
            analysis_id="analysis-low",
            findings=[f_low],
            evidence_coverage=90.0,
        )
        assert assessment.overall_risk_tier == RiskTier.LOW
        assert len(assessment.risk_items) == 1
        assert assessment.risk_items[0].risk_tier == RiskTier.LOW

    def test_itemized_transparent_factor_breakdown(
        self, engine: DeterministicRiskEngine
    ) -> None:
        f_null = SecurityFinding.create(
            finding_id="FND-NULL-1",
            analysis_id="analysis-factors",
            rule_id="POL-RFC-8221-01",
            rule_version="1.0.0",
            profile_id="profile_nist_sp800_77",
            category=FindingCategory.CIPHER_SUITE,
            severity=FindingSeverity.CRITICAL,
            title="NULL Encryption in Child SA",
            technical_description="Cleartext ESP traffic observed",
            root_cause_key="RC_ESP_NULL_CIPHER",
            affected_entity_type="CHILD_SA",
            affected_entity_id="child-1",
            observed_value="NULL",
            expected_requirement="AES-GCM",
            evidence_state=EvidenceState.VERIFIED,
        )

        assessment = engine.evaluate_risk(
            analysis_id="analysis-factors",
            findings=[f_null],
            evidence_coverage=88.0,
        )
        assert assessment.overall_risk_tier == RiskTier.CRITICAL
        assert len(assessment.risk_items) == 1

        item = assessment.risk_items[0]
        assert item.contributes_to_aggregate is True
        assert item.aggregation_role == "PRIMARY_DRIVER"
        assert item.policy_hash == engine.policy.policy_hash
        assert item.methodology_type == "DETERMINISTIC_PRIORITIZATION_HEURISTIC"

        # Check factor breakdown completeness
        factor_names = [f.factor_name for f in item.factors]
        assert "Policy Severity" in factor_names
        assert "Evidence Strength" in factor_names
        assert "Exploitation Likelihood" in factor_names
        assert "Technical Impact" in factor_names
        assert "Asset Criticality" in factor_names
        assert "External Exposure" in factor_names
        assert "Vulnerability Applicability" in factor_names
        assert "Compensating Controls" in factor_names

        # Unassessed environmental factors must be explicitly marked NOT_ASSESSED, never 0 or low
        crit_factor = next(f for f in item.factors if f.factor_name == "Asset Criticality")
        assert crit_factor.factor_value == "NOT_ASSESSED"
        assert crit_factor.aggregation_role == "UNASSESSED_EXPLICIT_GAP"

    def test_root_cause_deduplication_aggregates(
        self, engine: DeterministicRiskEngine
    ) -> None:
        """Multiple findings sharing the same root cause must deduplicate for aggregation."""
        f1 = SecurityFinding.create(
            finding_id="FND-DUP-1",
            analysis_id="analysis-dedup",
            rule_id="POL-NIST-001",
            rule_version="1.0.0",
            profile_id="profile_nist_sp800_77",
            category=FindingCategory.CRYPTOGRAPHY,
            severity=FindingSeverity.HIGH,
            title="3DES in proposal A",
            technical_description="3DES negotiated",
            root_cause_key="RC_CIPHER_3DES",
            affected_entity_type="IKE_SA",
            affected_entity_id="sa-1",
            observed_value="3DES",
            expected_requirement="AES-GCM",
            evidence_state=EvidenceState.VERIFIED,
        )
        f2 = SecurityFinding.create(
            finding_id="FND-DUP-2",
            analysis_id="analysis-dedup",
            rule_id="POL-NIST-001",
            rule_version="1.0.0",
            profile_id="profile_nist_sp800_77",
            category=FindingCategory.CRYPTOGRAPHY,
            severity=FindingSeverity.HIGH,
            title="3DES in proposal B",
            technical_description="3DES negotiated duplicate",
            root_cause_key="RC_CIPHER_3DES",
            affected_entity_type="IKE_SA",
            affected_entity_id="sa-2",
            observed_value="3DES",
            expected_requirement="AES-GCM",
            evidence_state=EvidenceState.VERIFIED,
        )

        assessment = engine.evaluate_risk(
            analysis_id="analysis-dedup",
            findings=[f1, f2],
            evidence_coverage=80.0,
        )
        assert len(assessment.risk_items) == 2
        first_item = assessment.risk_items[0]
        second_item = assessment.risk_items[1]

        assert first_item.contributes_to_aggregate is True
        assert first_item.aggregation_role == "PRIMARY_DRIVER"

        assert second_item.contributes_to_aggregate is False
        assert second_item.aggregation_role == "DEDUPLICATED_BY_ROOT_CAUSE"


class TestThreatCatalogAndMitreAttack:
    """Verifies pre-authored threat catalog integrity and selective ATT&CK mappings."""

    def test_catalog_hash_is_canonical_and_tamper_evident(self) -> None:
        computed = compute_catalog_hash()
        assert computed == THREAT_CATALOG_CANONICAL_HASH
        assert len(computed) == 64

        engine = ThreatMatrixEngine()
        assert engine.catalog_hash == computed
        assert engine.catalog_hash != "threat_catalog_hash_canonical_v1"

    def test_authoritative_mitre_attack_mappings(self) -> None:
        # THR-003: IKEv1 Aggressive Mode PSK cracking -> T1110.002
        thr3 = get_threat_by_id("THR-003")
        assert thr3 is not None
        assert thr3.mitre_attack is not None
        assert thr3.mitre_attack.technique_id == "T1110.002"
        assert thr3.mitre_attack.technique_name == "Password Cracking"
        assert "attack.mitre.org/techniques/T1110/002" in thr3.mitre_attack.source_url

        # THR-005: Non-AEAD bit flipping -> T1565.002
        thr5 = get_threat_by_id("THR-005")
        assert thr5 is not None
        assert thr5.mitre_attack is not None
        assert thr5.mitre_attack.technique_id == "T1565.002"
        assert thr5.mitre_attack.technique_name == "Transmitted Data Manipulation"
        assert "attack.mitre.org/techniques/T1565/002" in thr5.mitre_attack.source_url

        # THR-008: ESP NULL cleartext -> T1040
        thr8 = get_threat_by_id("THR-008")
        assert thr8 is not None
        assert thr8.mitre_attack is not None
        assert thr8.mitre_attack.technique_id == "T1040"
        assert thr8.mitre_attack.technique_name == "Network Sniffing"
        assert "attack.mitre.org/techniques/T1040" in thr8.mitre_attack.source_url

    def test_intentionally_unmapped_catalog_entries(self) -> None:
        """Cryptanalytic and design limits must remain strictly unmapped without placeholder IDs."""
        unmapped_ids = ["THR-001", "THR-002", "THR-004", "THR-006", "THR-007"]
        for tid in unmapped_ids:
            entry = get_threat_by_id(tid)
            assert entry is not None
            assert entry.mitre_attack is None, f"{tid} must not have a speculative ATT&CK mapping"
            assert entry.mitre_attack_id is None

    def test_threat_mapper_carries_attack_metadata(self) -> None:
        f_null = SecurityFinding.create(
            finding_id="FND-NULL",
            analysis_id="analysis-thr",
            rule_id="POL-RFC-8221-01",
            rule_version="1.0.0",
            profile_id="profile_nist_sp800_77",
            category=FindingCategory.CIPHER_SUITE,
            severity=FindingSeverity.CRITICAL,
            title="NULL Cipher",
            technical_description="Cleartext ESP",
            root_cause_key="RC_ESP_NULL_CIPHER",
            affected_entity_type="CHILD_SA",
            affected_entity_id="child-1",
            observed_value="NULL",
            expected_requirement="AES-GCM",
        )

        engine = ThreatMatrixEngine()
        threats = engine.map_findings("analysis-thr", [f_null])
        assert len(threats) == 1
        thr = threats[0]
        assert thr.threat_id == "THR-008"
        assert thr.mitre_attack_id == "T1040"
        assert thr.mitre_attack_name == "Network Sniffing"
        assert thr.catalog_hash == engine.catalog_hash


class TestThreatIntelServiceOffline:
    """Verifies offline CISA KEV and FIRST EPSS ingestion and epistemic boundaries."""

    @pytest.fixture
    def intel_service(self) -> ThreatIntelService:
        return ThreatIntelService()

    def test_known_cve_lookup_success(self, intel_service: ThreatIntelService) -> None:
        # Sweet32: CVE-2016-2183
        res = intel_service.lookup_cve("CVE-2016-2183")
        assert res.cve_id == "CVE-2016-2183"
        assert res.cisa_kev_status in (FeedStatus.PRESENT, FeedStatus.STALE)
        assert res.cisa_kev_record is not None
        assert "Triple-DES" in res.cisa_kev_record.product or "3DES" in res.cisa_kev_record.product

        assert res.epss_status in (FeedStatus.PRESENT, FeedStatus.STALE)
        assert res.epss_record is not None
        assert res.epss_record.epss_score > 0.05
        assert res.epss_record.epss_percentile > 0.50

    def test_unknown_cve_returns_not_present_in_snapshot(
        self, intel_service: ThreatIntelService
    ) -> None:
        """Missing CVE from snapshot must NEVER be labeled 'not vulnerable' or 'safe'."""
        res = intel_service.lookup_cve("CVE-9999-99999")
        assert res.cve_id == "CVE-9999-99999"
        assert res.cisa_kev_status == FeedStatus.NOT_PRESENT_IN_THIS_SNAPSHOT
        assert res.cisa_kev_record is None
        assert res.epss_status == FeedStatus.NOT_PRESENT_IN_THIS_SNAPSHOT
        assert res.epss_record is None

    def test_integrity_digests_and_disclaimer_present(
        self, intel_service: ThreatIntelService
    ) -> None:
        res = intel_service.lookup_cve("CVE-2015-4000")
        assert res.cisa_kev_digest is not None
        assert len(res.cisa_kev_digest) == 64
        assert res.epss_digest is not None
        assert len(res.epss_digest) == 64
        assert "NOT that this observed gateway is affected or compromised" in res.disclaimer
        assert "Neither metric modifies deterministic policy scores" in res.disclaimer
