"""Unit tests for deterministic Risk Modeling and Threat Matrix mapping."""

from __future__ import annotations

import pytest

from app.security.findings.models import FindingCategory, FindingSeverity, SecurityFinding
from app.security.risk.engine import DeterministicRiskEngine
from app.security.risk.models import Impact, Likelihood, RiskTier
from app.security.threats.mapper import ThreatMatrixEngine


class TestDeterministicRiskEngine:
    """Tests verifying deterministic risk tier and impact mapping."""

    @pytest.fixture
    def risk_engine(self):
        return DeterministicRiskEngine()

    def test_critical_and_high_risk_assignment(self, risk_engine) -> None:
        f_null = SecurityFinding.create(
            finding_id="FND-NULL",
            analysis_id="analysis-1",
            rule_id="POL-RFC-8221-01",
            rule_version="v1.0.0",
            profile_id="profile_nist_sp800_77",
            category=FindingCategory.CIPHER_SUITE,
            severity=FindingSeverity.CRITICAL,
            title="NULL cipher",
            technical_description="Cleartext ESP traffic",
            root_cause_key="RC_ESP_NULL_CIPHER",
            affected_entity_type="CHILD_SA",
            affected_entity_id="child-1",
            observed_value="NULL",
            expected_requirement="AES-GCM",
        )
        f_dh = SecurityFinding.create(
            finding_id="FND-DH",
            analysis_id="analysis-1",
            rule_id="POL-NIST-004",
            rule_version="v1.0.0",
            profile_id="profile_nist_sp800_77",
            category=FindingCategory.KEY_EXCHANGE,
            severity=FindingSeverity.HIGH,
            title="Weak DH Group",
            technical_description="MODP 1024",
            root_cause_key="RC_DH_WEAK_GROUP",
            affected_entity_type="IKE_SA",
            affected_entity_id="sa-1",
            observed_value="MODP_1024",
            expected_requirement="MODP_2048",
        )

        res = risk_engine.assess_risks("analysis-1", [f_null, f_dh])
        assert res.overall_risk_tier == RiskTier.CRITICAL
        assert len(res.items) == 2

        item_by_id = {item.finding_id: item for item in res.items}
        assert item_by_id["FND-NULL"].risk_tier == RiskTier.CRITICAL
        assert item_by_id["FND-NULL"].impact == Impact.HIGH
        assert item_by_id["FND-DH"].risk_tier == RiskTier.HIGH


class TestThreatMatrixEngine:
    """Tests verifying pre-authored threat catalog mapping without hallucination."""

    @pytest.fixture
    def threat_engine(self):
        return ThreatMatrixEngine()

    def test_sweet32_threat_mapping(self, threat_engine) -> None:
        f_3des = SecurityFinding.create(
            finding_id="FND-3DES",
            analysis_id="analysis-1",
            rule_id="POL-NIST-001",
            rule_version="v1.0.0",
            profile_id="profile_nist_sp800_77",
            category=FindingCategory.CRYPTOGRAPHY,
            severity=FindingSeverity.HIGH,
            title="3DES Cipher Disallowed",
            technical_description="3DES is vulnerable to Sweet32",
            root_cause_key="RC_CIPHER_3DES",
            affected_entity_type="IKE_SA",
            affected_entity_id="sa-1",
            observed_value="3DES",
            expected_requirement="AES-GCM",
        )

        threats = threat_engine.map_findings("analysis-1", [f_3des])
        assert len(threats) == 1
        thr = threats[0]
        assert thr.threat_id == "THR-002"
        assert "Sweet32" in thr.threat_name
        assert thr.risk_tier == RiskTier.HIGH
        assert thr.likelihood == Likelihood.MEDIUM
        assert thr.impact == Impact.HIGH

    def test_null_cipher_threat_mapping(self, threat_engine) -> None:
        f_null = SecurityFinding.create(
            finding_id="FND-NULL",
            analysis_id="analysis-1",
            rule_id="POL-RFC-8221-01",
            rule_version="v1.0.0",
            profile_id="profile_nist_sp800_77",
            category=FindingCategory.CIPHER_SUITE,
            severity=FindingSeverity.CRITICAL,
            title="Cleartext ESP",
            technical_description="NULL cipher ESP",
            root_cause_key="RC_ESP_NULL_CIPHER",
            affected_entity_type="CHILD_SA",
            affected_entity_id="child-1",
            observed_value="NULL",
            expected_requirement="AES-GCM",
        )

        threats = threat_engine.map_findings("analysis-1", [f_null])
        assert len(threats) == 1
        thr = threats[0]
        assert thr.threat_id == "THR-008"
        assert thr.risk_tier == RiskTier.CRITICAL
        assert thr.likelihood == Likelihood.HIGH
        assert thr.impact == Impact.HIGH

    def test_unmapped_finding_handling(self, threat_engine) -> None:
        """Unmapped rule finding must NOT generate fabricated threat text."""
        f_unmapped = SecurityFinding.create(
            finding_id="FND-CUSTOM",
            analysis_id="analysis-1",
            rule_id="POL-CUSTOM-999",
            rule_version="v1.0.0",
            profile_id="profile_custom_org",
            category=FindingCategory.SA_MANAGEMENT,
            severity=FindingSeverity.LOW,
            title="Custom rule violation",
            technical_description="Custom parameter mismatch",
            root_cause_key="RC_CUSTOM_UNKNOWN",
            affected_entity_type="IKE_SESSION",
            affected_entity_id="sess-1",
            observed_value="VAL_A",
            expected_requirement="VAL_B",
        )

        threats = threat_engine.map_findings("analysis-1", [f_unmapped])
        assert len(threats) == 0, "Unmapped finding must not produce fabricated threat scenarios"
