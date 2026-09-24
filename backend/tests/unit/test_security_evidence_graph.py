"""Unit tests for the Forensic Evidence & Provenance Graph and Assessment Manifest."""

from __future__ import annotations

import pytest

from app.security.evidence.builder import EvidenceGraphBuilder
from app.security.evidence.models import EvidenceNodeType
from app.security.evidence.query import EvidenceProvenanceResolver
from app.security.facts.models import DerivationType, EvidenceState, SecurityFact, SubjectType
from app.security.findings.models import FindingCategory, FindingSeverity, SecurityFinding
from app.security.manifest import AssessmentManifest
from app.security.policy.evaluator import ComplianceState, EvaluationRecord
from app.security.scoring.models import EvidenceCoverage, ScoreAssessment, ScoreDeduction
from app.security.threats.models import Impact, Likelihood, RiskTier, ThreatInstance


class TestEvidenceGraphAndProvenance:
    """Tests verifying unbroken cryptographic lineage from packets to findings."""

    @pytest.fixture
    def sample_data(self):
        analysis_id = "test-analysis-1"
        capture_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

        fact_3des = SecurityFact(
            fact_id="fact-ike-3des",
            analysis_id=analysis_id,
            subject_type=SubjectType.IKE_SA,
            subject_id="sa-1",
            canonical_key="ike_sa.encryption_algorithm",
            value="3DES-CBC",
            data_type="string",
            evidence_state=EvidenceState.VERIFIED,
            derivation_type=DerivationType.DIRECT,
            source_frame_numbers=[14, 15],
            source_observation_ids=["obs-14", "obs-15"],
        )

        rec = EvaluationRecord(
            rule_id="POL-NIST-001",
            rule_version="v1.0.0",
            profile_id="profile_nist_sp800_77",
            subject_type="IKE_SA",
            subject_id="sa-1",
            compliance_state=ComplianceState.FAIL,
            evidence_state="VERIFIED",
            rationale="3DES disallowed",
        )

        finding = SecurityFinding.create(
            finding_id="FND-3DES",
            analysis_id=analysis_id,
            rule_id="POL-NIST-001",
            rule_version="v1.0.0",
            profile_id="profile_nist_sp800_77",
            category=FindingCategory.CRYPTOGRAPHY,
            severity=FindingSeverity.HIGH,
            title="3DES Cipher Disallowed",
            technical_description="3DES violates NIST SP 800-77 Rev. 1",
            root_cause_key="RC_CIPHER_3DES",
            affected_entity_type="IKE_SA",
            affected_entity_id="sa-1",
            observed_value="3DES-CBC",
            expected_requirement="AES-GCM",
            evidence_node_links=["fact-ike-3des"],
            remediation_guidance="Upgrade strongSwan cipher suite to aes256gcm16.",
        )

        threat = ThreatInstance(
            threat_id="THR-001",
            finding_id="FND-3DES",
            rule_id="POL-NIST-001",
            rule_version="v1.0.0",
            threat_name="Sweet32 Attack",
            affected_entity="IKE_SA sa-1",
            preconditions="Passive attacker observes 32GB+ traffic.",
            attack_vector="Collision attack on 64-bit block cipher.",
            impact=Impact.HIGH,
            likelihood=Likelihood.MEDIUM,
            risk_tier=RiskTier.HIGH,
            evidence_state="VERIFIED",
        )

        deduction = ScoreDeduction(
            finding_id="FND-3DES",
            rule_id="POL-NIST-001",
            category="CRYPTOGRAPHY",
            severity=FindingSeverity.HIGH,
            root_cause_key="RC_CIPHER_3DES",
            raw_deduction=15.0,
            applied_deduction=15.0,
            is_deduplicated=False,
            rationale="Primary violation",
        )

        score_ass = ScoreAssessment(
            analysis_id=analysis_id,
            overall_score=85.0,
            raw_score=85.0,
            score_policy_id="SCORE-DEFAULT",
            score_policy_version="v1.0.0",
            score_policy_hash="hash123",
            status="ACTIVE",
            category_scores={"CRYPTOGRAPHY": 85.0},
            deduction_audit=[deduction],
            evidence_coverage=EvidenceCoverage(
                applicable_rules=1,
                evaluated_rules=1,
                unknown_rules=0,
                not_applicable_rules=0,
                coverage_percentage=100.0,
            ),
        )

        return {
            "analysis_id": analysis_id,
            "capture_sha256": capture_sha256,
            "facts": [fact_3des],
            "evals": [rec],
            "findings": [finding],
            "threats": [threat],
            "score": score_ass,
        }

    def test_evidence_graph_building_and_lineage(self, sample_data) -> None:
        builder = EvidenceGraphBuilder()
        graph = builder.build_graph(
            analysis_id=sample_data["analysis_id"],
            capture_sha256=sample_data["capture_sha256"],
            security_facts=sample_data["facts"],
            eval_records=sample_data["evals"],
            findings=sample_data["findings"],
            evidence_gaps=[],
            threat_instances=sample_data["threats"],
            score_assessment=sample_data["score"],
        )

        node_types = {n.node_type for n in graph.nodes}
        assert EvidenceNodeType.CAPTURE in node_types
        assert EvidenceNodeType.FRAME in node_types
        assert EvidenceNodeType.SECURITY_FACT in node_types
        assert EvidenceNodeType.POLICY_RULE in node_types
        assert EvidenceNodeType.SECURITY_FINDING in node_types
        assert EvidenceNodeType.THREAT in node_types
        assert EvidenceNodeType.SCORE_COMPONENT in node_types

        # Verify React Flow conversion
        rf = graph.to_react_flow()
        assert "nodes" in rf
        assert "edges" in rf
        assert len(rf["nodes"]) == len(graph.nodes)
        assert len(rf["edges"]) == len(graph.edges)

        # Verify Provenance Resolver resolves finding back to frames
        resolver = EvidenceProvenanceResolver(graph)
        lineage = resolver.resolve_finding_lineage("FND-3DES")
        assert lineage["finding"]["node_id"] == "finding:FND-3DES"
        assert lineage["capture_sha256"] == sample_data["capture_sha256"]

        frame_numbers = [f["properties"]["frame_number"] for f in lineage["source_frames"]]
        assert 14 in frame_numbers
        assert 15 in frame_numbers

        threat_ids = [t["properties"]["threat_id"] for t in lineage["mapped_threats"]]
        assert "THR-001" in threat_ids


class TestAssessmentManifest:
    """Tests verifying tamper-evident cryptographic sealing of assessments."""

    def test_manifest_sealing_and_tamper_detection(self) -> None:
        m1 = AssessmentManifest.create(
            analysis_id="analysis-1",
            capture_sha256="abc123sha",
            policy_bundle_id="bundle-1",
            policy_bundle_version="v1.0.0",
            policy_bundle_hash="hash_bundle",
            score_policy_hash="hash_score",
            risk_policy_hash="hash_risk",
            threat_catalog_hash="hash_threat",
            ml_bundle_hash=None,
            finding_hashes=["f_hash_1", "f_hash_2"],
            score_value=85.0,
            coverage_percentage=100.0,
            fingerprintability_hash="hash_mfi",
        )
        assert m1.manifest_sha256
        assert len(m1.manifest_sha256) == 64

        # Any altered finding hash produces a completely different manifest hash
        m2 = AssessmentManifest.create(
            analysis_id="analysis-1",
            capture_sha256="abc123sha",
            policy_bundle_id="bundle-1",
            policy_bundle_version="v1.0.0",
            policy_bundle_hash="hash_bundle",
            score_policy_hash="hash_score",
            risk_policy_hash="hash_risk",
            threat_catalog_hash="hash_threat",
            ml_bundle_hash=None,
            finding_hashes=["f_hash_1", "f_hash_TAMPERED"],
            score_value=85.0,
            coverage_percentage=100.0,
            fingerprintability_hash="hash_mfi",
        )
        assert m1.manifest_sha256 != m2.manifest_sha256
