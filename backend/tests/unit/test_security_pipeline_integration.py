"""End-to-End Pipeline Integration Tests for Stage 8 Security Engine.

Validates the full deterministic pipeline across:
1. Positive Control: Compliant modern IPsec (AES-GCM-256, DH Group 14/19, IKEv2, PFS).
2. Negative Control: Insecure legacy IPsec (3DES-CBC, MD5, DH Group 2, Sweet32, NULL).
3. Inconclusive Control: Handshake unobserved / truncated (ESP data plane only).
4. Evidence Provenance & Cryptographic Manifest verification.
"""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest

from app.db.models.reconstruction import (
    ChildSecurityAssociation,
    ESPFlow,
    IKESecurityAssociation,
    IKESession,
)
from app.reconstruction.models import Mode, PFSStatus
from app.security.evidence.models import EvidenceNodeType
from app.security.evidence.query import EvidenceProvenanceResolver
from app.security.facts.models import EvidenceState
from app.security.service import SecurityAssessmentService


@pytest.fixture
def rules_dir():
    return Path(__file__).resolve().parent.parent.parent.parent / "policies" / "rules"


@pytest.fixture
def security_service(rules_dir):
    return SecurityAssessmentService(rules_dir=rules_dir)


class TestSecurityPipelineIntegration:
    """End-to-end integration tests for the Security, Compliance & Scoring Engine."""

    def test_positive_control_compliant_stack(self, security_service: SecurityAssessmentService) -> None:
        """Fully compliant AES-GCM-256 / DH-19 / IKEv2 stack must yield 100.0 score and zero findings."""
        analysis_id = str(uuid.uuid4())
        capture_sha = "11" * 32

        session = IKESession(
            id=uuid.uuid4(),
            analysis_id=uuid.UUID(analysis_id),
            initiator_spi="aabbccddeeff0011",
            responder_spi="1100ffeeddccbbaa",
            ike_version="IKEv2",
            frame_numbers=[1, 2, 3, 4],
        )
        ike_sa = IKESecurityAssociation(
            id=uuid.uuid4(),
            session_id=session.id,
            encryption_algorithm="AES-256-GCM-16",
            key_length_bits=256,
            prf_algorithm="PRF-HMAC-SHA2-256",
            integrity_algorithm=None,  # Implicit in AEAD
            dh_group="ECP-256 (19)",
        )
        session.parent_sa = ike_sa

        child_sa = ChildSecurityAssociation(
            id=uuid.uuid4(),
            analysis_id=uuid.UUID(analysis_id),
            ike_sa_id=ike_sa.id,
            protocol="ESP",
            inbound_spi="0xc001beef",
            outbound_spi="0xdeadc001",
            mode=Mode.TUNNEL,
            encryption_algorithm="AES-256-GCM-16",
            integrity_algorithm=None,
            pfs_status=PFSStatus.ENABLED,
            pfs_dh_group="ECP-256 (19)",
        )

        flow = ESPFlow(
            id=uuid.uuid4(),
            analysis_id=uuid.UUID(analysis_id),
            child_sa_id=child_sa.id,
            spi="0xc001beef",
            packet_count=120,
            byte_count=144000,
            forward_packets=60,
            reverse_packets=60,
            duration_seconds=5.0,
        )

        res = security_service.run_assessment(
            analysis_id=analysis_id,
            capture_sha256=capture_sha,
            sessions=[session],
            child_sas=[child_sa],
            flows=[flow],
            profile_id="profile_nist_sp800_77",
        )

        # 1. Scoring Invariants
        assert res.score_assessment.overall_score == 100.0
        assert res.score_assessment.raw_score == 100.0
        assert len(res.findings) == 0
        assert res.score_assessment.evidence_coverage.coverage_percentage >= 70.0

        # 2. Risk & Threats
        assert res.risk_assessment.overall_risk_tier.value in ("NO_FINDINGS_UNDER_THIS_POLICY", "LOW")
        assert len(res.threat_instances) == 0

        # 3. Cryptographic Manifest
        assert res.manifest.manifest_sha256
        assert res.manifest.finding_count == 0
        assert res.manifest.score_value == 100.0

        # 4. Evidence Graph Integrity
        graph = res.evidence_graph
        node_types = {n.node_type for n in graph.nodes}
        assert EvidenceNodeType.CAPTURE in node_types
        assert EvidenceNodeType.FRAME in node_types
        assert EvidenceNodeType.SECURITY_FACT in node_types
        assert EvidenceNodeType.POLICY_RULE in node_types

    def test_negative_control_weak_crypto_deductions_and_threats(
        self, security_service: SecurityAssessmentService
    ) -> None:
        """Insecure stack with 3DES-CBC, MD5, and DH Group 2 must yield audited deductions and threat mappings."""
        analysis_id = str(uuid.uuid4())
        capture_sha = "22" * 32

        session = IKESession(
            id=uuid.uuid4(),
            analysis_id=uuid.UUID(analysis_id),
            initiator_spi="3344556677889900",
            responder_spi="0099887766554433",
            ike_version="IKEv2",
            frame_numbers=[10, 11, 12, 13],
        )
        ike_sa = IKESecurityAssociation(
            id=uuid.uuid4(),
            session_id=session.id,
            encryption_algorithm="3DES-CBC",
            key_length_bits=168,
            prf_algorithm="PRF-HMAC-MD5",
            integrity_algorithm="HMAC-MD5",
            dh_group="MODP-1024 (2)",
        )
        session.parent_sa = ike_sa

        child_sa = ChildSecurityAssociation(
            id=uuid.uuid4(),
            analysis_id=uuid.UUID(analysis_id),
            ike_sa_id=ike_sa.id,
            protocol="ESP",
            inbound_spi="0xbad0cafe",
            outbound_spi="0xcafebad0",
            mode=Mode.TUNNEL,
            encryption_algorithm="3DES-CBC",
            integrity_algorithm="HMAC-MD5",
            pfs_status=PFSStatus.DISABLED,
        )

        flow = ESPFlow(
            id=uuid.uuid4(),
            analysis_id=uuid.UUID(analysis_id),
            child_sa_id=child_sa.id,
            spi="0xbad0cafe",
            packet_count=80,
            byte_count=96000,
            forward_packets=40,
            reverse_packets=40,
            duration_seconds=3.0,
        )

        res = security_service.run_assessment(
            analysis_id=analysis_id,
            capture_sha256=capture_sha,
            sessions=[session],
            child_sas=[child_sa],
            flows=[flow],
            profile_id="profile_nist_sp800_77",
        )

        # 1. Findings generated for violations
        assert len(res.findings) >= 3
        rule_ids = {f.rule_id for f in res.findings}
        assert "POL-NIST-001" in rule_ids  # Disallow DES/3DES
        assert "POL-NIST-003" in rule_ids  # Disallow MD5/SHA1
        assert "POL-NIST-004" in rule_ids  # DH Group >= 14

        # 2. Score Deduction Auditing
        assert res.score_assessment.overall_score < 100.0
        assert res.score_assessment.overall_score >= 0.0
        deduction_keys = {d.root_cause_key for d in res.score_assessment.deduction_audit}
        assert "CIPHER_DEPRECATED_DES" in deduction_keys
        assert "INTEGRITY_DEPRECATED_HASH" in deduction_keys
        assert "DH_GROUP_WEAK_LOGJAM" in deduction_keys

        # 3. Threat Matrix mapping
        threat_ids = {t.threat_id for t in res.threat_instances}
        assert "THR-002" in threat_ids or "THR-004" in threat_ids  # Sweet32 or Deprecated Integrity

        # 4. Forensic Provenance Lineage: Finding resolves back to frame 10
        resolver = EvidenceProvenanceResolver(res.evidence_graph)
        first_finding = res.findings[0]
        lineage = resolver.resolve_finding_lineage(first_finding.finding_id)
        assert lineage["finding"]["node_id"] == f"finding:{first_finding.finding_id}"
        assert lineage["capture_sha256"] == capture_sha

    def test_inconclusive_control_unobserved_handshake_zero_penalty(
        self, security_service: SecurityAssessmentService
    ) -> None:
        """Mid-stream ESP capture without IKE handshake must yield UNKNOWN gaps and exactly 0.0 penalty."""
        analysis_id = str(uuid.uuid4())
        capture_sha = "76b74be5fc6e60d931c1bcf959360c84b59d7f70bada30b46af8938bff339bdd"

        # No IKE session or IKE SAs observed (e.g. real_esp_only.pcap)
        # Child SA is inferred from ESP packets with unknown parameters
        child_sa = ChildSecurityAssociation(
            id=uuid.uuid4(),
            analysis_id=uuid.UUID(analysis_id),
            ike_sa_id=None,
            protocol="ESP",
            inbound_spi="0xc4f6f980",
            outbound_spi="0xc9535e6a",
            mode=Mode.TUNNEL,
            encryption_algorithm=None,  # Unobserved
            integrity_algorithm=None,   # Unobserved
            pfs_status=PFSStatus.UNKNOWN,
            evidence_state=EvidenceState.INFERRED,
        )

        flow = ESPFlow(
            id=uuid.uuid4(),
            analysis_id=uuid.UUID(analysis_id),
            child_sa_id=child_sa.id,
            spi="0xc4f6f980",
            packet_count=8,
            byte_count=1588,
            forward_packets=4,
            reverse_packets=4,
            duration_seconds=1.2,
        )

        res = security_service.run_assessment(
            analysis_id=analysis_id,
            capture_sha256=capture_sha,
            sessions=[],
            child_sas=[child_sa],
            flows=[flow],
            profile_id="profile_nist_sp800_77",
        )

        # 1. Epistemic Invariant: UNKNOWN is NOT a weakness -> zero deduction
        assert res.score_assessment.overall_score == 100.0
        assert len(res.findings) == 0

        # 2. Auditable Evidence Gaps generated
        assert len(res.evidence_gaps) >= 1
        gap_rules = {g.rule_id for g in res.evidence_gaps}
        assert "POL-NIST-001" in gap_rules or "POL-RFC-7296-01" in gap_rules

        # 3. Evidence Coverage reflects unobserved facts
        assert res.score_assessment.evidence_coverage.unknown_rules > 0
        assert res.score_assessment.evidence_coverage.coverage_percentage < 100.0

        # 4. Mandatory internal product disclaimer present
        assert "NOT an official NIST" in res.score_assessment.disclaimer
