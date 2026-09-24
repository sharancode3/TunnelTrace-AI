"""Unit tests for Stage 9 deterministic report generation and template security."""

from __future__ import annotations

import uuid
from typing import Any

from app.reporting.engine import ReportGeneratorEngine
from app.services.storage.local import LocalStorageProvider


def _build_test_snapshot(analysis_id: uuid.UUID | None = None) -> dict[str, Any]:
    """Construct an explicit test fixture snapshot conforming to domain contracts."""
    aid = analysis_id or uuid.uuid4()
    return {
        "analysis_id": str(aid),
        "capture": {
            "id": str(uuid.uuid4()),
            "filename": "controlled_test_capture.pcap",
            "sha256": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
            "file_size_bytes": 10240,
            "packet_count": 128,
        },
        "analysis": {
            "status": "COMPLETED",
            "current_stage": "COMPLETED",
            "parser_engine": "tshark",
            "parser_version": "4.2.0",
            "schema_version": "1.0.0",
            "created_at": "2026-09-24T10:00:00Z",
            "completed_at": "2026-09-24T10:00:02Z",
        },
        "protocol": {
            "total_observations": 4,
            "ike_versions": ["IKEv2"],
            "protocols_detected": ["ESP", "IKEv2"],
            "nat_detected": False,
            "transforms_observed": ["ENCR_AES_GCM_16_256", "PRF_HMAC_SHA2_256"],
            "dh_groups": ["19"],
        },
        "security_associations": {
            "ike_session_count": 1,
            "child_sa_count": 2,
            "flow_count": 2,
            "total_bytes": 2048,
            "total_packets": 32,
            "child_sas": [
                {
                    "id": str(uuid.uuid4()),
                    "protocol": "ESP",
                    "inbound_spi": "0x11223344",
                    "outbound_spi": "0x55667788",
                    "mode": "TUNNEL",
                    "pfs_status": "ENABLED",
                    "encryption_algorithm": "AES-256-GCM",
                    "integrity_algorithm": "AEAD-INTEGRATED",
                    "lifecycle_state": "ESTABLISHED",
                    "evidence_state": "VERIFIED",
                }
            ],
        },
        "traffic": {
            "classified_flows": 2,
            "classes_detected": ["IPSEC_CONTROL", "DNS_OVER_IPSEC"],
            "avg_calibrated_confidence": 0.942,
            "ood_count": 0,
            "anomaly_count": 0,
            "class_distribution": {"IPSEC_CONTROL": 1, "DNS_OVER_IPSEC": 1},
        },
        "compliance": {
            "total_evaluations": 4,
            "pass_count": 3,
            "fail_count": 1,
            "unknown_count": 0,
            "not_applicable_count": 0,
            "evaluations": [
                {
                    "rule_id": "POL-NIST-001",
                    "rule_title": "Approved Encryption Algorithms",
                    "category": "CRYPTOGRAPHY",
                    "severity": "CRITICAL",
                    "standard": "NIST SP 800-77 Rev. 1 Section 4.1",
                    "compliance_state": "PASS",
                    "evidence_state": "VERIFIED",
                    "observed_value": "AES-256-GCM",
                    "expected_value": "AES-GCM-128+",
                    "rationale": "AES-256-GCM complies with NIST SP 800-77 Rev. 1 requirements.",
                },
                {
                    "rule_id": "POL-NIST-002",
                    "rule_title": "Approved Key Exchange Groups",
                    "category": "KEY_EXCHANGE",
                    "severity": "HIGH",
                    "standard": "NIST SP 800-77 Rev. 1 Section 4.2",
                    "compliance_state": "FAIL",
                    "evidence_state": "VERIFIED",
                    "observed_value": "Group 2",
                    "expected_value": "Group 14+",
                    "rationale": "DH Group 2 (MODP-1024) is deprecated and insecure.",
                },
            ],
        },
        "findings": {
            "total_findings": 1,
            "critical_count": 0,
            "high_count": 1,
            "medium_count": 0,
            "low_count": 0,
            "findings": [
                {
                    "finding_id": str(uuid.uuid4()),
                    "rule_id": "POL-NIST-002",
                    "title": "Deprecated Diffie-Hellman Group 2",
                    "severity": "HIGH",
                    "category": "KEY_EXCHANGE",
                    "score_deduction": 20.0,
                    "affected_entity": "IKE_SA[0x11223344]",
                    "technical_description": "Diffie-Hellman Group 2 (MODP-1024) provides only 80 bits of security.",
                    "remediation_guidance": "Migrate to DH Group 14 (MODP-2048) or Group 19 (ECP-256).",
                    "evidence_references": ["obs:frame_1"],
                    "evidence_state": "VERIFIED",
                    "root_cause_key": "DH_DEPRECATED_GROUP_2",
                }
            ],
        },
        "score": {
            "score": 80.0,
            "evidence_coverage": 1.0,
            "methodology_version": "1.0.0",
            "score_policy_hash": "sha256:testscorehash123",
            "itemized_deductions": {"DH_DEPRECATED_GROUP_2": 20.0},
        },
        "risk": {
            "aggregate_risk_tier": "HIGH",
            "risk_score": 75.0,
            "rationale": "High cryptographic downgrade risk observed on key exchange.",
        },
        "threats": [
            {
                "threat_id": "THR-002",
                "title": "Diffie-Hellman Discrete Logarithm Factoring",
                "category": "CRYPTOGRAPHIC_ATTACK",
                "likelihood": "MEDIUM",
                "impact": "HIGH",
                "risk_tier": "HIGH",
                "mitre_technique_id": "T1600.001",
                "nist_control": "SC-12",
                "evidence_state": "VERIFIED",
            }
        ],
        "metadata_fingerprintability": {
            "overall_index": 0.421,
            "is_experimental": True,
            "component_metrics": {
                "packet_size_dispersion": 0.35,
                "burst_entropy": 0.45,
                "directionality_ratio": 0.50,
            },
            "disclaimer": "Behavioral side-channel distinguishability under tested methodology. Does not imply decryption.",
        },
        "generated_at": "2026-09-24T10:00:05Z",
        "snapshot_sha256": "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
    }


def test_executive_report_html_rendering():
    """Verify Executive report renders expected fields, escapes malicious content, and embeds styling."""
    engine = ReportGeneratorEngine()
    snapshot = _build_test_snapshot()

    html = engine.render_html("EXECUTIVE", snapshot)

    assert "<!DOCTYPE html>" in html
    assert "Executive Security Assessment" in html
    assert "controlled_test_capture.pcap" in html
    assert "80.0" in html
    assert "POL-NIST-002" in html
    assert "Deprecated Diffie-Hellman Group 2" in html
    assert "THR-002" in html
    assert "0.421" in html
    assert "Forensic Report Provenance &amp; Artifact Attestation" in html or "Forensic Report Provenance & Artifact Attestation" in html
    assert "1234567890abcdef" in html


def test_technical_report_html_rendering():
    """Verify Technical report renders forensic observations, SAs, compliance audit, and disclaimers."""
    engine = ReportGeneratorEngine()
    snapshot = _build_test_snapshot()

    html = engine.render_html("TECHNICAL", snapshot)

    assert "<!DOCTYPE html>" in html
    assert "Technical Forensics &amp; Security Audit" in html or "Technical Forensics & Security Audit" in html
    assert "controlled_test_capture.pcap" in html
    assert "ENCR_AES_GCM_16_256" in html
    assert "0x11223344" in html
    assert "POL-NIST-001" in html
    assert "POL-NIST-002" in html
    assert "DH_DEPRECATED_GROUP_2" in html
    assert ("packet size dispersion" in html or "packet_size_dispersion" in html)
    assert "Payload is not decrypted" in html or "payloads are never decrypted" in html.lower()


def test_report_determinism():
    """Generating HTML report twice with same snapshot produces identical byte content."""
    engine = ReportGeneratorEngine()
    snapshot = _build_test_snapshot()

    html1 = engine.render_html("EXECUTIVE", snapshot)
    html2 = engine.render_html("EXECUTIVE", snapshot)

    assert html1 == html2


def test_xss_prevention_in_report_rendering():
    """Verify malicious script injection attempts in filenames or finding titles are escaped."""
    engine = ReportGeneratorEngine()
    snapshot = _build_test_snapshot()
    snapshot["capture"]["filename"] = "<script>alert('xss')</script>.pcap"
    snapshot["findings"]["findings"][0]["title"] = "<img src=x onerror=alert(1)>"

    html = engine.render_html("EXECUTIVE", snapshot)

    assert "<script>alert('xss')</script>" not in html
    assert "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;.pcap" in html or "&lt;script&gt;" in html
    assert "<img src=x onerror=alert(1)>" not in html
    assert "&lt;img src=x onerror=alert(1)&gt;" in html


def test_generate_report_artifacts_local_storage(tmp_path):
    """Verify generate_report_artifacts persists HTML, computes SHA-256, and returns metadata."""
    storage = LocalStorageProvider(root_path=tmp_path)
    engine = ReportGeneratorEngine()
    analysis_id = uuid.uuid4()
    snapshot = _build_test_snapshot(analysis_id)

    res = engine.generate_report_artifacts(
        analysis_id=analysis_id,
        report_type="EXECUTIVE",
        snapshot=snapshot,
        storage=storage,
    )

    assert res["status"] in ["COMPLETED", "PDF_FAILED_HTML_AVAILABLE"]
    assert res["html_artifact_path"] is not None
    assert storage.exists(res["html_artifact_path"])
    assert res["html_sha256"] is not None
    assert len(res["html_sha256"]) == 64
    assert res["snapshot_manifest_sha256"] == snapshot["snapshot_sha256"]
