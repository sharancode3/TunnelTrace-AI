"""Unit tests for Configuration Security Twin & Policy Projection Engine."""

from __future__ import annotations

import pytest

from app.remediation.ir import (
    ChildSAConfigurationIR,
    ConfigurationIR,
    ConnectionConfigurationIR,
    CurrentConfigurationSnapshot,
    EpistemicValue,
    TransformIR,
)
from app.remediation.twin import ConfigurationSecurityTwin, TWIN_DISCLAIMER
from app.security.findings.models import SecurityFinding
from app.security.policy.evaluator import ComplianceState
from app.security.policy.schema import FindingCategory, Severity


def test_twin_policy_projection_labels_and_audit():
    """Verify Twin projection runs same Policy Engine and explicitly labels outcomes as PROJECTED."""
    twin_engine = ConfigurationSecurityTwin()

    current_snapshot = CurrentConfigurationSnapshot(
        analysis_id="an-twin-1",
        capture_sha256="hash-baseline",
        ike_version=EpistemicValue.known("IKEv2", "wire"),
        ike_encryption=EpistemicValue.known("3DES", "wire"),  # Deprecated (POL-NIST-001)
        ike_key_length=EpistemicValue.known(64, "wire"),  # Weak key (POL-NIST-002)
        ike_integrity=EpistemicValue.known("MD5", "wire"),  # Deprecated (POL-NIST-003)
        ike_prf=EpistemicValue.known("MD5", "wire"),
        ike_dh_group=EpistemicValue.known(2, "wire"),  # Weak DH (POL-NIST-004)
        child_mode=EpistemicValue.known("tunnel", "wire"),
        child_encryption=EpistemicValue.known("AES256-GCM", "wire"),
        child_integrity=EpistemicValue.known("AEAD-INTEGRATED", "wire"),
        child_pfs_status=EpistemicValue.known("DISABLED", "wire"),  # (POL-PFS-001)
        child_pfs_dh_group=EpistemicValue.unknown("wire"),
        child_replay_window=EpistemicValue.known(64, "wire"),
        is_nat_detected=EpistemicValue.known(False, "wire"),
    )

    baseline_findings = [
        SecurityFinding.create(
            finding_id="find-3des",
            analysis_id="an-twin-1",
            rule_id="POL-NIST-001",
            rule_version="1.0.0",
            profile_id="profile_nist_sp800_77",
            category=FindingCategory.CRYPTOGRAPHY,
            severity=Severity.CRITICAL,
            title="Prohibition of DES and Triple-DES",
            technical_description="3DES observed",
            root_cause_key="CIPHER_DEPRECATED_DES",
            affected_entity_type="IKE_SA",
            affected_entity_id="sa-1",
            observed_value="3DES",
            expected_requirement="AES-GCM",
        ),
        SecurityFinding.create(
            finding_id="find-dh2",
            analysis_id="an-twin-1",
            rule_id="POL-NIST-004",
            rule_version="1.0.0",
            profile_id="profile_nist_sp800_77",
            category=FindingCategory.KEY_EXCHANGE,
            severity=Severity.HIGH,
            title="Weak DH Group",
            technical_description="DH Group 2 observed",
            root_cause_key="DH_GROUP_WEAK_LOGJAM",
            affected_entity_type="IKE_SA",
            affected_entity_id="sa-1",
            observed_value=2,
            expected_requirement="Group 14+",
        ),
    ]

    # Propose fully hardened configuration: AES-256-GCM + Group 19 (ECP-256) + PFS
    proposed_ir = ConfigurationIR(
        connections=(
            ConnectionConfigurationIR(
                name="tt-hardened",
                ike_version=2,
                ike_proposals=(
                    TransformIR(
                        encryption="aes256gcm16",
                        key_length=256,
                        prf="prfsha256",
                        dh_group=19,
                    ),
                ),
                children=(
                    ChildSAConfigurationIR(
                        name="child-hardened",
                        mode="tunnel",
                        esp_proposals=(
                            TransformIR(
                                encryption="aes256gcm16",
                                key_length=256,
                                dh_group=19,
                            ),
                        ),
                        pfs_dh_group=19,
                        replay_window=64,
                    ),
                ),
            ),
        )
    )

    sim = twin_engine.run_projection(
        analysis_id="an-twin-1",
        current_snapshot=current_snapshot,
        proposed_ir=proposed_ir,
        baseline_findings=baseline_findings,
        baseline_score=45.0,
        baseline_risk_score=78.0,
        profile_id="profile_nist_sp800_77",
    )

    # 1. Verification of status and disclaimer
    assert sim.status == "PROJECTED"
    assert sim.disclaimer == TWIN_DISCLAIMER
    assert len(sim.proposal_hash) == 64

    # 2. Score Projection
    assert sim.projected_score is not None
    assert sim.projected_score > 45.0
    assert sim.projected_score_delta is not None
    assert sim.projected_score_delta > 0

    # 3. Projected Regression Audit
    audit = sim.regression_audit
    assert audit.has_blocking_regressions is False
    assert len(audit.projected_resolved_findings) >= 2
    resolved_rules = {r["rule_id"] for r in audit.projected_resolved_findings}
    assert "POL-NIST-001" in resolved_rules
    assert "POL-NIST-004" in resolved_rules

    # Every item must be marked PROJECTED_RESOLVED, not VERIFIED
    for res_item in audit.projected_resolved_findings:
        assert res_item["projected_state"] == "PROJECTED_RESOLVED"
        assert "VERIFIED" not in res_item["projected_state"]


def test_twin_detects_projected_regressions():
    """Verify Twin detects when a proposed configuration introduces new policy regressions."""
    twin_engine = ConfigurationSecurityTwin()

    current_snapshot = CurrentConfigurationSnapshot(
        analysis_id="an-twin-2",
        capture_sha256="hash-baseline",
        ike_version=EpistemicValue.known("IKEv2", "wire"),
        ike_encryption=EpistemicValue.known("AES256", "wire"),
        ike_key_length=EpistemicValue.known(256, "wire"),
        ike_integrity=EpistemicValue.known("SHA256", "wire"),
        ike_prf=EpistemicValue.known("SHA256", "wire"),
        ike_dh_group=EpistemicValue.known(14, "wire"),
        child_mode=EpistemicValue.known("tunnel", "wire"),
        child_encryption=EpistemicValue.known("AES256", "wire"),
        child_integrity=EpistemicValue.known("SHA256", "wire"),
        child_pfs_status=EpistemicValue.known("ENABLED", "wire"),
        child_pfs_dh_group=EpistemicValue.known(14, "wire"),
        child_replay_window=EpistemicValue.known(64, "wire"),
        is_nat_detected=EpistemicValue.known(False, "wire"),
    )

    # Inadvertently proposing 3DES or weak DH 2 introduces a regression!
    regressive_ir = ConfigurationIR(
        connections=(
            ConnectionConfigurationIR(
                name="tt-regressive",
                ike_version=2,
                ike_proposals=(
                    TransformIR(
                        encryption="3des",
                        key_length=64,
                        prf="md5",
                        dh_group=2,  # Logjam weak group!
                    ),
                ),
                children=(
                    ChildSAConfigurationIR(
                        name="child-regressive",
                        mode="tunnel",
                        esp_proposals=(TransformIR(encryption="null"),),  # Cleartext null!
                        replay_window=64,
                    ),
                ),
            ),
        )
    )

    sim = twin_engine.run_projection(
        analysis_id="an-twin-2",
        current_snapshot=current_snapshot,
        proposed_ir=regressive_ir,
        baseline_findings=[],  # Baseline had zero findings
        baseline_score=100.0,
        baseline_risk_score=10.0,
    )

    audit = sim.regression_audit
    assert len(audit.projected_new_regressions) > 0
    assert audit.has_blocking_regressions is True
    reg_rules = {r["rule_id"] for r in audit.projected_new_regressions}
    assert "POL-NIST-001" in reg_rules or "POL-NIST-004" in reg_rules
