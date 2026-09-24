"""Unit tests for Stage 10 Typed Configuration IR, Epistemic Values, and Parser/Renderer."""

from __future__ import annotations

import pytest

from app.remediation.ir import (
    ChildSAConfigurationIR,
    ConfigurationIR,
    ConnectionConfigurationIR,
    CurrentConfigurationSnapshot,
    EpistemicState,
    EpistemicValue,
    SecretConfigurationIR,
    TransformIR,
)
from app.remediation.parser import ForensicFactsSnapshotBuilder, SwanctlParser
from app.remediation.renderer import ConfigurationDiffEngine, SwanctlRenderer
from app.security.facts.models import DerivationType, EvidenceState, SecurityFact, SubjectType


def test_epistemic_value_preservation():
    """Verify epistemic states KNOWN, UNKNOWN, NOT_APPLICABLE, UNSUPPORTED are strictly preserved."""
    v_known = EpistemicValue.known(19, source="wire_dh_group")
    assert v_known.state == EpistemicState.KNOWN
    assert v_known.value == 19
    assert v_known.to_dict()["state"] == "KNOWN"

    v_unknown = EpistemicValue.unknown(source="unobserved_pfs")
    assert v_unknown.state == EpistemicState.UNKNOWN
    assert v_unknown.value is None
    # Must not falsify unknown as False or 0
    assert v_unknown.value is not False

    v_na = EpistemicValue.not_applicable(source="transport_mode_no_outer_ip")
    assert v_na.state == EpistemicState.NOT_APPLICABLE

    v_unsupported = EpistemicValue.unsupported(source="vendor_proprietary_flag")
    assert v_unsupported.state == EpistemicState.UNSUPPORTED


def test_transform_ir_strongswan_string():
    """Verify standard strongSwan proposal syntax rendering."""
    tf_aead = TransformIR(encryption="aes256gcm16", key_length=256, prf="prfsha256", dh_group=19)
    assert tf_aead.to_strongswan_string(is_ike=True) == "aes256gcm16-prfsha256-ecp256"
    assert tf_aead.to_strongswan_string(is_ike=False) == "aes256gcm16-ecp256"

    tf_cbc = TransformIR(encryption="aes256", key_length=256, integrity="sha256", prf="prfsha256", dh_group=14)
    assert tf_cbc.to_strongswan_string(is_ike=True) == "aes256-sha256-prfsha256-modp2048"
    assert tf_cbc.to_strongswan_string(is_ike=False) == "aes256-sha256-modp2048"


def test_swanctl_parser_and_renderer_roundtrip():
    """Verify parse -> IR -> render -> parse roundtrip preserves supported security semantics."""
    original_conf = """
connections {
    tunnel-gw-a {
        version = 2
        local_addrs = 192.168.1.1
        remote_addrs = 192.168.1.2
        proposals = aes256gcm16-prfsha256-ecp256
        encap = yes
        rekey_time = 14400s

        local {
            auth = psk
            id = peer-a.tunneltrace.local
        }
        remote {
            auth = psk
            id = peer-b.tunneltrace.local
        }

        children {
            child-sa {
                local_ts = 10.0.1.0/24
                remote_ts = 10.0.2.0/24
                mode = tunnel
                esp_proposals = aes256gcm16-ecp256
                start_action = start
                rekey_time = 3600s
                replay_window = 64
            }
        }
    }
}

secrets {
    ike-psk {
        id = peer-b.tunneltrace.local
        secret = "super_secret_lab_psk_12345"
    }
}
"""
    # 1. Parse
    ir1 = SwanctlParser.parse_text(original_conf)
    assert len(ir1.connections) == 1
    conn1 = ir1.connections[0]
    assert conn1.name == "tunnel-gw-a"
    assert conn1.ike_version == 2
    assert conn1.encap is True
    assert len(conn1.children) == 1
    child1 = conn1.children[0]
    assert child1.mode == "tunnel"
    assert child1.replay_window == 64
    assert child1.pfs_dh_group == 19

    # Verify secrets are redacted in IR
    assert ir1.secrets[0].is_redacted is True
    assert "super_secret" not in ir1.secrets[0].secret_placeholder

    # 2. Render
    rendered = SwanctlRenderer.render(ir1)
    assert "connections {" in rendered
    assert "aes256gcm16-prfsha256-ecp256" in rendered
    assert "aes256gcm16-ecp256" in rendered

    # 3. Re-parse rendered
    ir2 = SwanctlParser.parse_text(rendered)
    assert len(ir2.connections) == 1
    assert ir2.connections[0].ike_version == ir1.connections[0].ike_version
    assert ir2.connections[0].children[0].pfs_dh_group == ir1.connections[0].children[0].pfs_dh_group


def test_forensic_facts_snapshot_builder():
    """Verify CurrentConfigurationSnapshot is constructed purely from facts without unobserved assumptions."""
    facts = [
        SecurityFact(
            key="ike_session.ike_version",
            value="IKEv2",
            data_type="string",
            subject_type=SubjectType.IKE_SESSION,
            subject_id="sess-1",
            evidence_state=EvidenceState.VERIFIED,
            analysis_id="an-1",
            capture_sha256="hash-1",
            derivation_type=DerivationType.DIRECT,
        ),
        SecurityFact(
            key="ike_sa.encryption_algorithm",
            value="3DES",
            data_type="string",
            subject_type=SubjectType.IKE_SA,
            subject_id="sa-1",
            evidence_state=EvidenceState.VERIFIED,
            analysis_id="an-1",
            capture_sha256="hash-1",
            derivation_type=DerivationType.DIRECT,
        ),
        SecurityFact(
            key="ike_sa.diffie_hellman_group",
            value=2,
            data_type="integer",
            subject_type=SubjectType.IKE_SA,
            subject_id="sa-1",
            evidence_state=EvidenceState.VERIFIED,
            analysis_id="an-1",
            capture_sha256="hash-1",
            derivation_type=DerivationType.DIRECT,
        ),
        SecurityFact(
            key="child_sa.pfs_status",
            value=None,
            data_type="string",
            subject_type=SubjectType.CHILD_SA,
            subject_id="csa-1",
            evidence_state=EvidenceState.UNKNOWN,
            analysis_id="an-1",
            capture_sha256="hash-1",
            derivation_type=DerivationType.DETERMINISTIC_DERIVATION,
        ),
    ]

    snapshot = ForensicFactsSnapshotBuilder.build_snapshot("an-1", "hash-1", facts)
    assert snapshot.ike_version.value == "IKEv2"
    assert snapshot.ike_version.state == EpistemicState.KNOWN
    assert snapshot.ike_encryption.value == "3DES"
    assert snapshot.ike_dh_group.value == 2
    # PFS must remain UNKNOWN, not assumed false
    assert snapshot.child_pfs_status.state == EpistemicState.UNKNOWN
    assert snapshot.child_pfs_status.value is None


def test_deterministic_semantic_diff():
    """Verify semantic diff correctly identifies changed security properties."""
    snapshot = CurrentConfigurationSnapshot(
        analysis_id="an-1",
        capture_sha256="hash-1",
        ike_version=EpistemicValue.known("IKEv1", "wire"),
        ike_encryption=EpistemicValue.known("3DES", "wire"),
        ike_key_length=EpistemicValue.known(64, "wire"),
        ike_integrity=EpistemicValue.known("MD5", "wire"),
        ike_prf=EpistemicValue.known("MD5", "wire"),
        ike_dh_group=EpistemicValue.known(2, "wire"),
        child_mode=EpistemicValue.known("tunnel", "wire"),
        child_encryption=EpistemicValue.known("NULL", "wire"),
        child_integrity=EpistemicValue.unknown("wire"),
        child_pfs_status=EpistemicValue.known("DISABLED", "wire"),
        child_pfs_dh_group=EpistemicValue.unknown("wire"),
        child_replay_window=EpistemicValue.known(32, "wire"),
        is_nat_detected=EpistemicValue.known(False, "wire"),
    )

    proposed_ir = ConfigurationIR(
        connections=(
            ConnectionConfigurationIR(
                name="tt-hardened",
                ike_version=2,
                ike_proposals=(TransformIR(encryption="aes256gcm16", key_length=256, prf="prfsha256", dh_group=19),),
                children=(
                    ChildSAConfigurationIR(
                        name="child-hardened",
                        mode="tunnel",
                        esp_proposals=(TransformIR(encryption="aes256gcm16", key_length=256, dh_group=19),),
                        pfs_dh_group=19,
                        replay_window=64,
                    ),
                ),
            ),
        )
    )

    diffs = ConfigurationDiffEngine.compute_semantic_diff(snapshot, proposed_ir)
    diff_map = {d["field"]: d for d in diffs}

    assert diff_map["ike_version"]["is_changed"] is True
    assert diff_map["ike_encryption"]["is_changed"] is True
    assert diff_map["ike_dh_group"]["is_changed"] is True
    assert diff_map["child_encryption"]["is_changed"] is True
    assert diff_map["child_pfs_status"]["is_changed"] is True
    assert diff_map["child_replay_window"]["is_changed"] is True
