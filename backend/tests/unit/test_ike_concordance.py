"""Unit tests for IKE multi-source concordance evaluation (TShark vs IKE-scan)."""

from app.protocol.ike_scan.concordance import evaluate_ike_concordance


def test_concordance_consistent():
    """Verify consistent verdict when passive capture and active probe agree."""
    passive_sas = [
        {
            "version": "IKEv1",
            "encryption_algorithm": "3DES",
            "integrity_algorithm": "SHA1",
            "dh_group": "MODP-1024",
        }
    ]
    passive_obs = [
        {
            "frame_number": 1,
            "category": "CRYPTO",
            "field_name": "ENCR_ALGORITHM",
            "normalized_value": "3DES",
        }
    ]
    active_results = [
        {
            "response_category": "RESPONDED_HANDSHAKE",
            "ike_version": "IKEv1",
            "transforms_returned": [{"encr": "3DES", "hash": "SHA1", "dh_group": "2:modp1024"}],
            "rtt_ms": 45.2,
        }
    ]

    eval_res = evaluate_ike_concordance(
        target_ip="192.168.1.50",
        passive_ike_sas=passive_sas,
        passive_observations=passive_obs,
        active_probe_results=active_results,
    )

    assert eval_res.concordance_status == "CONSISTENT"
    assert eval_res.passive_selected_cipher == "3DES"
    assert eval_res.active_accepted_cipher == "3DES"
    assert "consistent" in eval_res.summary.lower()


def test_concordance_conflict():
    """Verify conflict verdict when passive observed cipher differs from active accepted transform."""
    passive_sas = [
        {
            "version": "IKEv2",
            "encryption_algorithm": "AES-GCM-256",
            "integrity_algorithm": None,
            "dh_group": "ECP-256",
        }
    ]
    active_results = [
        {
            "response_category": "RESPONDED_HANDSHAKE",
            "ike_version": "IKEv1",
            "transforms_returned": [{"encr": "3DES", "hash": "SHA1", "dh_group": "2:modp1024"}],
            "rtt_ms": 32.1,
        }
    ]

    eval_res = evaluate_ike_concordance(
        target_ip="192.168.1.50",
        passive_ike_sas=passive_sas,
        active_probe_results=active_results,
    )

    assert eval_res.concordance_status == "CONFLICT"
    assert "mismatch" in eval_res.summary.lower()


def test_concordance_insufficient_evidence_missing_passive():
    """Verify INSUFFICIENT_EVIDENCE when passive capture lacks initial IKE negotiation."""
    passive_sas = []  # Incomplete capture (e.g. only encrypted ESP frames)
    active_results = [
        {
            "response_category": "RESPONDED_HANDSHAKE",
            "ike_version": "IKEv1",
            "transforms_returned": [{"encr": "3DES"}],
        }
    ]

    eval_res = evaluate_ike_concordance(
        target_ip="192.168.1.50",
        passive_ike_sas=passive_sas,
        active_probe_results=active_results,
    )

    assert eval_res.concordance_status == "INSUFFICIENT_EVIDENCE"
    assert "lacks initial ike negotiation" in eval_res.summary.lower()


def test_concordance_insufficient_evidence_active_no_response():
    """Verify INSUFFICIENT_EVIDENCE when active probe receives no response."""
    passive_sas = [
        {
            "version": "IKEv2",
            "encryption_algorithm": "AES-CBC-128",
        }
    ]
    active_results = [
        {
            "response_category": "NO_RESPONSE",
            "ike_version": "IKEv2",
            "transforms_returned": [],
        }
    ]

    eval_res = evaluate_ike_concordance(
        target_ip="192.168.1.50",
        passive_ike_sas=passive_sas,
        active_probe_results=active_results,
    )

    assert eval_res.concordance_status == "INSUFFICIENT_EVIDENCE"
    assert "received no response" in eval_res.summary.lower()


def test_concordance_not_comparable():
    """Verify NOT_COMPARABLE when no evidence is present for the target."""
    eval_res = evaluate_ike_concordance(
        target_ip="10.0.0.1",
        passive_ike_sas=[],
        active_probe_results=[],
    )
    assert eval_res.concordance_status == "NOT_COMPARABLE"
