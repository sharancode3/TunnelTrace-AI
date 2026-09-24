"""Unit tests for IKE-scan subprocess runner and execution safety."""

import subprocess
from unittest.mock import MagicMock, patch

from app.protocol.ike_scan.profiles import IkeScanProfile
from app.protocol.ike_scan.runner import (
    IkeBinaryInfo,
    build_ike_scan_argv,
    detect_ike_scan_binary,
    run_ike_scan,
)
from app.protocol.ike_scan.validator import validate_ike_scope


def test_build_argv_ikev1():
    """Verify argv construction for IKEv1 Main Mode."""
    scope = validate_ike_scope(
        operator_id="op-test",
        authorization_reference="AUTH-1",
        authorization_attestation="Attestation test statement for scope",
        profile_name=IkeScanProfile.IKEV1_MAIN_MODE_DISCOVERY.value,
        target="192.168.1.10",
        port=500,
    )
    argv = build_ike_scan_argv(scope)
    assert "192.168.1.10" in argv
    assert "--destport=500" in argv
    assert "-2" not in argv
    assert any("--retry=" in a for a in argv)


def test_build_argv_ikev2_experimental():
    """Verify argv construction for experimental IKEv2."""
    scope = validate_ike_scope(
        operator_id="op-test",
        authorization_reference="AUTH-1",
        authorization_attestation="Attestation test statement for scope",
        profile_name=IkeScanProfile.IKEV2_DEFAULT_EXPERIMENTAL.value,
        target="192.168.1.10",
        port=500,
    )
    argv = build_ike_scan_argv(scope)
    assert "-2" in argv
    assert "192.168.1.10" in argv


def test_runner_returns_tool_unavailable_when_missing():
    """Verify runner handles missing binary gracefully without running subprocess."""
    scope = validate_ike_scope(
        operator_id="op-test",
        authorization_reference="AUTH-1",
        authorization_attestation="Attestation test statement for scope",
        profile_name=IkeScanProfile.IKEV1_MAIN_MODE_DISCOVERY.value,
        target="192.168.1.10",
        port=500,
    )
    with patch("app.protocol.ike_scan.runner.detect_ike_scan_binary") as mock_detect:
        mock_detect.return_value = IkeBinaryInfo(
            is_available=False,
            error_message="ike-scan executable not found",
        )
        res = run_ike_scan(scope)
        assert res.status == "TOOL_UNAVAILABLE"
        assert res.tool_version is None
        assert "not found" in (res.diagnostic_message or "")


def test_runner_executes_mocked_subprocess():
    """Verify runner executes subprocess with shell=False when binary is available."""
    scope = validate_ike_scope(
        operator_id="op-test",
        authorization_reference="AUTH-1",
        authorization_attestation="Attestation test statement for scope",
        profile_name=IkeScanProfile.IKEV1_MAIN_MODE_DISCOVERY.value,
        target="192.168.1.10",
        port=500,
    )
    canned_out = "192.168.1.10\tMain Mode Handshake returned\nEnding ike-scan: 1 returned handshake; 0 returned notify"

    with patch("app.protocol.ike_scan.runner.detect_ike_scan_binary") as mock_detect, \
         patch("subprocess.run") as mock_run:
        mock_detect.return_value = IkeBinaryInfo(
            is_available=True,
            path="/usr/bin/ike-scan",
            version="ike-scan 1.9",
        )
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=canned_out,
            stderr="",
        )

        res = run_ike_scan(scope)
        assert res.status == "COMPLETED"
        assert res.exit_code == 0
        assert res.output_sha256 is not None
        assert res.output_bytes_count > 0
        assert res.tool_version == "ike-scan 1.9"

        # Assert shell=False was enforced
        _, kwargs = mock_run.call_args
        assert kwargs.get("shell") is False


def test_runner_handles_timeout():
    """Verify runner handles TimeoutExpired cleanly."""
    scope = validate_ike_scope(
        operator_id="op-test",
        authorization_reference="AUTH-1",
        authorization_attestation="Attestation test statement for scope",
        profile_name=IkeScanProfile.IKEV1_MAIN_MODE_DISCOVERY.value,
        target="192.168.1.10",
        port=500,
    )
    with patch("app.protocol.ike_scan.runner.detect_ike_scan_binary") as mock_detect, \
         patch("subprocess.run") as mock_run:
        mock_detect.return_value = IkeBinaryInfo(
            is_available=True,
            path="/usr/bin/ike-scan",
            version="ike-scan 1.9",
        )
        mock_run.side_effect = subprocess.TimeoutExpired(cmd=["ike-scan"], timeout=15.0)

        res = run_ike_scan(scope)
        assert res.status == "CANCELLED"
        assert "timed out" in (res.diagnostic_message or "")
