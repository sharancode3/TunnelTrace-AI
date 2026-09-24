"""Unit tests for subprocess runner isolation, argv construction, and bounds enforcement."""

import subprocess
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from app.discovery.profiles import DiscoveryProfile
from app.discovery.runner import (
    ExecutionResult,
    NmapBinaryInfo,
    _sanitize_diagnostic,
    build_nmap_argv,
    detect_nmap_binary,
    run_discovery_scan,
)
from app.discovery.validator import validate_scope_request


def test_build_nmap_argv_safe_array():
    """Ensure argv is an un-interpolated list of arguments with exact flags and no shell concatenation."""
    scope = validate_scope_request(
        operator_id="op-1",
        authorization_reference="AUTH-REF-1",
        authorization_attestation="Approved scope for testing and discovery verification.",
        profile_name="IKE_SERVICE_DISCOVERY",
        requested_targets=["10.0.0.1", "10.0.0.2"],
        permitted_ports=[500, 4500],
    )
    argv = build_nmap_argv(
        binary_path="C:\\bin\\nmap.exe",
        scope=scope,
        output_xml_path="C:\\tmp\\out.xml",
        rate_limit=50,
    )

    # Invariants:
    # 1. First element is binary path
    assert argv[0] == "C:\\bin\\nmap.exe"
    # 2. Contains safe UDP flags
    assert "-sU" in argv
    assert "-Pn" in argv
    assert "-n" in argv
    # 3. Contains rate limit and ports
    assert "--max-rate" in argv
    idx_rate = argv.index("--max-rate")
    assert argv[idx_rate + 1] == "50"
    assert "-p" in argv
    idx_p = argv.index("-p")
    assert argv[idx_p + 1] == "500,4500"
    # 4. XML output argument
    assert "-oX" in argv
    assert argv[argv.index("-oX") + 1] == "C:\\tmp\\out.xml"
    # 5. Exactly the canonical targets
    assert argv[-2:] == ["10.0.0.1", "10.0.0.2"]


def test_detect_nmap_binary_missing():
    """Ensure detection returns is_available=False cleanly when binary does not exist."""
    with patch("shutil.which", return_value=None):
        info = detect_nmap_binary()
        assert info.is_available is False
        assert "not found" in info.error_message


def test_runner_tool_unavailable_when_missing():
    """Ensure run_discovery_scan immediately returns TOOL_UNAVAILABLE status without running subprocess."""
    scope = validate_scope_request(
        operator_id="op-1",
        authorization_reference="AUTH-REF-1",
        authorization_attestation="Approved scope for testing and discovery verification.",
        profile_name="IKE_SERVICE_DISCOVERY",
        requested_targets=["127.0.0.1"],
    )

    with patch("app.discovery.runner.detect_nmap_binary") as mock_detect, \
         patch("subprocess.Popen") as mock_popen:
        mock_detect.return_value = NmapBinaryInfo(
            is_available=False,
            error_message="Nmap executable not found on host.",
        )

        res = run_discovery_scan(
            job_id=uuid.uuid4(),
            scope=scope,
        )

        assert res.status == "TOOL_UNAVAILABLE"
        assert "not found" in res.diagnostic_message
        mock_popen.assert_not_called()


def test_runner_timeout_cancels_and_terminates():
    """Ensure process timeout cancels scan and terminates process tree."""
    scope = validate_scope_request(
        operator_id="op-1",
        authorization_reference="AUTH-REF-1",
        authorization_attestation="Approved scope for testing and discovery verification.",
        profile_name="IKE_SERVICE_DISCOVERY",
        requested_targets=["127.0.0.1"],
    )

    mock_proc = MagicMock()
    mock_proc.pid = 9999
    mock_proc.communicate.side_effect = subprocess.TimeoutExpired(cmd=["nmap"], timeout=1.0)

    with patch("app.discovery.runner.detect_nmap_binary") as mock_detect, \
         patch("subprocess.Popen", return_value=mock_proc), \
         patch("app.discovery.runner._kill_process_tree") as mock_kill:
        mock_detect.return_value = NmapBinaryInfo(
            is_available=True,
            path="C:\\bin\\nmap.exe",
            version="7.94",
        )

        res = run_discovery_scan(
            job_id=uuid.uuid4(),
            scope=scope,
            timeout_sec=1.0,
        )

        assert res.status == "CANCELLED"
        assert "exceeded hard timeout" in res.diagnostic_message
        mock_kill.assert_called_once_with(mock_proc)


def test_runner_nonzero_exit_code_sanitizes_stderr():
    """Ensure non-zero exit code captures sanitized stderr and redacts sensitive filesystem paths."""
    scope = validate_scope_request(
        operator_id="op-1",
        authorization_reference="AUTH-REF-1",
        authorization_attestation="Approved scope for testing and discovery verification.",
        profile_name="IKE_SERVICE_DISCOVERY",
        requested_targets=["127.0.0.1"],
    )

    mock_proc = MagicMock()
    mock_proc.returncode = 1
    mock_proc.communicate.return_value = (
        "",
        "Error: failed to open C:\\Users\\secret_admin\\AppData\\Local\\nmap.log: permission denied",
    )

    with patch("app.discovery.runner.detect_nmap_binary") as mock_detect, \
         patch("subprocess.Popen", return_value=mock_proc):
        mock_detect.return_value = NmapBinaryInfo(
            is_available=True,
            path="C:\\bin\\nmap.exe",
            version="7.94",
        )

        res = run_discovery_scan(
            job_id=uuid.uuid4(),
            scope=scope,
        )

        assert res.status == "FAILED"
        assert res.exit_code == 1
        assert "secret_admin" not in res.diagnostic_message
        assert "[REDACTED_PATH]" in res.diagnostic_message


def test_sanitize_diagnostic_redaction():
    """Verify diagnostic sanitizer redacts Windows and POSIX absolute paths."""
    raw = "Failed at C:\\Program Files\\Nmap\\nmap.exe and /etc/shadow or /var/log/nmap.log"
    clean = _sanitize_diagnostic(raw)
    assert "C:\\Program Files" not in clean
    assert "/etc/shadow" not in clean
    assert "[REDACTED_PATH]" in clean
