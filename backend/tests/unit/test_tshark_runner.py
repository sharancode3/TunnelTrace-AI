"""Unit tests for hardened TShark subprocess runner and ToolchainResolver."""

import pytest

from app.core.errors import ParserError
from app.protocol.tshark.binary import ToolchainResolver, get_toolchain, to_wsl_path
from app.protocol.tshark.process import TSharkProcessRunner


def test_toolchain_version_discovery():
    """Verify toolchain discovers installed TShark and Capinfos versions."""
    tc = get_toolchain()
    tshark_ver = tc.get_version("tshark")
    capinfos_ver = tc.get_version("capinfos")

    assert "TShark" in tshark_ver or "Wireshark" in tshark_ver
    assert "Capinfos" in capinfos_ver or "Wireshark" in capinfos_ver
    assert "4.6.4" in tshark_ver


def test_toolchain_to_wsl_path_conversion():
    """Verify Windows drive paths convert accurately to WSL /mnt/ format."""
    assert to_wsl_path(r"C:\SHARAN PROJECTS\foo\bar.pcap").startswith("/mnt/c/")
    assert "/mnt/c/sharan projects/foo/bar.pcap" in to_wsl_path(r"C:\SHARAN PROJECTS\foo\bar.pcap").lower()
    assert to_wsl_path("/already/unix/path") == "/already/unix/path"


def test_tshark_runner_nonexistent_file_raises():
    """Verify running dissection on a missing file raises ParserError with CAPTURE_NOT_FOUND."""
    runner = TSharkProcessRunner()
    with pytest.raises(ParserError) as exc:
        runner.run_dissection("C:/nonexistent_fake_path_1234567.pcap")
    assert exc.value.code == "CAPTURE_NOT_FOUND"


def test_tshark_runner_safe_command_vector():
    """Verify resolve_command creates safe array arguments without shell=True."""
    tc = ToolchainResolver()
    cmd = tc.resolve_command("tshark", ["-r", "test.pcap", "-n"])
    assert isinstance(cmd, list)
    assert all(isinstance(c, str) for c in cmd)
    assert "-n" in cmd
    assert "-r" in cmd
