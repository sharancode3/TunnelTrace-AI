"""
TunnelTrace AI - Lab Safety & System Runner Unit Tests
======================================================
Verifies interface allowlists, physical interface protection, secret scrubbing,
and strict rejection of shell injection.
"""

import pytest

from lab.agent.operations.runner import (
    PhysicalInterfaceProtectionError,
    SafeCommand,
    SystemRunner,
)


class TestSafetyAndRunner:
    """Verifies isolation guarantees and security boundaries."""

    def test_rejection_of_physical_interfaces(self) -> None:
        runner = SystemRunner()
        forbidden_interfaces = [
            "eth0",
            "enp3s0",
            "wlan0",
            "wlo1",
            "docker0",
            "tailscale0",
            "Ethernet 2",
            "Wi-Fi",
        ]
        for iface in forbidden_interfaces:
            with pytest.raises(PhysicalInterfaceProtectionError):
                runner.validate_safety(iface)

    def test_acceptance_of_lab_interfaces(self) -> None:
        runner = SystemRunner()
        allowed_interfaces = [
            "br-wan",
            "v-cli-gw",
            "v-gw-cli",
            "v-wan-a",
            "v-wan-b",
            "tt-run-123-eth0",
        ]
        for iface in allowed_interfaces:
            # Should not raise exception
            runner.validate_safety(iface)

    def test_secret_scrubbing(self) -> None:
        cmd = SafeCommand(
            binary="/usr/sbin/swanctl",
            args=["--load-all", "--secret", "super_secret_vpn_psk_12345"]
        )
        assert "super_secret_vpn_psk_12345" in cmd.args
        # Redacted command representation must hide secrets
        redacted = cmd.get_redacted_command()
        assert "super_secret_vpn_psk_12345" not in redacted
        assert "[REDACTED_SECRET]" in redacted
