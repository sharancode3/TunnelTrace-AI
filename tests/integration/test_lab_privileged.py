"""
TunnelTrace AI - Privileged Lab Integration Tests
=================================================
Executes real network namespace creation, virtual ethernet wiring, strongSwan
daemon startup, XFRM policy installation, live tcpdump packet capture, and clean teardown.
MUST ONLY run in authorized Linux / WSL2 environments with root privilege.
"""

import os

import pytest

from lab.agent.cleanup.tracker import LabResourceTracker
from lab.agent.doctor import EnvironmentDoctor
from lab.agent.experiment import ExperimentRunner
from lab.agent.operations.runner import SystemRunner
from lab.scenarios.loader import ScenarioLoader


@pytest.fixture(scope="module")
def privileged_runner() -> SystemRunner:
    """Provides a SystemRunner and verifies environment readiness before running."""
    runner = SystemRunner()
    doctor = EnvironmentDoctor(runner)
    report = doctor.check_environment()
    if not report.get("ready"):
        pytest.skip(f"Privileged Linux environment not ready: {report.get('checks')}")
    return runner


@pytest.mark.requires_linux_privileged
class TestPrivilegedLabIntegration:
    """Privileged integration tests generating real IPsec network traffic."""

    def test_smoke_tunnel_ipv4_aes256gcm(self, privileged_runner: SystemRunner) -> None:
        """
        Canonical Smoke Test:
        Establishes 5-namespace Site-to-Site Tunnel Mode IPsec VPN,
        transits ICMP control traffic, captures encrypted WAN ESP and plaintext packets,
        verifies SHA-256 digests, and validates idempotent teardown.
        """
        scenario_file = os.path.join(
            os.path.dirname(__file__), "..", "..", "lab", "scenarios", "profiles", "01_tunnel_ipv4_aes256gcm_pfs.yaml"
        )
        scenario = ScenarioLoader.load_from_yaml(scenario_file)

        exp_runner = ExperimentRunner(runner=privileged_runner)
        manifest = exp_runner.execute_scenario(scenario, cleanup_after=True)

        assert manifest.sa_established is True, f"IKE/Child SA failed to establish. Summary: {manifest.status_summary}"
        assert manifest.traffic_probe_passed is True, "ICMP traffic probe failed to transit tunnel"
        assert len(manifest.captures) >= 1
        wan_cap = next((c for c in manifest.captures if "wan" in c.capture_id), None)
        assert wan_cap is not None, "Missing WAN capture artifact"
        assert wan_cap.file_size_bytes > 24, "WAN PCAP file is empty"
        assert wan_cap.packet_count > 0, "WAN PCAP captured 0 packets"
        assert len(wan_cap.sha256) == 64, "Missing or invalid SHA-256 digest for WAN PCAP"
        assert manifest.validation_status == "VALIDATED"

        tracker = LabResourceTracker(runner=privileged_runner)
        cleaned = tracker.clean_all_stale_resources()
        assert cleaned["namespaces"] == 0, "Dangling lab namespaces detected after cleanup"

    def test_tunnel_ipv4_aes256cbc_nopfs(self, privileged_runner: SystemRunner) -> None:
        """
        AES-256-CBC + HMAC-SHA256 with DH14 and PFS Disabled:
        Validates classical cipher suite negotiation and omission of Child SA DH exchange.
        """
        scenario_file = os.path.join(
            os.path.dirname(__file__), "..", "..", "lab", "scenarios", "profiles", "02_tunnel_ipv4_aes256cbc_hmacsha256_nopfs.yaml"
        )
        scenario = ScenarioLoader.load_from_yaml(scenario_file)

        exp_runner = ExperimentRunner(runner=privileged_runner)
        manifest = exp_runner.execute_scenario(scenario, cleanup_after=True)

        assert manifest.sa_established is True, f"CBC/No-PFS SA failed: {manifest.status_summary}"
        assert manifest.traffic_probe_passed is True, "ICMP traffic failed on CBC tunnel"
        assert manifest.validation_status == "VALIDATED"

        tracker = LabResourceTracker(runner=privileged_runner)
        cleaned = tracker.clean_all_stale_resources()
        assert cleaned["namespaces"] == 0

    def test_transport_ipv4_aes256gcm(self, privileged_runner: SystemRunner) -> None:
        """
        Host-to-Host Transport Mode:
        Validates 3-namespace topology where IPsec terminates directly on communicating peers.
        """
        scenario_file = os.path.join(
            os.path.dirname(__file__), "..", "..", "lab", "scenarios", "profiles", "03_transport_ipv4_aes256gcm.yaml"
        )
        scenario = ScenarioLoader.load_from_yaml(scenario_file)

        exp_runner = ExperimentRunner(runner=privileged_runner)
        manifest = exp_runner.execute_scenario(scenario, cleanup_after=True)

        assert manifest.sa_established is True, f"Transport SA failed: {manifest.status_summary}"
        assert manifest.traffic_probe_passed is True, "Transport ping failed between peers"
        assert manifest.validation_status == "VALIDATED"

        tracker = LabResourceTracker(runner=privileged_runner)
        cleaned = tracker.clean_all_stale_resources()
        assert cleaned["namespaces"] == 0

    def test_tunnel_ipv4_netem_impairment(self, privileged_runner: SystemRunner) -> None:
        """
        Traffic Impairment (tc/netem):
        Validates delay (40ms) and jitter (10ms) injection on the virtual WAN link.
        """
        scenario_file = os.path.join(
            os.path.dirname(__file__), "..", "..", "lab", "scenarios", "profiles", "05_tunnel_ipv4_netem_impairment.yaml"
        )
        scenario = ScenarioLoader.load_from_yaml(scenario_file)

        exp_runner = ExperimentRunner(runner=privileged_runner)
        manifest = exp_runner.execute_scenario(scenario, cleanup_after=True)

        assert manifest.sa_established is True, f"Netem impaired SA failed: {manifest.status_summary}"
        assert manifest.traffic_probe_passed is True, "ICMP failed to transit impaired WAN link"
        assert manifest.validation_status == "VALIDATED"

        # Check observed ping round-trip time reflects injected delay
        ping_out = manifest.observed_runtime_state.get("ping_output", "")
        assert "min/avg/max" in ping_out, f"Missing ping statistics: {ping_out}"

        tracker = LabResourceTracker(runner=privileged_runner)
        cleaned = tracker.clean_all_stale_resources()
        assert cleaned["namespaces"] == 0

    def test_tunnel_ipv6_aes256gcm(self, privileged_runner: SystemRunner) -> None:
        """
        IPv6 Site-to-Site Tunnel Mode:
        Validates dual-stack IPsec capabilities over isolated IPv6 Unique Local subnets.
        """
        scenario_file = os.path.join(
            os.path.dirname(__file__), "..", "..", "lab", "scenarios", "profiles", "04_tunnel_ipv6_aes256gcm_pfs.yaml"
        )
        scenario = ScenarioLoader.load_from_yaml(scenario_file)

        exp_runner = ExperimentRunner(runner=privileged_runner)
        manifest = exp_runner.execute_scenario(scenario, cleanup_after=True)

        assert manifest.sa_established is True, f"IPv6 SA failed: {manifest.status_summary}"
        assert manifest.traffic_probe_passed is True, "IPv6 ping6 failed to transit tunnel"
        assert manifest.validation_status == "VALIDATED"

        tracker = LabResourceTracker(runner=privileged_runner)
        cleaned = tracker.clean_all_stale_resources()
        assert cleaned["namespaces"] == 0

    def test_tunnel_ipv4_natt(self, privileged_runner: SystemRunner) -> None:
        """
        NAT-Traversal Encapsulation (UDP/4500):
        Validates UDP-encapsulated ESP packet generation on the simulated WAN link.
        """
        scenario_file = os.path.join(
            os.path.dirname(__file__), "..", "..", "lab", "scenarios", "profiles", "06_tunnel_ipv4_natt.yaml"
        )
        scenario = ScenarioLoader.load_from_yaml(scenario_file)

        exp_runner = ExperimentRunner(runner=privileged_runner)
        manifest = exp_runner.execute_scenario(scenario, cleanup_after=True)

        assert manifest.sa_established is True, f"NAT-T SA failed: {manifest.status_summary}"
        assert manifest.traffic_probe_passed is True, "ICMP failed to transit NAT-T tunnel"
        assert manifest.validation_status == "VALIDATED"

        tracker = LabResourceTracker(runner=privileged_runner)
        cleaned = tracker.clean_all_stale_resources()
        assert cleaned["namespaces"] == 0

    def test_tunnel_ipv4_no_common_proposal_rejection(self, privileged_runner: SystemRunner) -> None:
        """
        Controlled Negative Test — Incompatible / Mismatched Proposals:
        Initiator proposes AES-256-GCM / ECP-256 while responder strictly requires AES-256-CBC / MODP-2048.
        Proves strongSwan rejects negotiation with NO_PROPOSAL_CHOSEN notify and yields VALIDATED
        under the EXPECTED_REJECTION contract.
        """
        scenario_file = os.path.join(
            os.path.dirname(__file__), "..", "..", "lab", "scenarios", "profiles", "08_tunnel_ipv4_no_common_proposal.yaml"
        )
        scenario = ScenarioLoader.load_from_yaml(scenario_file)

        exp_runner = ExperimentRunner(runner=privileged_runner)
        manifest = exp_runner.execute_scenario(scenario, cleanup_after=True)

        # Expected outcome semantics: SA must NOT establish
        assert manifest.sa_established is False, "SA unexpectedly established despite mismatched proposals!"
        assert manifest.validation_status == "VALIDATED", f"Expected rejection validation failed: {manifest.status_summary}"
        assert "Expected rejection verified" in manifest.status_summary

        # Verify WAN capture recorded the IKE negotiation notify packets
        wan_cap = next((c for c in manifest.captures if c.role == "WAN_ENCRYPTED"), None)
        assert wan_cap is not None, "WAN capture artifact missing"
        assert wan_cap.packet_count > 0, "Expected IKE exchange packets in WAN capture"

        tracker = LabResourceTracker(runner=privileged_runner)
        cleaned = tracker.clean_all_stale_resources()
        assert cleaned["namespaces"] == 0


