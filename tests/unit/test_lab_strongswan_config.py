"""
TunnelTrace AI - strongSwan Config Generation Unit Tests
========================================================
Verifies mapping of cryptographic proposal suites to strongSwan/swanctl syntax,
PFS child SA proposals, and configuration hashing.
"""

from lab.agent.strongswan.config_generator import (
    CryptoProposalMapper,
    SwanctlConfigGenerator,
)
from lab.scenarios.schema import (
    CryptoProfile,
    IPVersion,
    PFSMode,
    ScenarioDefinition,
    TopologyType,
)


class TestStrongSwanConfigGenerator:
    """Tests swanctl.conf rendering logic."""

    def test_crypto_proposal_mapper_aes_gcm_pfs(self) -> None:
        proposals = CryptoProposalMapper.get_proposals(
            CryptoProfile.IKEV2_AES256GCM_DH19_PFS,
            PFSMode.ENABLED
        )
        assert "aes256gcm16-prfsha256-ecp256" in proposals["ike"]
        # Child SA proposal MUST include DH group ecp256 when PFS is enabled
        assert "aes256gcm16-ecp256" in proposals["esp"]

    def test_crypto_proposal_mapper_aes_cbc_nopfs(self) -> None:
        proposals = CryptoProposalMapper.get_proposals(
            CryptoProfile.IKEV2_AES256CBC_SHA256_DH14_NOPFS,
            PFSMode.DISABLED
        )
        assert "aes256-sha256-modp2048" in proposals["ike"]
        # Child SA proposal MUST omit DH group when PFS is disabled
        assert proposals["esp"] == "aes256-sha256"

    def test_tunnel_config_rendering(self) -> None:
        gen = SwanctlConfigGenerator()
        scenario = ScenarioDefinition(
            scenario_id="scn-test-tunnel",
            topology=TopologyType.TUNNEL_SITE_TO_SITE,
            ip_version=IPVersion.IPV4,
            crypto_profile=CryptoProfile.IKEV2_AES256GCM_DH19_PFS,
            pfs=PFSMode.ENABLED,
        )
        rendered = gen.generate_tunnel_config(
            peer_role="gw-a",
            scenario=scenario,
            local_wan_ip="198.51.100.1",
            remote_wan_ip="198.51.100.2",
            local_ts="10.10.1.0/24",
            remote_ts="10.10.2.0/24",
            psk_secret="test_lab_secret_psk"
        )
        assert "sha256" in rendered
        assert len(rendered["sha256"]) == 64
        conf = rendered["content"]
        assert "connections {" in conf
        assert "tunnel-gw-a {" in conf
        assert "local_addrs = 198.51.100.1" in conf
        assert "remote_addrs = 198.51.100.2" in conf
        assert "mode = tunnel" in conf
        assert "test_lab_secret_psk" in conf

    def test_crypto_proposal_mapper_ikev1_3des_weak(self) -> None:
        """Verify mapping of legacy weak 3DES suite."""
        proposals = CryptoProposalMapper.get_proposals(
            CryptoProfile.IKEV1_3DES_SHA1_DH2,
            PFSMode.DISABLED
        )
        assert proposals["ike"] == "3des-sha1-modp1024"
        assert proposals["esp"] == "3des-sha1"

    def test_asymmetric_peer_proposals_rendering(self) -> None:
        """Verify that Peer B receives its assigned peer_b_crypto_profile for mismatch testing."""
        from lab.scenarios.schema import ExpectedOutcome
        scenario = ScenarioDefinition(
            scenario_id="scn-mismatch-rendering",
            topology=TopologyType.TUNNEL_SITE_TO_SITE,
            ip_version=IPVersion.IPV4,
            crypto_profile=CryptoProfile.IKEV2_AES256GCM_DH19_PFS,
            peer_b_crypto_profile=CryptoProfile.IKEV2_AES256CBC_SHA256_DH14_NOPFS,
            is_negative_test=True,
            allow_insecure_suite=True,
            expected_outcome=ExpectedOutcome.EXPECTED_REJECTION,
        )
        address_plan = {
            "gw_a_wan_ip": "198.51.100.1",
            "gw_b_wan_ip": "198.51.100.2",
            "client_subnet": "10.10.1.0/24",
            "server_subnet": "10.10.2.0/24",
        }
        # Render for Peer A
        conf_a, _ = SwanctlConfigGenerator.render_peer_config(scenario, "gw_a", address_plan, "secret1")
        # Render for Peer B
        conf_b, _ = SwanctlConfigGenerator.render_peer_config(scenario, "gw_b", address_plan, "secret1")

        # Peer A must propose GCM
        assert "aes256gcm16" in conf_a
        assert "modp2048" not in conf_a

        # Peer B must require CBC/MODP-2048
        assert "aes256-sha256-modp2048" in conf_b
        assert "aes256gcm16" not in conf_b

