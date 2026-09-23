"""
TunnelTrace AI - Lab Scenario Schema & Loader Unit Tests
========================================================
Validates strict schema enforcement, boundary conditions, and path traversal rejection.
"""

import pytest
from pydantic import ValidationError

from lab.scenarios.loader import (
    ScenarioLoader,
    ScenarioLoadError,
)
from lab.scenarios.schema import (
    CryptoProfile,
    EncapsulationMode,
    IKEVersion,
    IPVersion,
    NetemConfig,
    PFSMode,
    ScenarioDefinition,
    TopologyType,
)


class TestScenarioSchema:
    """Tests Pydantic scenario schema validation."""

    def test_valid_scenario_creation(self) -> None:
        sc = ScenarioDefinition(
            scenario_id="scn-valid-tunnel",
            topology=TopologyType.TUNNEL_SITE_TO_SITE,
            ip_version=IPVersion.IPV4,
            ike_version=IKEVersion.IKEV2,
            crypto_profile=CryptoProfile.IKEV2_AES256GCM_DH19_PFS,
            pfs=PFSMode.ENABLED,
            encapsulation=EncapsulationMode.NATIVE_ESP,
        )
        assert sc.scenario_id == "scn-valid-tunnel"
        assert sc.topology == TopologyType.TUNNEL_SITE_TO_SITE
        assert sc.netem.has_impairment() is False

    def test_invalid_scenario_id_characters(self) -> None:
        with pytest.raises(ValidationError):
            ScenarioDefinition(
                scenario_id="invalid/id with spaces; rm -rf",
                topology=TopologyType.TUNNEL_SITE_TO_SITE,
                crypto_profile=CryptoProfile.IKEV2_AES256GCM_DH19_PFS,
            )

    def test_invalid_scenario_id_length(self) -> None:
        with pytest.raises(ValidationError):
            ScenarioDefinition(
                scenario_id="a" * 65,
                topology=TopologyType.TUNNEL_SITE_TO_SITE,
                crypto_profile=CryptoProfile.IKEV2_AES256GCM_DH19_PFS,
            )

    def test_invalid_topology_rejection(self) -> None:
        with pytest.raises(ValidationError):
            ScenarioDefinition(
                scenario_id="scn-test",
                topology="INVALID_TOPOLOGY", # type: ignore
                crypto_profile=CryptoProfile.IKEV2_AES256GCM_DH19_PFS,
            )

    def test_invalid_ip_version_rejection(self) -> None:
        with pytest.raises(ValidationError):
            ScenarioDefinition(
                scenario_id="scn-test",
                ip_version="IPV5", # type: ignore
                crypto_profile=CryptoProfile.IKEV2_AES256GCM_DH19_PFS,
            )

    def test_invalid_crypto_profile_rejection(self) -> None:
        with pytest.raises(ValidationError):
            ScenarioDefinition(
                scenario_id="scn-test",
                crypto_profile="DES_MD5_NONE", # type: ignore
            )

    def test_netem_boundaries_and_jitter_validation(self) -> None:
        # Delay > 2000ms rejected
        with pytest.raises(ValidationError):
            NetemConfig(delay_ms=2500.0)

        # Loss > 50% rejected
        with pytest.raises(ValidationError):
            NetemConfig(loss_pct=55.0)

        # Jitter without delay rejected
        with pytest.raises(ValidationError):
            NetemConfig(delay_ms=0.0, jitter_ms=10.0)

        # Jitter exceeding baseline delay rejected
        with pytest.raises(ValidationError):
            NetemConfig(delay_ms=20.0, jitter_ms=25.0)

        # Valid netem config
        valid_netem = NetemConfig(delay_ms=50.0, jitter_ms=10.0, loss_pct=1.5, rate_kbit=10000)
        assert valid_netem.has_impairment() is True
        assert valid_netem.rate_kbps == 10000


class TestScenarioLoader:
    """Tests safe YAML scenario loading and hashing."""

    def test_load_all_built_in_profiles(self) -> None:
        import os

        from lab.scenarios.loader import ScenarioLoader
        profiles_dir = os.path.join(os.path.dirname(__file__), "..", "..", "lab", "scenarios", "profiles")
        profiles_dir = os.path.abspath(profiles_dir)

        count = 0
        for f in os.listdir(profiles_dir):
            if f.endswith(".yaml"):
                sc = ScenarioLoader.load_from_yaml(os.path.join(profiles_dir, f))
                assert sc.scenario_id.startswith("scn-")
                assert sc.sha256_hash is not None
                assert len(sc.sha256_hash) == 64
                count += 1
        assert count == 6

    def test_loader_nonexistent_file(self) -> None:
        with pytest.raises(ScenarioLoadError):
            ScenarioLoader.load_from_yaml("nonexistent_path_xyz.yaml")

    def test_loader_malformed_yaml(self) -> None:
        with pytest.raises(ScenarioLoadError):
            ScenarioLoader.load_from_yaml("this is not yaml: [}}")
