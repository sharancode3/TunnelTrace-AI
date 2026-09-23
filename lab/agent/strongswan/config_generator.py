"""Deterministic strongSwan swanctl.conf configuration generator and cryptographic mapper."""

import hashlib
from typing import Any, Dict, Tuple, Optional

from lab.scenarios.schema import (
    CryptoProfile,
    EncapsulationMode,
    IKEVersion,
    IPVersion,
    PFSMode,
    ScenarioDefinition,
    TopologyType,
)


class CryptoProposals(tuple):
    """Tuple subclass allowing both index and key-based access for proposals."""
    @property
    def ike(self) -> str:
        return self[0]

    @property
    def esp(self) -> str:
        return self[1]

    def __getitem__(self, item):
        if item == "ike":
            return self[0]
        elif item == "esp":
            return self[1]
        return super().__getitem__(item)


class CryptoProposalMapper:
    """Maps abstract scenario crypto profiles to concrete strongSwan proposal strings."""

    @classmethod
    def get_proposals(cls, profile: CryptoProfile, pfs: PFSMode) -> CryptoProposals:
        """Return (ike_proposals, esp_proposals) mapped to strongSwan syntax."""
        pfs_enabled = pfs == PFSMode.ENABLED

        if profile == CryptoProfile.IKEV2_AES256GCM_DH19_PFS:
            ike = "aes256gcm16-prfsha256-ecp256,aes256-sha256-ecp256"
            esp = "aes256gcm16-ecp256,aes256-sha256-ecp256" if pfs_enabled else "aes256gcm16,aes256-sha256"
            return CryptoProposals((ike, esp))

        elif profile == CryptoProfile.IKEV2_AES128GCM_DH14_PFS:
            ike = "aes128gcm16-prfsha256-modp2048,aes128-sha256-modp2048"
            esp = "aes128gcm16-modp2048,aes128-sha256-modp2048" if pfs_enabled else "aes128gcm16,aes128-sha256"
            return CryptoProposals((ike, esp))

        elif profile == CryptoProfile.IKEV2_AES256CBC_SHA256_DH14_NOPFS:
            ike = "aes256-sha256-modp2048"
            esp = "aes256-sha256-modp2048" if pfs_enabled else "aes256-sha256"
            return CryptoProposals((ike, esp))

        elif profile == CryptoProfile.IKEV2_AES128CBC_SHA1_DH2_NOPFS:
            ike = "aes128-sha1-modp1024"
            esp = "aes128-sha1-modp1024" if pfs_enabled else "aes128-sha1"
            return CryptoProposals((ike, esp))

        elif profile == CryptoProfile.IKEV1_AES256CBC_SHA1_DH14:
            ike = "aes256-sha1-modp2048"
            esp = "aes256-sha1-modp2048" if pfs_enabled else "aes256-sha1"
            return CryptoProposals((ike, esp))

        # Fallback default
        return CryptoProposals(("aes256gcm16-prfsha256-ecp256", "aes256gcm16-ecp256"))


class SwanctlConfigGenerator:
    """Renders modular, collision-proof swanctl.conf files for Peer A and Peer B."""

    @classmethod
    def render_peer_config(
        cls,
        scenario: ScenarioDefinition,
        peer_role: str,  # "gw_a" or "gw_b" / "peer_a" or "peer_b"
        address_plan: dict[str, Any],
        psk_secret: str,
    ) -> Tuple[str, str]:
        """Render swanctl.conf for a specific peer.

        Returns:
            tuple[str, str]: (Rendered configuration text, SHA-256 digest)
        """
        norm_role = peer_role.replace("-", "_").lower()
        is_peer_a = norm_role in ("gw_a", "peer_a")
        is_ipv6 = scenario.ip_version == IPVersion.IPV6
        is_tunnel = scenario.topology == TopologyType.TUNNEL_SITE_TO_SITE
        ike_version_num = 1 if scenario.ike_version == IKEVersion.IKEV1 else 2

        # Address endpoints
        local_wan_ip = address_plan.get("gw_a_wan_ip") or address_plan.get("peer_a_wan_ip") if is_peer_a else address_plan.get("gw_b_wan_ip") or address_plan.get("peer_b_wan_ip")
        remote_wan_ip = address_plan.get("gw_b_wan_ip") or address_plan.get("peer_b_wan_ip") if is_peer_a else address_plan.get("gw_a_wan_ip") or address_plan.get("peer_a_wan_ip")

        # Subnets to protect
        if is_tunnel:
            local_ts = address_plan["client_subnet"] if is_peer_a else address_plan["server_subnet"]
            remote_ts = address_plan["server_subnet"] if is_peer_a else address_plan["client_subnet"]
            child_mode = "tunnel"
        else:
            # Transport mode host-to-host
            local_ts = f"{local_wan_ip}/128" if is_ipv6 else f"{local_wan_ip}/32"
            remote_ts = f"{remote_wan_ip}/128" if is_ipv6 else f"{remote_wan_ip}/32"
            child_mode = "transport"

        # Proposals
        ike_proposals, esp_proposals = CryptoProposalMapper.get_proposals(
            scenario.crypto_profile, scenario.pfs
        )

        encap_directive = "yes" if scenario.encapsulation == EncapsulationMode.NAT_T else "no"
        start_action = "start" if is_peer_a else "none"

        local_id = f"peer-a.tunneltrace.local" if is_peer_a else f"peer-b.tunneltrace.local"
        remote_id = f"peer-b.tunneltrace.local" if is_peer_a else f"peer-a.tunneltrace.local"

        conn_name = f"{'tunnel' if is_tunnel else 'transport'}-{peer_role.replace('_', '-')}"
        child_name = "child-sa"

        conf = f"""# ==============================================================================

# TunnelTrace AI — strongSwan swanctl.conf
# Scenario: {scenario.scenario_id} (Version {scenario.scenario_version})
# Peer Role: {peer_role}
# Mode: {child_mode} | IP: {scenario.ip_version.value} | PFS: {scenario.pfs.value}
# ==============================================================================

connections {{
    {conn_name} {{
        version = {ike_version_num}
        local_addrs = {local_wan_ip}
        remote_addrs = {remote_wan_ip}
        proposals = {ike_proposals}
        encap = {encap_directive}

        local {{
            auth = psk
            id = {local_id}
        }}
        remote {{
            auth = psk
            id = {remote_id}
        }}

        children {{
            {child_name} {{
                local_ts = {local_ts}
                remote_ts = {remote_ts}
                mode = {child_mode}
                esp_proposals = {esp_proposals}
                start_action = {start_action}
                rekey_time = 3600s
            }}
        }}
    }}
}}

secrets {{
    ike-psk {{
        id = {remote_id}
        secret = "{psk_secret}"
    }}
}}
"""
        sha256_hash = hashlib.sha256(conf.encode("utf-8")).hexdigest()
        return conf, sha256_hash

    def generate_tunnel_config(
        self,
        peer_role: str,
        scenario: ScenarioDefinition,
        local_wan_ip: str,
        remote_wan_ip: str,
        local_ts: str,
        remote_ts: str,
        psk_secret: str,
    ) -> Dict[str, str]:
        """Convenience method for Tunnel mode returning dict with content and sha256."""
        norm_role = peer_role.replace("-", "_").lower()
        is_peer_a = norm_role in ("gw_a", "peer_a")
        address_plan = {
            "gw_a_wan_ip": local_wan_ip if is_peer_a else remote_wan_ip,
            "gw_b_wan_ip": remote_wan_ip if is_peer_a else local_wan_ip,
            "client_subnet": local_ts if is_peer_a else remote_ts,
            "server_subnet": remote_ts if is_peer_a else local_ts,
        }
        content, sha = self.render_peer_config(scenario, peer_role, address_plan, psk_secret)
        return {"content": content, "sha256": sha}

    def generate_transport_config(
        self,
        peer_role: str,
        scenario: ScenarioDefinition,
        local_ip: str,
        remote_ip: str,
        psk_secret: str,
    ) -> Dict[str, str]:
        """Convenience method for Transport mode returning dict with content and sha256."""
        norm_role = peer_role.replace("-", "_").lower()
        is_peer_a = norm_role in ("gw_a", "peer_a")
        address_plan = {
            "peer_a_wan_ip": local_ip if is_peer_a else remote_ip,
            "peer_b_wan_ip": remote_ip if is_peer_a else local_ip,
        }
        content, sha = self.render_peer_config(scenario, peer_role, address_plan, psk_secret)
        return {"content": content, "sha256": sha}
