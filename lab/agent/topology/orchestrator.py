"""Linux Network Namespace topology provisioning for Site-to-Site Tunnel and Host-to-Host Transport modes."""

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from lab.agent.cleanup.tracker import LabResourceTracker
from lab.agent.operations.runner import SystemRunner
from lab.scenarios.schema import IPVersion, ScenarioDefinition, TopologyType

logger = logging.getLogger(__name__)


@dataclass
class TopologyResult:
    """Encapsulates created namespace names and address plan for an experiment run."""
    ns_client: str = ""
    ns_gw_a: str = ""
    ns_wan: str = ""
    ns_gw_b: str = ""
    ns_server: str = ""
    ns_peer_a: str = ""
    ns_peer_b: str = ""
    wan_capture_dev: str = "br-wan"
    wan_capture_ns: str = ""
    plaintext_dev: str = ""
    plaintext_ns: str = ""
    address_plan: Dict[str, Any] = field(default_factory=dict)

    def __getitem__(self, item: str) -> Any:
        return getattr(self, item)


class TopologyOrchestrator:
    """Provisions isolated Linux network namespaces, veth interfaces, and static routing."""

    def __init__(
        self,
        runner: Optional[SystemRunner] = None,
        tracker: Optional[LabResourceTracker] = None,
        run_id: Optional[str] = None
    ) -> None:
        self.runner = runner or SystemRunner()
        self.tracker = tracker or LabResourceTracker(runner=self.runner)
        self.run_id = run_id or self.tracker.run_id
        self.pfx = f"tt-{self.run_id}"

    def get_address_plan(self, scenario: Optional[ScenarioDefinition] = None, ip_version: Optional[IPVersion] = None) -> Dict[str, Any]:
        """Return deterministic addressing assignments for the experiment run."""
        is_ipv6 = (scenario.ip_version == IPVersion.IPV6) if scenario else (ip_version == IPVersion.IPV6)

        if is_ipv6:
            return {
                "client_ip": "fd00:10:1::10",
                "client_gw_ip": "fd00:10:1::1",
                "client_subnet": "fd00:10:1::/64",
                "client_subnet_gw": "fd00:10:1::0",
                "gw_a_wan_ip": "fd00:ba::1",
                "gw_b_wan_ip": "fd00:ba::2",
                "peer_a_wan_ip": "fd00:ba::1",
                "peer_b_wan_ip": "fd00:ba::2",
                "wan_subnet": "fd00:ba::/64",

                "server_gw_ip": "fd00:10:2::1",
                "server_ip": "fd00:10:2::10",
                "server_subnet": "fd00:10:2::/64",
                "server_subnet_gw": "fd00:10:2::0",
                "prefix_len": 64,
            }
        else:
            return {
                "client_ip": "10.10.1.10",
                "client_gw_ip": "10.10.1.1",
                "client_subnet": "10.10.1.0/24",
                "client_subnet_gw": "10.10.1.0",
                "gw_a_wan_ip": "198.51.100.1",
                "gw_b_wan_ip": "198.51.100.2",
                "peer_a_wan_ip": "198.51.100.1",
                "peer_b_wan_ip": "198.51.100.2",
                "wan_subnet": "198.51.100.0/24",
                "server_gw_ip": "10.10.2.1",
                "server_ip": "10.10.2.10",
                "server_subnet": "10.10.2.0/24",
                "server_subnet_gw": "10.10.2.0",
                "prefix_len": 24,
            }

    def setup_tunnel_topology(self, run_id: str, ip_version: IPVersion) -> TopologyResult:
        """Helper called by ExperimentRunner to create 5-namespace Site-to-Site layout."""
        self.run_id = run_id
        self.pfx = f"tt-{run_id}"
        plan = self.get_address_plan(ip_version=ip_version)
        is_ipv6 = ip_version == IPVersion.IPV6

        ns_cli = self.tracker.register_namespace(f"{self.pfx}-cli")
        ns_gwa = self.tracker.register_namespace(f"{self.pfx}-gwa")
        ns_wan = self.tracker.register_namespace(f"{self.pfx}-wan")
        ns_gwb = self.tracker.register_namespace(f"{self.pfx}-gwb")
        ns_srv = self.tracker.register_namespace(f"{self.pfx}-srv")

        # 1. Create namespaces and bring up loopbacks
        for ns in (ns_cli, ns_gwa, ns_wan, ns_gwb, ns_srv):
            self.runner.run(["ip", "netns", "add", ns])
            self.runner.run(["ip", "netns", "exec", ns, "ip", "link", "set", "lo", "up"])

        # 2. Veth links: Client <-> GW-A Private
        dev_cli = "v-cli-gw"
        dev_gwa_priv = "v-gw-cli"
        self.runner.run(["ip", "link", "add", dev_cli, "type", "veth", "peer", "name", dev_gwa_priv])
        self.runner.run(["ip", "link", "set", dev_cli, "netns", ns_cli])
        self.runner.run(["ip", "link", "set", dev_gwa_priv, "netns", ns_gwa])

        # 3. Veth links: GW-A WAN <-> WAN node
        dev_gwa_wan = "v-gwa-w"
        dev_wan_a = "v-wan-a"
        self.runner.run(["ip", "link", "add", dev_gwa_wan, "type", "veth", "peer", "name", dev_wan_a])
        self.runner.run(["ip", "link", "set", dev_gwa_wan, "netns", ns_gwa])
        self.runner.run(["ip", "link", "set", dev_wan_a, "netns", ns_wan])

        # 4. Veth links: WAN node <-> GW-B WAN
        dev_wan_b = "v-wan-b"
        dev_gwb_wan = "v-gwb-w"
        self.runner.run(["ip", "link", "add", dev_wan_b, "type", "veth", "peer", "name", dev_gwb_wan])
        self.runner.run(["ip", "link", "set", dev_wan_b, "netns", ns_wan])
        self.runner.run(["ip", "link", "set", dev_gwb_wan, "netns", ns_gwb])

        # 5. Veth links: GW-B Private <-> Server
        dev_gwb_priv = "v-gw-srv"
        dev_srv = "v-srv-gw"
        self.runner.run(["ip", "link", "add", dev_gwb_priv, "type", "veth", "peer", "name", dev_srv])
        self.runner.run(["ip", "link", "set", dev_gwb_priv, "netns", ns_gwb])
        self.runner.run(["ip", "link", "set", dev_srv, "netns", ns_srv])

        # 6. Bridge WAN interfaces inside WAN namespace
        dev_wan_br = "br-wan"
        self.runner.run(["ip", "netns", "exec", ns_wan, "ip", "link", "add", dev_wan_br, "type", "bridge"])
        self.runner.run(["ip", "netns", "exec", ns_wan, "ip", "link", "set", dev_wan_a, "master", dev_wan_br])
        self.runner.run(["ip", "netns", "exec", ns_wan, "ip", "link", "set", dev_wan_b, "master", dev_wan_br])
        self.runner.run(["ip", "netns", "exec", ns_wan, "ip", "link", "set", dev_wan_a, "up"])
        self.runner.run(["ip", "netns", "exec", ns_wan, "ip", "link", "set", dev_wan_b, "up"])
        self.runner.run(["ip", "netns", "exec", ns_wan, "ip", "link", "set", dev_wan_br, "up"])

        # 7. Configure Addressing & Routes
        plen = plan["prefix_len"]

        if is_ipv6:
            # Client
            self.runner.run(["ip", "netns", "exec", ns_cli, "ip", "-6", "addr", "add", f"{plan['client_ip']}/{plen}", "dev", dev_cli])
            self.runner.run(["ip", "netns", "exec", ns_cli, "ip", "link", "set", dev_cli, "up"])
            self.runner.run(["ip", "netns", "exec", ns_cli, "ip", "-6", "route", "add", "default", "via", plan["client_gw_ip"]])

            # GW-A
            self.runner.run(["ip", "netns", "exec", ns_gwa, "ip", "-6", "addr", "add", f"{plan['client_gw_ip']}/{plen}", "dev", dev_gwa_priv])
            self.runner.run(["ip", "netns", "exec", ns_gwa, "ip", "-6", "addr", "add", f"{plan['gw_a_wan_ip']}/{plen}", "dev", dev_gwa_wan])
            self.runner.run(["ip", "netns", "exec", ns_gwa, "ip", "link", "set", dev_gwa_priv, "up"])
            self.runner.run(["ip", "netns", "exec", ns_gwa, "ip", "link", "set", dev_gwa_wan, "up"])
            self.runner.run(["ip", "netns", "exec", ns_gwa, "sysctl", "-w", "net.ipv6.conf.all.forwarding=1"])
            self.runner.run(["ip", "netns", "exec", ns_gwa, "ip", "-6", "route", "add", plan["server_subnet"], "via", plan["gw_b_wan_ip"]])

            # GW-B
            self.runner.run(["ip", "netns", "exec", ns_gwb, "ip", "-6", "addr", "add", f"{plan['server_gw_ip']}/{plen}", "dev", dev_gwb_priv])
            self.runner.run(["ip", "netns", "exec", ns_gwb, "ip", "-6", "addr", "add", f"{plan['gw_b_wan_ip']}/{plen}", "dev", dev_gwb_wan])
            self.runner.run(["ip", "netns", "exec", ns_gwb, "ip", "link", "set", dev_gwb_priv, "up"])
            self.runner.run(["ip", "netns", "exec", ns_gwb, "ip", "link", "set", dev_gwb_wan, "up"])
            self.runner.run(["ip", "netns", "exec", ns_gwb, "sysctl", "-w", "net.ipv6.conf.all.forwarding=1"])
            self.runner.run(["ip", "netns", "exec", ns_gwb, "ip", "-6", "route", "add", plan["client_subnet"], "via", plan["gw_a_wan_ip"]])

            # Server
            self.runner.run(["ip", "netns", "exec", ns_srv, "ip", "-6", "addr", "add", f"{plan['server_ip']}/{plen}", "dev", dev_srv])
            self.runner.run(["ip", "netns", "exec", ns_srv, "ip", "link", "set", dev_srv, "up"])
            self.runner.run(["ip", "netns", "exec", ns_srv, "ip", "-6", "route", "add", "default", "via", plan["server_gw_ip"]])

        else:
            # Client
            self.runner.run(["ip", "netns", "exec", ns_cli, "ip", "addr", "add", f"{plan['client_ip']}/{plen}", "dev", dev_cli])
            self.runner.run(["ip", "netns", "exec", ns_cli, "ip", "link", "set", dev_cli, "up"])
            self.runner.run(["ip", "netns", "exec", ns_cli, "ip", "route", "add", "default", "via", plan["client_gw_ip"]])

            # GW-A
            self.runner.run(["ip", "netns", "exec", ns_gwa, "ip", "addr", "add", f"{plan['client_gw_ip']}/{plen}", "dev", dev_gwa_priv])
            self.runner.run(["ip", "netns", "exec", ns_gwa, "ip", "addr", "add", f"{plan['gw_a_wan_ip']}/{plen}", "dev", dev_gwa_wan])
            self.runner.run(["ip", "netns", "exec", ns_gwa, "ip", "link", "set", dev_gwa_priv, "up"])
            self.runner.run(["ip", "netns", "exec", ns_gwa, "ip", "link", "set", dev_gwa_wan, "up"])
            self.runner.run(["ip", "netns", "exec", ns_gwa, "sysctl", "-w", "net.ipv4.ip_forward=1"])
            self.runner.run(["ip", "netns", "exec", ns_gwa, "ip", "route", "add", plan["server_subnet"], "via", plan["gw_b_wan_ip"]])

            # GW-B
            self.runner.run(["ip", "netns", "exec", ns_gwb, "ip", "addr", "add", f"{plan['server_gw_ip']}/{plen}", "dev", dev_gwb_priv])
            self.runner.run(["ip", "netns", "exec", ns_gwb, "ip", "addr", "add", f"{plan['gw_b_wan_ip']}/{plen}", "dev", dev_gwb_wan])
            self.runner.run(["ip", "netns", "exec", ns_gwb, "ip", "link", "set", dev_gwb_priv, "up"])
            self.runner.run(["ip", "netns", "exec", ns_gwb, "ip", "link", "set", dev_gwb_wan, "up"])
            self.runner.run(["ip", "netns", "exec", ns_gwb, "sysctl", "-w", "net.ipv4.ip_forward=1"])
            self.runner.run(["ip", "netns", "exec", ns_gwb, "ip", "route", "add", plan["client_subnet"], "via", plan["gw_a_wan_ip"]])

            # Server
            self.runner.run(["ip", "netns", "exec", ns_srv, "ip", "addr", "add", f"{plan['server_ip']}/{plen}", "dev", dev_srv])
            self.runner.run(["ip", "netns", "exec", ns_srv, "ip", "link", "set", dev_srv, "up"])
            self.runner.run(["ip", "netns", "exec", ns_srv, "ip", "route", "add", "default", "via", plan["server_gw_ip"]])

        return TopologyResult(
            ns_client=ns_cli,
            ns_gw_a=ns_gwa,
            ns_wan=ns_wan,
            ns_gw_b=ns_gwb,
            ns_server=ns_srv,
            wan_capture_dev=dev_wan_br,
            wan_capture_ns=ns_wan,
            plaintext_dev=dev_cli,
            plaintext_ns=ns_cli,
            address_plan=plan
        )

    def setup_transport_topology(self, run_id: str, ip_version: IPVersion) -> TopologyResult:
        """Helper called by ExperimentRunner to create 3-namespace Host-to-Host layout."""
        self.run_id = run_id
        self.pfx = f"tt-{run_id}"
        plan = self.get_address_plan(ip_version=ip_version)
        is_ipv6 = ip_version == IPVersion.IPV6

        ns_peera = self.tracker.register_namespace(f"{self.pfx}-peera")
        ns_wan = self.tracker.register_namespace(f"{self.pfx}-wan")
        ns_peerb = self.tracker.register_namespace(f"{self.pfx}-peerb")

        for ns in (ns_peera, ns_wan, ns_peerb):
            self.runner.run(["ip", "netns", "add", ns])
            self.runner.run(["ip", "netns", "exec", ns, "ip", "link", "set", "lo", "up"])

        # Links
        dev_a_wan = "v-a-w"
        dev_wan_a = "v-wan-a"
        self.runner.run(["ip", "link", "add", dev_a_wan, "type", "veth", "peer", "name", dev_wan_a])
        self.runner.run(["ip", "link", "set", dev_a_wan, "netns", ns_peera])
        self.runner.run(["ip", "link", "set", dev_wan_a, "netns", ns_wan])

        dev_b_wan = "v-b-w"
        dev_wan_b = "v-wan-b"
        self.runner.run(["ip", "link", "add", dev_b_wan, "type", "veth", "peer", "name", dev_wan_b])
        self.runner.run(["ip", "link", "set", dev_b_wan, "netns", ns_peerb])
        self.runner.run(["ip", "link", "set", dev_wan_b, "netns", ns_wan])

        # WAN bridge
        dev_wan_br = "br-wan"
        self.runner.run(["ip", "netns", "exec", ns_wan, "ip", "link", "add", dev_wan_br, "type", "bridge"])
        self.runner.run(["ip", "netns", "exec", ns_wan, "ip", "link", "set", dev_wan_a, "master", dev_wan_br])
        self.runner.run(["ip", "netns", "exec", ns_wan, "ip", "link", "set", dev_wan_b, "master", dev_wan_br])
        self.runner.run(["ip", "netns", "exec", ns_wan, "ip", "link", "set", dev_wan_a, "up"])
        self.runner.run(["ip", "netns", "exec", ns_wan, "ip", "link", "set", dev_wan_b, "up"])
        self.runner.run(["ip", "netns", "exec", ns_wan, "ip", "link", "set", dev_wan_br, "up"])

        plen = plan["prefix_len"]
        ip_cmd = ["ip", "-6"] if is_ipv6 else ["ip"]

        # Peer A
        self.runner.run(["ip", "netns", "exec", ns_peera] + ip_cmd + ["addr", "add", f"{plan['peer_a_wan_ip']}/{plen}", "dev", dev_a_wan])
        self.runner.run(["ip", "netns", "exec", ns_peera, "ip", "link", "set", dev_a_wan, "up"])

        # Peer B
        self.runner.run(["ip", "netns", "exec", ns_peerb] + ip_cmd + ["addr", "add", f"{plan['peer_b_wan_ip']}/{plen}", "dev", dev_b_wan])
        self.runner.run(["ip", "netns", "exec", ns_peerb, "ip", "link", "set", dev_b_wan, "up"])

        return TopologyResult(
            ns_peer_a=ns_peera,
            ns_wan=ns_wan,
            ns_peer_b=ns_peerb,
            ns_gw_a=ns_peera,
            ns_gw_b=ns_peerb,
            wan_capture_dev=dev_wan_br,
            wan_capture_ns=ns_wan,
            plaintext_dev=dev_a_wan,
            plaintext_ns=ns_peera,
            address_plan=plan
        )

    def provision_tunnel_topology(self, scenario: ScenarioDefinition) -> TopologyResult:
        return self.setup_tunnel_topology(self.run_id, scenario.ip_version)

    def provision_transport_topology(self, scenario: ScenarioDefinition) -> TopologyResult:
        return self.setup_transport_topology(self.run_id, scenario.ip_version)
