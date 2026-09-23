"""
TunnelTrace AI - Local Class B Privileged Agent Client
=====================================================
Executes strictly allowlisted, typed lab operations in the local Linux/WSL2
testbed environment when NETAGENT_ENABLED=True.
Never accepts arbitrary shell commands or unsanitized strings.
"""

import asyncio
import os
from typing import Any

from lab.agent.capture.manager import CaptureManager
from lab.agent.cleanup.tracker import LabResourceTracker
from lab.agent.doctor import EnvironmentDoctor
from lab.agent.operations.runner import SystemRunner
from lab.scenarios.loader import ScenarioLoader

from app.integrations.privileged_agent.base import (
    AgentStatus,
    AgentStatusResponse,
    PrivilegedAgentClient,
    PrivilegedAgentUnavailableError,
)


class LocalPrivilegedAgentClient(PrivilegedAgentClient):
    """Executes typed Class B operations directly on the local Linux/WSL2 testbed."""

    # Explicit allowlist of permissible actions
    ALLOWED_ACTIONS = {
        "LAB_DOCTOR",
        "LIST_SCENARIOS",
        "RUN_SCENARIO",
        "CLEAN_STALE",
        "LIST_INTERFACES",
        "START_LIVE_CAPTURE",
        "STOP_LIVE_CAPTURE",
        "GET_LIVE_CAPTURE_STATUS",
    }

    # Allowlisted interface prefixes for live capture
    ALLOWLISTED_INTERFACE_PREFIXES = ("br-", "v-", "lab-", "tt-")
    ALLOWLISTED_INTERFACES = {"lo"}

    def __init__(self, enabled: bool = True, endpoint: str = "local://unix-ns") -> None:
        self.enabled = enabled
        self.endpoint = endpoint
        self.runner = SystemRunner()
        self.doctor = EnvironmentDoctor(self.runner)
        self.capture_mgr = CaptureManager(self.runner)

    async def get_status(self) -> AgentStatusResponse:
        """Runs the doctor pre-flight probe to determine agent readiness."""
        if not self.enabled:
            return AgentStatusResponse(
                status=AgentStatus.DOWN,
                available=False,
                configured=False,
                endpoint=self.endpoint,
                message="Privileged agent is explicitly disabled in configuration."
            )

        # Run non-blocking probe in thread
        doc_report = await asyncio.to_thread(self.doctor.check_environment)
        is_ready = doc_report.get("ready", False)

        return AgentStatusResponse(
            status=AgentStatus.UP if is_ready else AgentStatus.DOWN,
            available=is_ready,
            configured=True,
            endpoint=self.endpoint,
            message=f"Environment ready: {is_ready}. Linux Kernel: {doc_report.get('kernel')}"
        )

    async def ping(self) -> bool:
        """Pings the underlying Linux kernel environment."""
        if not self.enabled:
            return False
        try:
            res = await asyncio.to_thread(self.runner.run_raw, ["true"], None, True, 2.0)
            return res.returncode == 0
        except Exception:
            return False

    async def execute_action(self, action: str, params: dict[str, Any]) -> dict[str, Any]:
        """Executes a typed, allowlisted lab action."""
        if not self.enabled:
            raise PrivilegedAgentUnavailableError("Privileged agent is disabled.")

        if action not in self.ALLOWED_ACTIONS:
            raise ValueError(f"Action '{action}' is not in the privileged allowlist: {self.ALLOWED_ACTIONS}")

        if action == "LAB_DOCTOR":
            return await asyncio.to_thread(self.doctor.check_environment)

        elif action == "CLEAN_STALE":
            return await asyncio.to_thread(LabResourceTracker.clean_all_stale_resources, self.runner)

        elif action == "LIST_SCENARIOS":
            profiles_dir = os.path.join(os.path.dirname(__file__), "..", "..", "..", "..", "lab", "scenarios", "profiles")
            profiles_dir = os.path.abspath(profiles_dir)
            scenarios = []
            if os.path.isdir(profiles_dir):
                for f in sorted(os.listdir(profiles_dir)):
                    if f.endswith(".yaml") or f.endswith(".yml"):
                        try:
                            sc = ScenarioLoader.load_from_yaml(os.path.join(profiles_dir, f))
                            scenarios.append({
                                "file": f,
                                "scenario_id": sc.scenario_id,
                                "topology": sc.topology.value,
                                "ip_version": sc.ip_version.value,
                                "crypto": sc.crypto_profile.value,
                                "sha256": sc.sha256_hash
                            })
                        except Exception:
                            pass
            return {"scenarios": scenarios}

        elif action == "LIST_INTERFACES":
            import json

            from lab.agent.operations.runner import PROTECTED_HOST_INTERFACES
            interfaces = []
            try:
                res = await asyncio.to_thread(self.runner.run_raw, [self.runner.ip_bin, "-j", "link"], check=False)
                if res.returncode == 0:
                    links = json.loads(res.stdout)
                    for link in links:
                        iface_name = link.get("ifname", "")
                        if iface_name in PROTECTED_HOST_INTERFACES:
                            continue
                        is_allowed = (
                            iface_name in self.ALLOWLISTED_INTERFACES
                            or any(iface_name.startswith(p) for p in self.ALLOWLISTED_INTERFACE_PREFIXES)
                        )
                        if is_allowed:
                            interfaces.append({
                                "interface_id": iface_name,
                                "display_name": f"Lab Interface ({iface_name})",
                                "type": link.get("link_type", "unknown"),
                                "capture_allowed": True,
                                "lab_owned": iface_name != "lo",
                                "operstate": link.get("operstate", "UNKNOWN"),
                            })
            except Exception:
                pass

            if not interfaces:
                interfaces.append({
                    "interface_id": "br-wan",
                    "display_name": "Lab WAN Bridge (br-wan)",
                    "type": "bridge",
                    "capture_allowed": True,
                    "lab_owned": True,
                    "operstate": "DOWN",
                })
                interfaces.append({
                    "interface_id": "lo",
                    "display_name": "Loopback (lo)",
                    "type": "loopback",
                    "capture_allowed": True,
                    "lab_owned": False,
                    "operstate": "UP",
                })
            return {"interfaces": interfaces}

        elif action == "START_LIVE_CAPTURE":
            from lab.agent.operations.runner import PROTECTED_HOST_INTERFACES
            session_id = params.get("session_id")
            interface = params.get("interface")
            output_pcap = params.get("output_pcap")
            bpf_filter = params.get("bpf_filter") or "udp port 500 or udp port 4500 or esp or ah"

            if not session_id or not interface or not output_pcap:
                raise ValueError("Missing required parameters for START_LIVE_CAPTURE")

            if interface in PROTECTED_HOST_INTERFACES:
                raise PermissionError(f"Access denied: Physical host interface '{interface}' is strictly protected.")

            is_allowed = (
                interface in self.ALLOWLISTED_INTERFACES
                or any(interface.startswith(p) for p in self.ALLOWLISTED_INTERFACE_PREFIXES)
            )
            if not is_allowed:
                raise ValueError(f"Interface '{interface}' is not in the authorized capture allowlist.")

            result = await asyncio.to_thread(
                self.capture_mgr.start_capture,
                capture_id=session_id,
                interface=interface,
                output_pcap_path=output_pcap,
                bpf_filter=bpf_filter,
            )
            return result

        elif action == "STOP_LIVE_CAPTURE":
            session_id = params.get("session_id")
            if not session_id:
                raise ValueError("Missing 'session_id' parameter for STOP_LIVE_CAPTURE")

            result = await asyncio.to_thread(self.capture_mgr.stop_capture, session_id)
            return result

        elif action == "GET_LIVE_CAPTURE_STATUS":
            import time
            session_id = params.get("session_id")
            if not session_id:
                raise ValueError("Missing 'session_id' parameter for GET_LIVE_CAPTURE_STATUS")

            cap_info = self.capture_mgr.active_captures.get(session_id)
            if not cap_info:
                return {"session_id": session_id, "status": "STOPPED", "active": False}
            return {
                "session_id": session_id,
                "status": "CAPTURING",
                "active": True,
                "interface": cap_info["interface"],
                "duration_sec": round(time.time() - cap_info["started_at"], 2),
            }

        raise RuntimeError(f"Unhandled allowlisted action: {action}")
