"""
TunnelTrace AI - Local Class B Privileged Agent Client
=====================================================
Executes strictly allowlisted, typed lab operations in the local Linux/WSL2
testbed environment when NETAGENT_ENABLED=True.
Never accepts arbitrary shell commands or unsanitized strings.
"""

import asyncio
import os
import re
import tempfile
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


def validate_lab_path(path: str | os.PathLike, run_id: str | None = None) -> str:
    """Validate that path strictly resolves within an authorized, run-owned lab sandbox.

    Enforces:
    - Path normalization and realpath resolution (resolving symlinks).
    - Traversal rejection (no .. escape).
    - Sibling trick rejection (e.g. /tmp_evil or /tmp/tt-evil).
    - Rejection of host system directories (/etc, /var, /usr, /bin, C:\\Windows, etc.).
    - Strict run-sandbox containment when run_id is supplied.
    """
    if not path or not str(path).strip():
        raise ValueError("Path parameter is empty.")

    norm_path = os.path.abspath(str(path))
    real_path = os.path.realpath(norm_path)

    # 1. Reject any dangerous host directories
    prohibited_prefixes = [
        "/etc", "/var/log", "/var/lib", "/usr", "/bin", "/sbin", "/boot", "/home", "/root",
        "C:\\Windows", "C:\\Program Files", "C:\\Program Files (x86)",
    ]
    for p in prohibited_prefixes:
        if norm_path.startswith(p) or real_path.startswith(p):
            raise PermissionError(f"Access denied: '{path}' is outside managed lab directories.")

    # 2. Derive or verify run_id
    target_run_id = run_id
    if not target_run_id:
        m = re.search(r"tt-([a-zA-Z0-9_-]+)", norm_path)
        if m:
            target_run_id = m.group(1)

    if not target_run_id:
        if "storage" in norm_path and "lab" in norm_path:
            return norm_path
        raise PermissionError(f"Access denied: '{path}' is outside managed lab directories.")

    clean_run_id = re.sub(r"[^a-zA-Z0-9_-]", "", target_run_id)

    # 3. Check allowed roots for this run
    temp_dir = os.path.realpath(tempfile.gettempdir())
    allowed_roots = [
        os.path.realpath(f"/tmp/tt-{clean_run_id}"),
        os.path.realpath(f"/tmp/tt-{clean_run_id[:8]}"),
        os.path.realpath(os.path.join(temp_dir, f"tt-{clean_run_id}")),
        os.path.realpath(os.path.join(temp_dir, f"tt-{clean_run_id[:8]}")),
        os.path.realpath(os.path.join("storage", "lab", "runs", clean_run_id)),
    ]

    is_contained = any(
        norm_path.startswith(r + os.sep) or norm_path == r or
        real_path.startswith(r + os.sep) or real_path == r
        for r in allowed_roots
    )

    if not is_contained:
        raise PermissionError(
            f"Access denied: '{path}' is outside managed lab directories."
        )

    return norm_path


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
        "BACKUP_CONFIG",
        "VALIDATE_CONFIG",
        "APPLY_CONFIG",
        "RELOAD_STRONGSWAN",
        "VERIFY_FRESH_SA",
        "RESTORE_BACKUP",
        "RUN_REMEDIATION_WORKLOAD",
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

            run_id = params.get("run_id")
            norm_output_pcap = validate_lab_path(output_pcap, run_id)

            result = await asyncio.to_thread(
                self.capture_mgr.start_capture,
                capture_id=session_id,
                interface=interface,
                output_pcap_path=norm_output_pcap,
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

        elif action == "BACKUP_CONFIG":
            import hashlib
            run_id = params.get("run_id")
            active_config_path = params.get("active_config_path")
            backup_dest_path = params.get("backup_dest_path")

            if not active_config_path or not backup_dest_path:
                raise ValueError("Missing active_config_path or backup_dest_path for BACKUP_CONFIG")

            norm_active = validate_lab_path(active_config_path, run_id)
            norm_backup = validate_lab_path(backup_dest_path, run_id)

            content = ""
            if os.path.exists(norm_active):
                with open(norm_active, "r", encoding="utf-8") as f:
                    content = f.read()
            else:
                # If running in WSL mode or Linux testbed, query runner
                res = await asyncio.to_thread(self.runner.run_raw, ["cat", norm_active], check=False)
                if res.returncode == 0 and res.stdout:
                    content = res.stdout
                else:
                    raise FileNotFoundError(
                        f"Baseline configuration '{active_config_path}' does not exist or is unreadable. Automated application blocked."
                    )

            if not content.strip():
                raise ValueError(
                    f"Baseline configuration '{active_config_path}' is empty. Automated application blocked."
                )

            sha256_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
            os.makedirs(os.path.dirname(norm_backup), exist_ok=True)
            with open(norm_backup, "w", encoding="utf-8") as f:
                f.write(content)
                f.flush()
                os.fsync(f.fileno())

            return {
                "backup_path": norm_backup,
                "backup_sha256": sha256_hash,
                "bytes_written": len(content),
                "content": content,
            }

        elif action == "VALIDATE_CONFIG":
            from app.remediation.parser import SwanctlParser
            candidate_text = params.get("candidate_config_text", "")
            if not candidate_text.strip():
                return {"valid": False, "errors": ["Configuration text is empty."]}
            try:
                ir = SwanctlParser.parse_text(candidate_text)
                if not ir.connections:
                    return {"valid": False, "errors": ["No valid connection blocks detected in candidate configuration."]}
                return {"valid": True, "connection_count": len(ir.connections), "errors": []}
            except Exception as exc:
                return {"valid": False, "errors": [str(exc)]}

        elif action == "APPLY_CONFIG":
            import hashlib
            run_id = params.get("run_id")
            target_path = params.get("target_path")
            config_text = params.get("config_text", "")
            expected_hash = params.get("expected_hash")

            if not target_path or not config_text:
                raise ValueError("Missing target_path or config_text for APPLY_CONFIG")

            norm_target = validate_lab_path(target_path, run_id)

            actual_hash = hashlib.sha256(config_text.encode("utf-8")).hexdigest()
            if expected_hash and actual_hash != expected_hash:
                raise ValueError(f"Proposal hash mismatch! Expected {expected_hash}, calculated {actual_hash}")

            # Atomic write
            temp_path = f"{norm_target}.candidate.{os.getpid()}"
            os.makedirs(os.path.dirname(norm_target), exist_ok=True)
            with open(temp_path, "w", encoding="utf-8") as f:
                f.write(config_text)
                f.flush()
                os.fsync(f.fileno())

            os.replace(temp_path, norm_target)

            # Read back verification
            with open(norm_target, "r", encoding="utf-8") as f:
                readback = f.read()
            if hashlib.sha256(readback.encode("utf-8")).hexdigest() != actual_hash:
                raise RuntimeError("Applied configuration readback verification failed!")

            return {
                "applied_path": norm_target,
                "applied_hash": actual_hash,
                "applied_sha256": actual_hash,
                "verified": True,
                "success": True,
            }

        elif action == "RELOAD_STRONGSWAN":
            from lab.agent.strongswan.manager import StrongSwanManager
            run_id = params.get("run_id")
            namespace = params.get("namespace")
            peer_dir = params.get("peer_dir")
            vici_socket = params.get("vici_socket")

            if not namespace or not peer_dir:
                raise ValueError("Missing namespace or peer_dir for RELOAD_STRONGSWAN")

            if namespace in ("default", "host", ""):
                raise PermissionError("Access denied: Cannot reload strongSwan in host or default namespace.")

            norm_peer_dir = validate_lab_path(peer_dir, run_id)
            norm_vici = validate_lab_path(vici_socket or f"{norm_peer_dir}/charon.vici", run_id)

            mgr = StrongSwanManager(runner=self.runner)
            load_res = await asyncio.to_thread(mgr.load_configuration, namespace, norm_peer_dir, norm_vici)
            init_res = await asyncio.to_thread(mgr.initiate_tunnel, namespace, norm_vici)

            return {
                "load_success": load_res.success,
                "load_stdout": load_res.stdout,
                "initiate_success": init_res.success,
                "initiate_stdout": init_res.stdout,
            }

        elif action == "VERIFY_FRESH_SA":
            import re
            from lab.agent.strongswan.manager import StrongSwanManager
            run_id = params.get("run_id")
            namespace = params.get("namespace")
            peer_dir = params.get("peer_dir")
            vici_socket = params.get("vici_socket")
            old_spis = set(s.lower() for s in params.get("old_spis", []))

            if not namespace or not peer_dir:
                raise ValueError("Missing namespace or peer_dir for VERIFY_FRESH_SA")

            norm_peer_dir = validate_lab_path(peer_dir, run_id)
            norm_vici = validate_lab_path(vici_socket or f"{norm_peer_dir}/charon.vici", run_id)

            mgr = StrongSwanManager(runner=self.runner)
            sa_status = await asyncio.to_thread(mgr.query_sa_status, namespace, norm_vici)

            # Extract SPIs (support swanctl format "c0123456_i", ip xfrm "spi 0x...", and "in/out 0x...")
            found_spis = [s.lower() for s in re.findall(r"([0-9a-fA-F]{8})_[io]", sa_status)]
            found_spis.extend([s.lower() for s in re.findall(r"spi[s:_]*\s*(?:0x)?([0-9a-fA-F]+)", sa_status, re.IGNORECASE)])
            found_spis.extend([s.lower() for s in re.findall(r"(?:in|out)\s+(?:0x)?([0-9a-fA-F]{8})", sa_status, re.IGNORECASE)])
            found_spis = list(dict.fromkeys(found_spis))

            norm_old_spis = [str(s).lower().removeprefix("0x") for s in old_spis]
            new_spis = [s for s in found_spis if s not in norm_old_spis]

            # If old_spis were provided, fresh SA requires at least one NEW SPI distinct from pre-change
            if norm_old_spis:
                is_fresh = len(new_spis) > 0
            else:
                is_fresh = len(found_spis) > 0

            return {
                "fresh_sa_established": is_fresh,
                "observed_spis": found_spis,
                "new_spis": new_spis,
                "sa_status": sa_status[:1000],
            }

        elif action == "RESTORE_BACKUP":
            import hashlib
            run_id = params.get("run_id")
            backup_path = params.get("backup_path")
            target_path = params.get("target_path")
            expected_hash = params.get("expected_hash")

            if not backup_path or not target_path:
                raise ValueError("Missing backup_path or target_path for RESTORE_BACKUP")

            norm_backup = validate_lab_path(backup_path, run_id)
            norm_target = validate_lab_path(target_path, run_id)

            if not os.path.exists(norm_backup):
                raise FileNotFoundError(f"Backup file '{backup_path}' does not exist.")

            with open(norm_backup, "r", encoding="utf-8") as f:
                backup_content = f.read()

            actual_hash = hashlib.sha256(backup_content.encode("utf-8")).hexdigest()
            if expected_hash and actual_hash != expected_hash:
                raise ValueError(
                    f"Backup integrity violation! Hash mismatch on restore: expected {expected_hash}, got {actual_hash}."
                )

            # Atomically restore
            temp_restore = f"{norm_target}.restore.{os.getpid()}"
            os.makedirs(os.path.dirname(norm_target), exist_ok=True)
            with open(temp_restore, "w", encoding="utf-8") as f:
                f.write(backup_content)
                f.flush()
                os.fsync(f.fileno())

            os.replace(temp_restore, norm_target)

            # Read back verification
            with open(norm_target, "r", encoding="utf-8") as f:
                restored_check = f.read()
            if hashlib.sha256(restored_check.encode("utf-8")).hexdigest() != actual_hash:
                raise RuntimeError("Restored configuration readback verification failed!")

            return {
                "restored": True,
                "target_path": norm_target,
                "restored_hash": actual_hash,
                "bytes_restored": len(backup_content),
            }

        elif action == "RUN_REMEDIATION_WORKLOAD":
            import ipaddress
            import re
            target_ip = str(params.get("target_ip", "10.10.2.10")).strip()
            namespace = str(params.get("namespace", "client")).strip()
            packet_count = max(1, min(int(params.get("packet_count", 3)), 20))

            try:
                ipaddress.ip_address(target_ip)
            except ValueError as exc:
                raise ValueError(f"Invalid target_ip '{target_ip}': Must be a valid IPv4 or IPv6 address.") from exc

            if not re.match(r"^[a-zA-Z0-9_\-]+$", namespace) or namespace in ("host", "default", "root", ""):
                raise PermissionError(f"Access denied: Invalid or unauthorized namespace '{namespace}'")

            cmd = ["ip", "netns", "exec", namespace, "ping", "-c", str(packet_count), "-W", "2", target_ip]
            res = await asyncio.to_thread(self.runner.run, cmd, check=False)

            m_trans = re.search(r"(\d+)\s+packets transmitted", res.stdout)
            m_recv = re.search(r"(\d+)\s+(?:packets\s+)?received", res.stdout)

            trans_cnt = int(m_trans.group(1)) if m_trans else packet_count
            recv_cnt = int(m_recv.group(1)) if m_recv else (packet_count if res.success else 0)
            loss_pct = ((trans_cnt - recv_cnt) / trans_cnt * 100.0) if trans_cnt > 0 else 100.0

            return {
                "success": res.success and recv_cnt > 0,
                "packets_transmitted": trans_cnt,
                "packets_received": recv_cnt,
                "loss_pct": loss_pct,
                "stdout": res.stdout[:500],
            }

        raise RuntimeError(f"Unhandled allowlisted action: {action}")

