"""strongSwan per-namespace lifecycle management and VICI/swanctl orchestration."""

import logging
import time
from typing import Any, Optional

from lab.agent.cleanup.tracker import LabResourceTracker
from lab.agent.operations.runner import CommandExecutionError, CommandResult, SystemRunner
from lab.agent.strongswan.config_generator import SwanctlConfigGenerator
from lab.scenarios.schema import ScenarioDefinition

logger = logging.getLogger(__name__)


class StrongSwanManager:
    """Manages strongSwan charon daemon instances and swanctl control within isolated namespaces."""

    def __init__(
        self,
        run_id: Any = None,
        tracker: Optional[LabResourceTracker] = None,
        runner: Optional[SystemRunner] = None,
    ) -> None:
        if isinstance(run_id, SystemRunner):
            self.runner = run_id
            self.tracker = tracker or LabResourceTracker(runner=self.runner)
            self.run_id = self.tracker.run_id
        else:
            self.run_id = str(run_id) if run_id else "default"
            self.runner = runner or SystemRunner()
            self.tracker = tracker or LabResourceTracker(run_id=self.run_id, runner=self.runner)
        self.base_runtime_dir = f"/tmp/tt-{self.run_id}"
        self.peer_runtimes: dict[str, dict[str, str]] = {}


    def prepare_peer_runtime(
        self,
        peer_role: str,
        namespace: str,
        scenario: ScenarioDefinition,
        address_plan: dict[str, Any],
        psk_secret: str = "tunneltrace_lab_test_psk_9921",
    ) -> tuple[str, str, str]:
        """Create isolated strongswan.conf and swanctl.conf for a specific peer namespace.

        Returns:
            tuple[str, str, str]: (peer_dir, vici_socket_path, swanctl_config_hash)
        """
        peer_dir = f"{self.base_runtime_dir}/{peer_role}"
        vici_socket = f"{peer_dir}/charon.vici"
        swanctl_dir = f"{peer_dir}/swanctl"
        strongswan_conf = f"{peer_dir}/strongswan.conf"
        swanctl_conf = f"{swanctl_dir}/swanctl.conf"

        # Create directories inside Linux
        self.runner.run(["mkdir", "-p", swanctl_dir])
        self.tracker.register_temp_path(peer_dir)

        # 1. Generate strongswan.conf configuring isolated VICI socket and loading modular plugins
        strongswan_content = f"""# Isolated strongSwan daemon config for {peer_role}
charon {{
    load_modular = yes
    install_routes = no
    install_virtual_ip = no
    plugins {{
        include /etc/strongswan.d/charon/*.conf
        vici {{
            socket = unix://{vici_socket}
        }}
    }}
}}

include /etc/strongswan.d/*.conf
"""
        self.runner.write_text_file(strongswan_conf, strongswan_content)

        # 2. Render swanctl.conf
        rendered_swanctl, config_hash = SwanctlConfigGenerator.render_peer_config(
            scenario=scenario,
            peer_role=peer_role,
            address_plan=address_plan,
            psk_secret=psk_secret,
        )
        self.runner.write_text_file(swanctl_conf, rendered_swanctl)

        return peer_dir, vici_socket, config_hash

    def start_charon(self, namespace: str, peer_dir: str) -> int:
        """Start isolated charon daemon inside the specified namespace with private /var/run tmpfs."""
        import subprocess
        strongswan_conf = f"{peer_dir}/strongswan.conf"
        vici_socket = f"{peer_dir}/charon.vici"
        log_file = f"{peer_dir}/charon.log"

        # Start charon in background with isolated /var/run mount namespace to prevent PID file collisions
        charon_cmd = [
            "/usr/sbin/ip",
            "netns",
            "exec",
            namespace,
            "/usr/bin/unshare",
            "-m",
            "/bin/sh",
            "-c",
            f"mount -t tmpfs tmpfs /var/run && STRONGSWAN_CONF={strongswan_conf} exec /usr/lib/ipsec/charon > {log_file} 2>&1"
        ]
        if self.runner.is_wsl_mode():
            full_cmd = ["wsl", "-u", "root", "-e"] + charon_cmd
        else:
            full_cmd = charon_cmd

        proc = subprocess.Popen(
            full_cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        self.tracker.register_pid(proc.pid, f"charon-{namespace}")

        # Wait for VICI socket creation and active responsiveness
        timeout = 7.0
        start = time.time()
        while time.time() - start < timeout:
            check_res = self.runner.run(
                [
                    "/usr/sbin/ip", "netns", "exec", namespace,
                    "/usr/sbin/swanctl", "--stats",
                    "--uri", f"unix://{vici_socket}"
                ],
                check=False
            )
            if check_res.success:
                logger.debug(f"charon started in {namespace} (PID {proc.pid}, VICI socket responding)")
                # Register all Linux PIDs strictly confined to this namespace
                try:
                    pids_res = self.runner.run(["ip", "netns", "pids", namespace], check=False)
                    if pids_res.success and pids_res.stdout.strip():
                        for p in pids_res.stdout.split():
                            if p.isdigit():
                                self.tracker.register_pid(int(p), f"charon-ns-{namespace}")
                except Exception:
                    pass
                return proc.pid
            time.sleep(0.3)

        # Query log if failed
        log_content = ""
        try:
            log_res = self.runner.run_raw(["cat", log_file], check=False)
            log_content = log_res.stdout.strip()
        except Exception:
            pass

        raise RuntimeError(
            f"charon in namespace '{namespace}' failed to respond on VICI socket after {timeout}s.\n"
            f"CHARON LOG:\n{log_content}"
        )




    def load_configuration(self, namespace: str, peer_dir: str, vici_socket: str) -> CommandResult:
        """Load rendered swanctl configuration into the active charon daemon."""
        swanctl_conf = f"{peer_dir}/swanctl/swanctl.conf"
        return self.runner.run(
            [
                "ip",
                "netns",
                "exec",
                namespace,
                "/usr/sbin/swanctl",
                "--load-all",
                "--file",
                swanctl_conf,
                "--uri",
                f"unix://{vici_socket}",
            ]
        )

    def initiate_tunnel(self, namespace: str, vici_socket: str, child_name: str = "child-sa") -> CommandResult:
        """Initiate IKE SA and Child SA negotiation from the initiating peer."""
        logger.info(f"Initiating IPsec tunnel from namespace '{namespace}'")
        return self.runner.run(
            [
                "ip",
                "netns",
                "exec",
                namespace,
                "/usr/sbin/swanctl",
                "--initiate",
                "--child",
                child_name,
                "--uri",
                f"unix://{vici_socket}",
                "--timeout",
                "10",
            ],
            timeout_sec=15.0,
            check=False,
        )

    def query_sa_status(self, namespace: str, vici_socket: str) -> str:
        """Query active Security Associations via swanctl --list-sas."""
        res = self.runner.run(
            [
                "ip",
                "netns",
                "exec",
                namespace,
                "/usr/sbin/swanctl",
                "--list-sas",
                "--uri",
                f"unix://{vici_socket}",
            ],
            check=False,
        )
        return res.stdout

    def query_xfrm_state(self, namespace: str) -> str:
        """Query kernel XFRM states inside namespace."""
        res = self.runner.run(["ip", "netns", "exec", namespace, "/usr/sbin/ip", "xfrm", "state"], check=False)
        return res.stdout

    def query_xfrm_policy(self, namespace: str) -> str:
        """Query kernel XFRM policies inside namespace."""
        res = self.runner.run(["ip", "netns", "exec", namespace, "/usr/sbin/ip", "xfrm", "policy"], check=False)
        return res.stdout

    def stop_peer_daemon(self, namespace: str, peer_dir: Optional[str] = None) -> None:
        """Safely stop charon daemon running inside the specified namespace using signal escalation."""
        try:
            pids_res = self.runner.run(["ip", "netns", "pids", namespace], check=False)
            if pids_res.success and pids_res.stdout.strip():
                for p in pids_res.stdout.split():
                    if p.isdigit():
                        pid_int = int(p)
                        # Graceful SIGTERM
                        self.runner.run_raw(["kill", "-TERM", str(pid_int)], check=False)
                        time.sleep(0.2)
                        # Check alive and escalate to SIGKILL if needed
                        alive = self.runner.run_raw(["kill", "-0", str(pid_int)], check=False)
                        if alive.returncode == 0:
                            logger.warning(f"charon PID {pid_int} in {namespace} still alive; escalating to SIGKILL")
                            self.runner.run_raw(["kill", "-KILL", str(pid_int)], check=False)
        except Exception as exc:
            logger.warning(f"Error terminating charon daemon in namespace '{namespace}': {exc}")

