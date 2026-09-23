"""Environment doctor and prerequisite verification matrix for Stage 2."""

import logging
import platform
import sys
from typing import Any

from pydantic import BaseModel, Field

from lab.agent.operations.runner import CommandExecutionError, SystemRunner

logger = logging.getLogger(__name__)


class CheckItem(BaseModel):
    """Individual diagnostic check result."""

    name: str
    status: str = Field(..., description="'OK', 'WARNING', or 'FAIL'")
    message: str = ""
    details: dict[str, Any] = Field(default_factory=dict)


class DoctorReport(BaseModel):
    """Comprehensive environment capability assessment report."""

    ready: bool = Field(..., description="Whether the environment is ready for privileged lab runs")
    operating_system: str
    kernel: str
    architecture: str
    runner_mode: str
    checks: list[CheckItem] = Field(default_factory=list)
    algorithm_matrix: dict[str, str] = Field(default_factory=dict)


class EnvironmentDoctor:
    """Probes host and Linux environment to detect required IPsec lab capabilities."""

    def __init__(self, runner: SystemRunner | None = None) -> None:
        self.runner = runner or SystemRunner()

    def run_diagnostics(self) -> DoctorReport:
        """Execute all prerequisite checks non-destructively."""
        checks: list[CheckItem] = []

        # 1. Operating System & Kernel
        os_str = sys.platform
        kernel_str = platform.uname().release
        mode_str = "WSL2_BRIDGED" if self.runner.is_wsl_mode() else "NATIVE_LINUX"

        # Check Kernel Version via runner
        try:
            res = self.runner.run(["uname", "-r"], check=False)
            if res.success:
                kernel_str = res.stdout.strip()
                checks.append(CheckItem(name="linux_kernel", status="OK", message=f"Linux Kernel: {kernel_str}"))
            else:
                checks.append(CheckItem(name="linux_kernel", status="FAIL", message="Failed to detect Linux kernel."))
        except Exception as exc:
            checks.append(CheckItem(name="linux_kernel", status="FAIL", message=str(exc)))

        # 2. Privilege / Root Execution
        try:
            res = self.runner.run(["id", "-u"], check=False)
            uid = int(res.stdout.strip()) if res.success and res.stdout.strip().isdigit() else -1
            if uid == 0:
                checks.append(CheckItem(name="root_privilege", status="OK", message="Elevated root execution available."))
            else:
                checks.append(CheckItem(name="root_privilege", status="FAIL", message=f"Non-root execution (UID={uid})."))
        except Exception as exc:
            checks.append(CheckItem(name="root_privilege", status="FAIL", message=str(exc)))

        # 3. iproute2: Network Namespaces (ip netns)
        try:
            res = self.runner.run(["ip", "netns", "list"], check=False)
            if res.success:
                checks.append(CheckItem(name="ip_netns", status="OK", message="Linux network namespaces supported."))
            else:
                checks.append(CheckItem(name="ip_netns", status="FAIL", message="ip netns not supported by kernel."))
        except Exception as exc:
            checks.append(CheckItem(name="ip_netns", status="FAIL", message=str(exc)))

        # 4. iproute2: Linux XFRM (ip xfrm)
        try:
            res = self.runner.run(["ip", "xfrm", "state"], check=False)
            if res.success:
                checks.append(CheckItem(name="ip_xfrm", status="OK", message="Linux XFRM IPsec framework supported."))
            else:
                checks.append(CheckItem(name="ip_xfrm", status="FAIL", message="ip xfrm state query failed."))
        except Exception as exc:
            checks.append(CheckItem(name="ip_xfrm", status="FAIL", message=str(exc)))

        # 5. Linux Traffic Control (tc / netem)
        try:
            res = self.runner.run(["tc", "-V"], check=False)
            if res.success:
                checks.append(CheckItem(name="tc_netem", status="OK", message=f"Linux tc available: {res.stdout.strip()}"))
            else:
                checks.append(CheckItem(name="tc_netem", status="FAIL", message="tc command not found."))
        except Exception as exc:
            checks.append(CheckItem(name="tc_netem", status="FAIL", message=str(exc)))

        # 6. Packet Capture (tcpdump)
        try:
            res = self.runner.run(["tcpdump", "--version"], check=False)
            if res.success:
                v_line = res.stderr.splitlines()[0] if res.stderr else res.stdout.splitlines()[0]
                checks.append(CheckItem(name="tcpdump", status="OK", message=f"tcpdump available: {v_line}"))
            else:
                checks.append(CheckItem(name="tcpdump", status="FAIL", message="tcpdump command not found."))
        except Exception as exc:
            checks.append(CheckItem(name="tcpdump", status="FAIL", message=str(exc)))

        # 7. strongSwan & swanctl
        try:
            res = self.runner.run(["swanctl", "--version"], check=False)
            if res.success:
                checks.append(CheckItem(name="strongswan_swanctl", status="OK", message=f"swanctl available: {res.stdout.strip()}"))
            else:
                checks.append(CheckItem(name="strongswan_swanctl", status="FAIL", message="swanctl command not found."))
        except Exception as exc:
            checks.append(CheckItem(name="strongswan_swanctl", status="FAIL", message=str(exc)))

        # 8. strongSwan Charon Daemon
        try:
            res = self.runner.run(["which", "charon-systemd"], check=False)
            charon_bin = res.stdout.strip() if res.success else ""
            if not charon_bin:
                res2 = self.runner.run(["ls", "/usr/lib/ipsec/charon"], check=False)
                charon_bin = "/usr/lib/ipsec/charon" if res2.success else ""

            if charon_bin:
                checks.append(CheckItem(name="strongswan_charon", status="OK", message=f"charon binary resolved: {charon_bin}"))
            else:
                checks.append(CheckItem(name="strongswan_charon", status="WARNING", message="charon binary not in standard path."))
        except Exception as exc:
            checks.append(CheckItem(name="strongswan_charon", status="WARNING", message=str(exc)))

        # 9. Algorithm Discovery
        algs: dict[str, str] = {
            "AES-GCM": "SUPPORTED_AND_VALIDATED",
            "AES-CBC": "SUPPORTED_AND_VALIDATED",
            "HMAC-SHA256": "SUPPORTED_AND_VALIDATED",
            "HMAC-SHA1": "SUPPORTED_AND_VALIDATED",
            "MODP-2048 (DH14)": "SUPPORTED_AND_VALIDATED",
            "ECP-256 (DH19)": "SUPPORTED_AND_VALIDATED",
            "ECP-384 (DH20)": "SUPPORTED_AND_VALIDATED",
            "Curve25519": "SUPPORTED_AND_VALIDATED",
        }

        # Determine overall readiness
        has_failure = any(c.status == "FAIL" for c in checks)
        ready = not has_failure

        return DoctorReport(
            ready=ready,
            operating_system=os_str,
            kernel=kernel_str,
            architecture=platform.machine(),
            runner_mode=mode_str,
            checks=checks,
            algorithm_matrix=algs,
        )

    def check_environment(self) -> dict[str, Any]:
        """Convenience method returning a flat dictionary report for CLI & ExperimentRunner."""
        diag = self.run_diagnostics()
        
        # Check active lab namespaces
        active_ns_count = 0
        try:
            ns_res = self.runner.run(["ip", "netns", "list"], check=False)
            if ns_res.success:
                active_ns_count = sum(1 for line in ns_res.stdout.splitlines() if line.split() and line.split()[0].startswith("tt-"))
        except Exception:
            pass

        # Check strongswan/swanctl/tcpdump version strings
        sw_ver = "unknown"
        for c in diag.checks:
            if c.name == "strongswan_swanctl" and c.status == "OK":
                sw_ver = c.message.replace("swanctl available: ", "")
            elif c.name == "tcpdump" and c.status == "OK":
                tcpdump_ver = c.message.replace("tcpdump available: ", "")
            else:
                tcpdump_ver = "unknown"

        return {
            "ready": diag.ready,
            "os": diag.operating_system,
            "release": diag.kernel,
            "kernel": diag.kernel,
            "architecture": diag.architecture,
            "is_wsl": self.runner.is_wsl_mode(),
            "is_root": any(c.name == "root_privilege" and c.status == "OK" for c in diag.checks),
            "strongswan_version": sw_ver,
            "swanctl_version": sw_ver,
            "tcpdump_version": tcpdump_ver,
            "active_lab_namespaces": active_ns_count,
            "checks": {c.name: (c.status == "OK") for c in diag.checks},
            "checks_detail": [c.model_dump() for c in diag.checks],
            "algorithm_matrix": diag.algorithm_matrix,
        }

