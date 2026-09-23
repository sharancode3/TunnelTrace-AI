"""Subprocess execution wrapper enforcing strict argument arrays, timeouts, and host isolation."""

import logging
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from typing import Optional, Sequence, Union

logger = logging.getLogger(__name__)

# Sensitive patterns to sanitize from subprocess execution logs
SECRET_MASKS = [
    re.compile(r"(?i)(psk|secret|key|password)=([^\s]+)"),
    re.compile(r"(?i)(secret\s*:\s*)([^\s]+)"),
    re.compile(r"(?i)(--secret\s+)([^\s]+)"),
]

# Physical host interfaces that must NEVER be modified by lab operations
PROTECTED_HOST_INTERFACES = {
    "eth0",
    "enp3s0",
    "wlan0",
    "wlo1",
    "en0",
    "docker0",
    "tailscale0",
    "tun0",
    "br0",
    "Ethernet",
    "Ethernet 2",
    "Wi-Fi",
}


@dataclass
class CommandResult:
    """Structured result of an executed subprocess."""

    args: list[str]
    returncode: int
    stdout: str
    stderr: str
    duration_sec: float
    success: bool


class SecurityViolationError(RuntimeError):
    """Raised when an operation attempts to touch a protected physical interface or dangerous parameter."""
    pass


PhysicalInterfaceProtectionError = SecurityViolationError


class CommandExecutionError(RuntimeError):
    """Raised when a required system command exits with a non-zero return code."""

    def __init__(self, message: str, result: CommandResult) -> None:
        super().__init__(message)
        self.result = result


@dataclass
class SafeCommand:
    """Represents a validated system command with secret redaction."""
    binary: str
    args: list[str]

    def get_redacted_command(self) -> str:
        cmd_str = f"{self.binary} " + " ".join(self.args)
        for pattern in SECRET_MASKS:
            cmd_str = pattern.sub(r"\1[REDACTED_SECRET]", cmd_str)
        return cmd_str


RESOLVED_BINARIES = {
    "ip": "/usr/sbin/ip",
    "tc": "/usr/sbin/tc",
    "swanctl": "/usr/sbin/swanctl",
    "tcpdump": "/usr/bin/tcpdump",
    "charon": "/usr/lib/ipsec/charon",
    "sysctl": "/usr/sbin/sysctl",
    "ping": "/usr/bin/ping",
    "ping6": "/usr/bin/ping6",
    "uname": "/usr/bin/uname",
    "id": "/usr/bin/id",
    "which": "/usr/bin/which",
    "ls": "/usr/bin/ls",
    "mkdir": "/usr/bin/mkdir",
    "cp": "/usr/bin/cp",
    "rm": "/usr/bin/rm",
    "stat": "/usr/bin/stat",
    "sha256sum": "/usr/bin/sha256sum",
    "pkill": "/usr/bin/pkill",
    "kill": "/usr/bin/kill",
    "true": "/usr/bin/true",
    "tee": "/usr/bin/tee",
    "env": "/usr/bin/env",
}


class SystemRunner:
    """Safe execution engine that bridges native Linux and Windows WSL2 environments."""

    def __init__(self, run_id_prefix: str = "tt-") -> None:
        self.run_id_prefix = run_id_prefix
        self.is_windows = sys.platform.startswith("win")
        self._wsl_available: Optional[bool] = None

    def write_text_file(self, target_linux_path: str, content: str) -> None:
        """Safely write arbitrary text content to a target file in Linux without any shell interpolation."""
        if self.is_wsl_mode():
            cmd = ["wsl", "-u", "root", "-e", "/usr/bin/tee", target_linux_path]
        else:
            cmd = ["/usr/bin/tee", target_linux_path]

        proc = subprocess.run(
            cmd,
            input=content,
            text=True,
            capture_output=True,
            shell=False,
            timeout=10.0,
        )
        if proc.returncode != 0:
            raise CommandExecutionError(
                f"Failed to write text file to '{target_linux_path}': {proc.stderr}",
                CommandResult(cmd, proc.returncode, proc.stdout, proc.stderr, 0.0, False),
            )


    @property
    def is_wsl(self) -> bool:
        return self.is_wsl_mode()

    @property
    def ip_bin(self) -> str:
        return RESOLVED_BINARIES["ip"]

    @property
    def tc_bin(self) -> str:
        return RESOLVED_BINARIES["tc"]

    @property
    def tcpdump_bin(self) -> str:
        return RESOLVED_BINARIES["tcpdump"]

    @property
    def swanctl_bin(self) -> str:
        return RESOLVED_BINARIES["swanctl"]

    @property
    def charon_bin(self) -> str:
        return RESOLVED_BINARIES["charon"]

    def is_wsl_mode(self) -> bool:
        """Determine if Linux commands must be bridged through WSL."""
        if not self.is_windows:
            return False
        if self._wsl_available is None:
            self._wsl_available = shutil.which("wsl") is not None
        return self._wsl_available

    def _to_wsl_path(self, path: str) -> str:
        """Convert Windows file path (c:\\...) to WSL path (/mnt/c/...)."""
        if not self.is_wsl_mode() or path.startswith("/"):
            return path.replace("\\", "/")
        norm = os.path.normpath(path)
        drive, rest = os.path.splitdrive(norm)
        if drive:
            drive_letter = drive[0].lower()
            rest = rest.replace("\\", "/")
            return f"/mnt/{drive_letter}{rest}"
        return path.replace("\\", "/")

    def sanitize_log(self, text: str) -> str:
        """Scrub secret credentials from logged command strings."""
        sanitized = text
        for pattern in SECRET_MASKS:
            sanitized = pattern.sub(r"\1***REDACTED***", sanitized)
        return sanitized

    def _resolve_binary_paths(self, args: Sequence[str]) -> list[str]:
        """Resolve short command names to standard Linux full paths for WSL compatibility."""
        resolved = list(args)
        if not resolved:
            return resolved

        # Top-level binary
        if resolved[0] in RESOLVED_BINARIES:
            resolved[0] = RESOLVED_BINARIES[resolved[0]]

        # Sub-commands (e.g. 'ip netns exec <ns> <cmd>')
        if len(resolved) >= 5 and resolved[0] in ("/usr/sbin/ip", "ip") and resolved[1] == "netns" and resolved[2] == "exec":
            sub_cmd = resolved[4]
            if sub_cmd in RESOLVED_BINARIES:
                resolved[4] = RESOLVED_BINARIES[sub_cmd]

        return resolved

    def validate_safety(self, target: Union[str, Sequence[str]]) -> None:
        """Assert that targets or commands do not target physical host interfaces or dangerous parameters."""
        if isinstance(target, str):
            iface = target.strip()
            if (
                iface in PROTECTED_HOST_INTERFACES
                or iface.startswith(("eth", "enp", "wlan", "wlo", "docker", "tailscale"))
                or "Ethernet" in iface
                or "Wi-Fi" in iface
            ):
                raise SecurityViolationError(
                    f"Refusing to execute operation touching protected physical host interface: '{iface}'"
                )
            return

        cmd_args = list(target)
        joined = " ".join(cmd_args)

        # Check for protected interfaces in modifying contexts
        if any(keyword in cmd_args for keyword in ("link", "addr", "route", "qdisc", "tc")):
            for iface in PROTECTED_HOST_INTERFACES:
                if f"dev {iface}" in joined or f"dev {iface}" in joined:
                    raise SecurityViolationError(
                        f"Refusing to execute command touching protected physical host interface: '{iface}'"
                    )

        # Disallow raw shell injections
        for forbidden in (";", "&&", "||", "|", "`", "$("):
            for arg in cmd_args:
                if forbidden in arg and not arg.startswith("echo") and not arg.startswith("printf"):
                    raise SecurityViolationError(
                        f"Potentially unsafe shell character '{forbidden}' detected in argument '{arg}'"
                    )

    def run(
        self,
        args: Sequence[str],
        timeout_sec: float = 30.0,
        check: bool = True,
        log_level: int = logging.DEBUG,
    ) -> CommandResult:
        """Execute a system command safely with strict argument lists and timeout protection."""
        self.validate_safety(args)
        resolved_args = self._resolve_binary_paths(args)

        final_args: list[str]
        if self.is_wsl_mode():
            final_args = ["wsl", "-u", "root", "-e"] + resolved_args
        else:
            final_args = resolved_args

        safe_cmd_str = self.sanitize_log(" ".join(final_args))
        logger.log(log_level, f"Executing: {safe_cmd_str}")

        import time
        start_time = time.perf_counter()

        try:
            process = subprocess.run(
                final_args,
                shell=False,
                capture_output=True,
                text=True,
                timeout=timeout_sec,
            )
            duration = round(time.perf_counter() - start_time, 3)

            result = CommandResult(
                args=list(args),
                returncode=process.returncode,
                stdout=process.stdout,
                stderr=process.stderr,
                duration_sec=duration,
                success=(process.returncode == 0),
            )

            if check and not result.success:
                err_msg = (
                    f"Command failed (exit {result.returncode}): {safe_cmd_str}\n"
                    f"STDERR: {result.stderr.strip()}\n"
                    f"STDOUT: {result.stdout.strip()}"
                )
                logger.error(err_msg)
                raise CommandExecutionError(err_msg, result)

            return result

        except subprocess.TimeoutExpired as exc:
            duration = round(time.perf_counter() - start_time, 3)
            logger.error(f"Command timed out after {timeout_sec}s: {safe_cmd_str}")
            res = CommandResult(
                args=list(args),
                returncode=-1,
                stdout=exc.stdout or "" if isinstance(exc.stdout, str) else "",
                stderr="Execution timed out",
                duration_sec=duration,
                success=False,
            )
            if check:
                raise CommandExecutionError(f"Command timed out after {timeout_sec}s: {safe_cmd_str}", res) from exc
            return res

    def run_raw(
        self,
        args: Sequence[str],
        netns: Optional[str] = None,
        check: bool = True,
        timeout_sec: float = 30.0,
    ) -> CommandResult:
        """Helper to run a raw command, optionally wrapped inside an ip netns exec."""
        if netns:
            cmd = ["ip", "netns", "exec", netns] + list(args)
        else:
            cmd = list(args)
        return self.run(cmd, timeout_sec=timeout_sec, check=check)

    def run_ip(
        self,
        args: Sequence[str],
        netns: Optional[str] = None,
        check: bool = True,
        timeout_sec: float = 30.0,
    ) -> CommandResult:
        """Helper for iproute2 commands."""
        if netns:
            cmd = ["ip", "netns", "exec", netns, "ip"] + list(args)
        else:
            cmd = ["ip"] + list(args)
        return self.run(cmd, timeout_sec=timeout_sec, check=check)

    def run_tc(
        self,
        args: Sequence[str],
        netns: Optional[str] = None,
        check: bool = True,
        timeout_sec: float = 30.0,
    ) -> CommandResult:
        """Helper for traffic control (tc) commands."""
        if netns:
            cmd = ["ip", "netns", "exec", netns, "tc"] + list(args)
        else:
            cmd = ["tc"] + list(args)
        return self.run(cmd, timeout_sec=timeout_sec, check=check)
