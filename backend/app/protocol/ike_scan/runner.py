"""Subprocess execution manager for IKE-scan with bounded execution and toolchain isolation."""

from __future__ import annotations

import hashlib
import logging
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from typing import Any

from app.core.config import settings
from app.protocol.ike_scan.profiles import assert_no_forbidden_arguments
from app.protocol.ike_scan.validator import ValidatedIkeScope
from app.protocol.tshark.binary import get_toolchain

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class IkeBinaryInfo:
    is_available: bool
    path: str | None = None
    version: str | None = None
    error_message: str | None = None


@dataclass(frozen=True)
class ExecutionResult:
    status: str  # "COMPLETED", "TOOL_UNAVAILABLE", "FAILED", "CANCELLED"
    exit_code: int | None
    raw_stdout: str | None
    output_sha256: str | None
    output_bytes_count: int
    tool_version: str | None
    diagnostic_message: str | None
    executed_argv: list[str]


def detect_ike_scan_binary() -> IkeBinaryInfo:
    """Detect whether ike-scan is available on host or via WSL2 bridge."""
    # 1. Custom path check
    if settings.IKE_SCAN_PATH:
        if os.path.isfile(settings.IKE_SCAN_PATH) and os.access(settings.IKE_SCAN_PATH, os.X_OK):
            try:
                proc = subprocess.run(
                    [settings.IKE_SCAN_PATH, "--version"],
                    capture_output=True,
                    text=True,
                    shell=False,
                    timeout=5.0,
                )
                first_line = proc.stdout.strip().split("\n")[0] if proc.stdout else "unknown"
                return IkeBinaryInfo(is_available=True, path=settings.IKE_SCAN_PATH, version=first_line)
            except Exception as e:
                return IkeBinaryInfo(is_available=False, path=settings.IKE_SCAN_PATH, error_message=str(e))
        return IkeBinaryInfo(
            is_available=False,
            path=settings.IKE_SCAN_PATH,
            error_message=f"Configured IKE_SCAN_PATH '{settings.IKE_SCAN_PATH}' does not exist or is not executable.",
        )

    # 2. Native PATH check
    native_path = shutil.which("ike-scan")
    if native_path:
        try:
            proc = subprocess.run(
                [native_path, "--version"],
                capture_output=True,
                text=True,
                shell=False,
                timeout=5.0,
            )
            first_line = proc.stdout.strip().split("\n")[0] if proc.stdout else "unknown"
            return IkeBinaryInfo(is_available=True, path=native_path, version=first_line)
        except Exception as e:
            return IkeBinaryInfo(is_available=False, path=native_path, error_message=str(e))

    # 3. WSL2 Toolchain check
    toolchain = get_toolchain()
    if toolchain.uses_wsl:
        cmd = toolchain.resolve_command("ike-scan", ["--version"])
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                shell=False,
                timeout=5.0,
            )
            if proc.returncode == 0:
                first_line = proc.stdout.strip().split("\n")[0] if proc.stdout else "unknown"
                return IkeBinaryInfo(is_available=True, path="/usr/bin/ike-scan", version=first_line)
            return IkeBinaryInfo(
                is_available=False,
                error_message="ike-scan returned non-zero exit code during version check in WSL2 environment.",
            )
        except Exception as e:
            return IkeBinaryInfo(
                is_available=False,
                error_message=f"Failed to execute ike-scan version check via WSL2: {e}",
            )

    return IkeBinaryInfo(
        is_available=False,
        error_message="ike-scan executable not found on host or WSL2 environment.",
    )


def build_ike_scan_argv(scope: ValidatedIkeScope) -> list[str]:
    """Construct an immutable, un-interpolated argv list for subprocess execution."""
    cfg = scope.profile_config
    args: list[str] = []

    if cfg.ike_version == "2":
        args.append("-2")

    args.extend([
        f"--retry={cfg.retries}",
        f"--timeout={cfg.timeout_ms}",
        f"--backoff={int(cfg.backoff_factor)}",
        f"--destport={scope.target_port}",
        scope.target_ip,
    ])

    # Enforce zero forbidden flags before returning
    assert_no_forbidden_arguments(args)

    toolchain = get_toolchain()
    if toolchain.uses_wsl and not settings.IKE_SCAN_PATH and not shutil.which("ike-scan"):
        return toolchain.resolve_command("ike-scan", args)

    bin_path = settings.IKE_SCAN_PATH or shutil.which("ike-scan") or "ike-scan"
    return [bin_path] + args


def run_ike_scan(scope: ValidatedIkeScope) -> ExecutionResult:
    """Execute bounded ike-scan command or report truthful TOOL_UNAVAILABLE status."""
    bin_info = detect_ike_scan_binary()
    if not bin_info.is_available:
        logger.warning(
            f"ike-scan probe requested for {scope.target_ip} but tool is unavailable: {bin_info.error_message}"
        )
        return ExecutionResult(
            status="TOOL_UNAVAILABLE",
            exit_code=None,
            raw_stdout=None,
            output_sha256=None,
            output_bytes_count=0,
            tool_version=None,
            diagnostic_message=bin_info.error_message or "ike-scan tool unavailable",
            executed_argv=[],
        )

    argv = build_ike_scan_argv(scope)
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            shell=False,
            timeout=settings.IKE_SCAN_TIMEOUT_SEC,
            check=False,
        )
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
        combined = stdout + ("\n" + stderr if stderr else "")

        output_bytes = combined.encode("utf-8")
        if len(output_bytes) > settings.IKE_SCAN_MAX_OUTPUT_BYTES:
            combined = combined[: settings.IKE_SCAN_MAX_OUTPUT_BYTES]
            output_bytes = combined.encode("utf-8")

        output_sha = hashlib.sha256(output_bytes).hexdigest()

        return ExecutionResult(
            status="COMPLETED" if proc.returncode == 0 else "FAILED",
            exit_code=proc.returncode,
            raw_stdout=combined,
            output_sha256=output_sha,
            output_bytes_count=len(output_bytes),
            tool_version=bin_info.version,
            diagnostic_message=None if proc.returncode == 0 else f"Process exited with code {proc.returncode}",
            executed_argv=argv,
        )

    except subprocess.TimeoutExpired:
        logger.error(f"ike-scan timed out after {settings.IKE_SCAN_TIMEOUT_SEC}s for {scope.target_ip}")
        return ExecutionResult(
            status="CANCELLED",
            exit_code=None,
            raw_stdout=None,
            output_sha256=None,
            output_bytes_count=0,
            tool_version=bin_info.version,
            diagnostic_message=f"ike-scan execution timed out after {settings.IKE_SCAN_TIMEOUT_SEC} seconds",
            executed_argv=argv,
        )
    except Exception as e:
        logger.exception(f"Unexpected error running ike-scan for {scope.target_ip}: {e}")
        return ExecutionResult(
            status="FAILED",
            exit_code=None,
            raw_stdout=None,
            output_sha256=None,
            output_bytes_count=0,
            tool_version=bin_info.version,
            diagnostic_message=f"Subprocess failure: {e}",
            executed_argv=argv,
        )
