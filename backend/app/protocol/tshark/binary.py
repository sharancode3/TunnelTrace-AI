"""Binary discovery and command resolution for TShark and Capinfos across Linux and Windows/WSL2."""

import logging
import os
import shutil
import subprocess
import sys
from collections.abc import Sequence
from functools import lru_cache
from pathlib import Path

logger = logging.getLogger(__name__)


def to_wsl_path(path: str | Path) -> str:
    """Convert a Windows file path (e.g. C:\\foo\\bar or relative path) to WSL path (/mnt/c/foo/bar)."""
    p_str = str(path)
    if p_str.startswith("/"):
        return p_str
    abs_path = os.path.abspath(p_str)
    drive, rest = os.path.splitdrive(abs_path)
    if drive:
        drive_letter = drive[0].lower()
        rest_unix = rest.replace("\\", "/")
        return f"/mnt/{drive_letter}{rest_unix}"
    return abs_path.replace("\\", "/")


class ToolchainResolver:
    """Discovers and adapts TShark and Capinfos across native Linux and Windows WSL2."""

    def __init__(self) -> None:
        self.is_windows = sys.platform.startswith("win")
        self._wsl_path = shutil.which("wsl") if self.is_windows else None
        self._version_cache: dict[str, str] = {}

    @property
    def uses_wsl(self) -> bool:
        """True if running on Windows and bridging through WSL2."""
        return self.is_windows and self._wsl_path is not None

    def resolve_command(self, tool: str, args: Sequence[str]) -> list[str]:
        """Construct the executable argument vector for the target tool.

        Runs as an unprivileged user (never root).
        Uses shell=False argument vectors exclusively.
        """
        tool_bin = "/usr/bin/" + tool if self.uses_wsl else tool

        if self.uses_wsl:
            # Map Windows file paths in args to WSL paths
            converted_args: list[str] = []
            for arg in args:
                s_arg = str(arg)
                # If arg is an existing file/path or contains path separators (and not a flag)
                if not s_arg.startswith("-") and (
                    os.path.exists(s_arg)
                    or ":\\" in s_arg
                    or ":/" in s_arg
                    or "\\" in s_arg
                    or "/" in s_arg
                ):
                    converted_args.append(to_wsl_path(s_arg))
                else:
                    converted_args.append(s_arg)

            # wsl -e executes without shell and without root
            return ["wsl", "-e", tool_bin] + converted_args

        return [tool_bin] + [str(a) for a in args]

    def get_version(self, tool: str) -> str:
        """Run tool -v and parse the version string with caching."""
        if tool in self._version_cache:
            return self._version_cache[tool]

        cmd = self.resolve_command(tool, ["-v"])
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                shell=False,
                timeout=15.0,
            )
            if proc.returncode == 0:
                first_line = proc.stdout.strip().split("\n")[0]
                self._version_cache[tool] = first_line
                return first_line
            ver = f"unknown (exit code {proc.returncode})"
            self._version_cache[tool] = ver
            return ver
        except Exception as exc:
            logger.warning(f"Failed to query {tool} version: {exc}")
            return "unavailable"


@lru_cache(maxsize=1)
def get_toolchain() -> ToolchainResolver:
    """Singleton getter for the toolchain resolver."""
    return ToolchainResolver()
