"""Workload Environment Doctor: diagnoses toolchain availability and readiness for Stage 5 generation."""

from __future__ import annotations

from typing import Any

from lab.agent.operations.runner import SystemRunner


class WorkloadDoctor:
    """Probes the host and Linux testbed environment for workload tools and capabilities."""

    def __init__(self, runner: SystemRunner | None = None) -> None:
        self.runner = runner or SystemRunner()

    def check_workload_environment(self) -> dict[str, Any]:
        """Perform comprehensive readiness probe across all 7 workload classes and OOD holdout."""
        checks: dict[str, Any] = {}

        # 1. Python 3 runtime
        py3_res = self.runner.run_raw(["which", "python3"], check=False)
        checks["python3"] = {
            "available": py3_res.returncode == 0,
            "path": py3_res.stdout.strip() if py3_res.returncode == 0 else None,
        }

        # 2. curl
        curl_res = self.runner.run_raw(["which", "curl"], check=False)
        checks["curl"] = {
            "available": curl_res.returncode == 0,
            "path": curl_res.stdout.strip() if curl_res.returncode == 0 else None,
        }

        # 3. ping / ping6
        ping_res = self.runner.run_raw(["which", "ping"], check=False)
        ping6_res = self.runner.run_raw(["which", "ping6"], check=False)
        checks["icmp"] = {
            "ping_available": ping_res.returncode == 0,
            "ping6_available": ping6_res.returncode == 0,
        }

        # 4. tc (traffic control)
        tc_res = self.runner.run_raw(["which", "tc"], check=False)
        checks["tc_netem"] = {
            "available": tc_res.returncode == 0,
            "path": tc_res.stdout.strip() if tc_res.returncode == 0 else None,
        }

        # 5. Class-specific support matrix
        classes_supported = {
            "Web": checks["python3"]["available"],
            "Video Streaming": checks["python3"]["available"],
            "VoIP": checks["python3"]["available"],
            "Chat/Messaging": checks["python3"]["available"],
            "Email": checks["python3"]["available"],
            "ICMP": checks["icmp"]["ping_available"],
            "File Transfer": checks["python3"]["available"],
            "OOD_HOLDOUT": checks["python3"]["available"],
        }
        checks["classes_supported"] = classes_supported

        all_ready = all(classes_supported.values())
        return {
            "ready": all_ready,
            "checks": checks,
            "supported_classes_count": sum(1 for v in classes_supported.values() if v),
            "total_classes_count": len(classes_supported),
        }

    @classmethod
    def check_environment(cls, runner: SystemRunner | None = None) -> dict[str, Any]:
        """Convenience classmethod evaluating workload environment readiness."""
        return cls(runner=runner).check_workload_environment()
