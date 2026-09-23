"""Dataset Quality Gate: validates candidate sessions before acceptance into curated dataset."""

from __future__ import annotations

import logging
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class QualityGateResult(BaseModel):
    """Result of automated quality gate validation for a candidate dataset session."""

    accepted: bool
    status: str  # ACCEPTED, REJECTED, PARTIAL
    rejection_reason: str | None = None
    checks_passed: list[str] = Field(default_factory=list)
    checks_failed: list[str] = Field(default_factory=list)
    failures: list[str] = Field(default_factory=list)
    metrics: dict[str, Any] = Field(default_factory=dict)


# Type alias for backwards compatibility
QualityCheckResult = QualityGateResult


class DatasetQualityGate:
    """Evaluates an experimental session against strict ground-truth and integrity standards."""

    @classmethod
    def validate(
        cls,
        sa_established: bool,
        workload_result: Any,
        outer_packet_count: int,
        outer_byte_count: int,
        esp_packet_count: int,
        duration_seconds: float,
        min_packets: int = 5,
        min_bytes: int = 100,
        max_duration: float = 300.0,
        known_hashes: set[str] | None = None,
        sha256_hash: str = "",
    ) -> QualityGateResult:
        """Validate candidate session facts against acceptance criteria."""
        passed: list[str] = []
        failed: list[str] = []

        # 1. IPsec SA establishment
        if sa_established:
            passed.append("sa_established")
        else:
            failed.append("SA negotiation failed (no CHILD_SA established)")

        # 2. Workload success signal
        w_success = getattr(workload_result, "success", False) if workload_result else False
        if w_success:
            passed.append("workload_success")
        else:
            err = getattr(workload_result, "error_message", None) if workload_result else None
            failed.append(f"Workload execution reported failure: {err or 'unknown error'}")

        # 3. ESP / NAT-T packet presence
        if esp_packet_count > 0:
            passed.append("esp_packets_present")
        else:
            failed.append("Zero ESP/NAT-T packets detected in outer capture")

        # 4. Minimum packet and byte count
        if outer_packet_count >= min_packets:
            passed.append("min_packets_satisfied")
        else:
            failed.append(
                f"Packet count {outer_packet_count} below threshold {min_packets}"
            )

        if outer_byte_count >= min_bytes:
            passed.append("min_bytes_satisfied")
        else:
            failed.append(
                f"Byte count {outer_byte_count} below threshold {min_bytes}"
            )

        # 5. Duration bounds
        if 0 < duration_seconds <= max_duration:
            passed.append("duration_valid")
        else:
            failed.append(
                f"Duration {duration_seconds}s exceeds limit {max_duration}s"
            )

        # 6. Duplicate hash check
        if known_hashes and sha256_hash in known_hashes:
            failed.append(f"Duplicate PCAP SHA-256 hash detected: {sha256_hash}")
        else:
            passed.append("unique_artifact_hash")

        is_accepted = len(failed) == 0
        status = "ACCEPTED" if is_accepted else "REJECTED"
        rejection_reason = "; ".join(failed) if failed else None

        return QualityGateResult(
            accepted=is_accepted,
            status=status,
            rejection_reason=rejection_reason,
            checks_passed=passed,
            checks_failed=failed,
            failures=failed,
            metrics={
                "outer_packet_count": outer_packet_count,
                "outer_byte_count": outer_byte_count,
                "esp_packet_count": esp_packet_count,
                "duration_seconds": duration_seconds,
                "sha256": sha256_hash,
            },
        )

    def evaluate_session(
        self,
        sa_established: bool,
        workload_success: bool,
        wan_pcap_exists: bool,
        wan_packet_count: int,
        wan_byte_count: int,
        ipsec_detected: bool,
        reconstructed_flows_count: int,
        sha256_hash: str,
        known_hashes: set[str] | None = None,
    ) -> QualityGateResult:
        """Validate candidate session facts against acceptance criteria."""
        passed: list[str] = []
        failed: list[str] = []

        if sa_established:
            passed.append("sa_established")
        else:
            failed.append("sa_not_established")

        if workload_success:
            passed.append("workload_success")
        else:
            failed.append("workload_failed")

        if wan_pcap_exists and wan_packet_count > 0 and wan_byte_count > 0:
            passed.append("wan_pcap_valid")
        else:
            failed.append("wan_pcap_empty_or_missing")

        if ipsec_detected:
            passed.append("stage3_ipsec_detected")
        else:
            failed.append("stage3_no_ipsec_detected")

        if reconstructed_flows_count > 0:
            passed.append("stage4_flows_reconstructed")
        else:
            failed.append("stage4_zero_flows")

        if known_hashes and sha256_hash in known_hashes:
            failed.append("duplicate_artifact_hash")
        else:
            passed.append("unique_artifact_hash")

        is_accepted = len(failed) == 0
        status = "ACCEPTED" if is_accepted else "REJECTED"
        rejection_reason = ", ".join(failed) if failed else None

        return QualityGateResult(
            accepted=is_accepted,
            status=status,
            rejection_reason=rejection_reason,
            checks_passed=passed,
            checks_failed=failed,
            failures=failed,
            metrics={
                "packet_count": wan_packet_count,
                "byte_count": wan_byte_count,
                "reconstructed_flows": reconstructed_flows_count,
                "sha256": sha256_hash,
            },
        )
