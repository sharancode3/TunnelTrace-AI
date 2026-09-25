"""Conservative asset mapping and product/version correlation engine for imported vulnerability reports.

Separates scanner-reported claims from TunnelTrace-confirmed facts.
Strictly preserves uncertainty: incomplete, wildcard, or banner-only evidence
is classified as POTENTIAL, UNKNOWN, or UNAVAILABLE—never CONFIRMED.
"""

from __future__ import annotations

import ipaddress
import logging
import uuid
from dataclasses import dataclass
from typing import Sequence

from app.db.models.discovery import DiscoveredHost
from app.vulnerabilities.parser import ParsedFinding, ParsedGreenboneReport

logger = logging.getLogger(__name__)


class AssetLinkState:
    MAPPED_EXACT_IP = "MAPPED_EXACT_IP"
    AMBIGUOUS_MULTIPLE_MATCHES = "AMBIGUOUS_MULTIPLE_MATCHES"
    UNLINKED_NO_DISCOVERY_RECORD = "UNLINKED_NO_DISCOVERY_RECORD"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"


class CorrelationStatus:
    CONFIRMED = "CONFIRMED"
    POTENTIAL = "POTENTIAL"
    UNKNOWN = "UNKNOWN"
    UNMATCHED = "UNMATCHED"
    STALE_EVIDENCE = "STALE_EVIDENCE"
    UNAVAILABLE = "UNAVAILABLE"


class CveApplicabilityState:
    POTENTIAL_VERSION_OVERLAP = "POTENTIAL_VERSION_OVERLAP"
    VERSION_MISMATCH_EXCLUDED = "VERSION_MISMATCH_EXCLUDED"
    INSUFFICIENT_VERSION_EVIDENCE = "INSUFFICIENT_VERSION_EVIDENCE"
    NO_RELIABLE_ADVISORY_DATA = "NO_RELIABLE_ADVISORY_DATA"


@dataclass(frozen=True)
class CorrelatedHostResult:
    host_ip: str
    asset_link_state: str
    asset_link_rationale: str
    mapped_host_id: uuid.UUID | None
    is_out_of_scope: bool


@dataclass(frozen=True)
class CorrelatedFindingResult:
    finding: ParsedFinding
    asset_link_state: str
    asset_link_rationale: str
    mapped_host_id: uuid.UUID | None
    correlation_status: str
    correlation_method: str
    cve_applicability_state: str
    correlation_rationale: str


def _is_ip_in_scope(ip_str: str, authorized_targets: list[str]) -> bool:
    """Verify if a host IP falls within an authorized target list or CIDR block."""
    if not authorized_targets:
        # If no explicit discrete scope list provided, scope boundary relies on engagement attestation
        return True

    try:
        candidate_ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False

    for target in authorized_targets:
        target_clean = target.strip()
        if not target_clean:
            continue
        try:
            if "/" in target_clean:
                network = ipaddress.ip_network(target_clean, strict=False)
                if candidate_ip in network:
                    return True
            else:
                discrete = ipaddress.ip_address(target_clean)
                if candidate_ip == discrete:
                    return True
        except ValueError:
            continue
    return False


class VulnerabilityCorrelator:
    """Evaluates asset mapping and product/version claims with strict uncertainty preservation."""

    @classmethod
    def evaluate_host_mapping(
        cls,
        host_ip: str,
        authorized_scope_targets: list[str],
        discovered_hosts: Sequence[DiscoveredHost],
    ) -> CorrelatedHostResult:
        """Map a single report host IP against existing authorized Discovery inventory."""
        # 1. Scope Check
        in_scope = _is_ip_in_scope(host_ip, authorized_scope_targets)
        if not in_scope:
            return CorrelatedHostResult(
                host_ip=host_ip,
                asset_link_state=AssetLinkState.OUT_OF_SCOPE,
                asset_link_rationale=f"Host IP {host_ip} is outside the authorized engagement target list.",
                mapped_host_id=None,
                is_out_of_scope=True,
            )

        # 2. Canonical IP Matching
        matching_hosts = [h for h in discovered_hosts if h.ip_address == host_ip]

        if len(matching_hosts) == 1:
            return CorrelatedHostResult(
                host_ip=host_ip,
                asset_link_state=AssetLinkState.MAPPED_EXACT_IP,
                asset_link_rationale=f"Mapped uniquely to DiscoveredHost {matching_hosts[0].id} via exact IP {host_ip}.",
                mapped_host_id=matching_hosts[0].id,
                is_out_of_scope=False,
            )
        elif len(matching_hosts) > 1:
            return CorrelatedHostResult(
                host_ip=host_ip,
                asset_link_state=AssetLinkState.AMBIGUOUS_MULTIPLE_MATCHES,
                asset_link_rationale=(
                    f"Ambiguous identity: {len(matching_hosts)} DiscoveredHost records share IP {host_ip}. "
                    "Preventing silent merge."
                ),
                mapped_host_id=None,
                is_out_of_scope=False,
            )
        else:
            return CorrelatedHostResult(
                host_ip=host_ip,
                asset_link_state=AssetLinkState.UNLINKED_NO_DISCOVERY_RECORD,
                asset_link_rationale=f"No matching DiscoveredHost record found in inventory for IP {host_ip}.",
                mapped_host_id=None,
                is_out_of_scope=False,
            )

    @classmethod
    def correlate_finding(
        cls,
        finding: ParsedFinding,
        host_correlation: CorrelatedHostResult,
    ) -> CorrelatedFindingResult:
        """Evaluate product/version correlation for an individual finding.

        Strict Truthfulness Invariants:
        - Banner assertions from unauthenticated probes are classified as POTENTIAL.
        - Missing, wildcard, or broad version specs are classified as UNKNOWN.
        - Lack of a pinned vendor advisory database is classified as UNAVAILABLE.
        - Zero findings or unmatched findings are NEVER labeled 'safe' or 'confirmed non-vulnerable'.
        """
        asset_link_state = host_correlation.asset_link_state
        asset_link_rationale = host_correlation.asset_link_rationale
        mapped_host_id = host_correlation.mapped_host_id

        # Epistemic Rule: No external advisory feed fetching allowed in this phase.
        # Report correlation status based on observable evidence confidence.
        qod = finding.qod_value or 0
        qod_type = (finding.qod_type or "").lower()
        has_cve = bool(finding.nvt.cves)
        has_version_claim = bool(finding.source_version_claim and finding.source_version_claim != "*")

        if host_correlation.is_out_of_scope:
            correlation_status = CorrelationStatus.UNMATCHED
            correlation_method = "SCOPE_EXCLUSION"
            cve_applicability = CveApplicabilityState.VERSION_MISMATCH_EXCLUDED
            rationale = "Finding belongs to an out-of-scope host; excluded from active posture evaluation."

        elif not has_cve or not has_version_claim or not finding.source_product_claim:
            # Missing version evidence, missing product, or wildcard CPE
            correlation_status = CorrelationStatus.UNKNOWN
            correlation_method = "INCOMPLETE_SCANNER_EVIDENCE"
            cve_applicability = CveApplicabilityState.INSUFFICIENT_VERSION_EVIDENCE
            rationale = (
                "Incomplete product/version evidence or wildcard CPE in scanner report. "
                "Cannot determine applicability with certainty."
            )

        elif qod_type == "remote_banner" or qod < 80:
            # Remote banner or low-confidence unauthenticated probe
            correlation_status = CorrelationStatus.POTENTIAL
            correlation_method = "SCANNER_BANNER_INFERENCE"
            cve_applicability = CveApplicabilityState.POTENTIAL_VERSION_OVERLAP
            rationale = (
                f"Greenbone reported finding based on remote banner (QoD={qod}%). "
                "Unverified without exact installed package, backport patch, or configuration audit."
            )

        else:
            # Finding has specific version claim and CVE from scanner, but TunnelTrace has no local pinned advisory DB
            correlation_status = CorrelationStatus.POTENTIAL
            correlation_method = "UNVERIFIED_SCANNER_ASSERTION"
            cve_applicability = CveApplicabilityState.NO_RELIABLE_ADVISORY_DATA
            rationale = (
                f"Scanner asserted vulnerability for {finding.source_product_claim or 'software'} "
                f"version {finding.source_version_claim} (QoD={qod}%). "
                "Authoritative vendor advisory correlation deferred to Stage 16."
            )

        return CorrelatedFindingResult(
            finding=finding,
            asset_link_state=asset_link_state,
            asset_link_rationale=asset_link_rationale,
            mapped_host_id=mapped_host_id,
            correlation_status=correlation_status,
            correlation_method=correlation_method,
            cve_applicability_state=cve_applicability,
            correlation_rationale=rationale,
        )

    @classmethod
    def correlate_report(
        cls,
        parsed_report: ParsedGreenboneReport,
        authorized_scope_targets: list[str],
        discovered_hosts: Sequence[DiscoveredHost],
    ) -> tuple[dict[str, CorrelatedHostResult], list[CorrelatedFindingResult]]:
        """Correlate all hosts and findings within a parsed report."""
        host_map: dict[str, CorrelatedHostResult] = {}
        for host_ip in parsed_report.unique_hosts:
            host_map[host_ip] = cls.evaluate_host_mapping(
                host_ip=host_ip,
                authorized_scope_targets=authorized_scope_targets,
                discovered_hosts=discovered_hosts,
            )

        correlated_findings: list[CorrelatedFindingResult] = []
        for finding in parsed_report.findings:
            host_corr = host_map.get(
                finding.host_ip,
                CorrelatedHostResult(
                    host_ip=finding.host_ip,
                    asset_link_state=AssetLinkState.UNLINKED_NO_DISCOVERY_RECORD,
                    asset_link_rationale="Host not pre-evaluated in mapping pass",
                    mapped_host_id=None,
                    is_out_of_scope=False,
                ),
            )
            correlated_findings.append(cls.correlate_finding(finding, host_corr))

        return host_map, correlated_findings
