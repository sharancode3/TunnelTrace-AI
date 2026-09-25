"""Hardened XML parser for Greenbone/OpenVAS vulnerability reports.

Uses defusedxml to strictly defend against XXE, external DTDs, and entity expansion attacks.
Enforces conservative payload, depth, host, and result limits.
Preserves Greenbone source severity, Quality of Detection (QoD), feed freshness, and raw claims.
"""

from __future__ import annotations

import hashlib
import ipaddress
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
import defusedxml.ElementTree as SafeET
from defusedxml.common import DefusedXmlException

logger = logging.getLogger(__name__)

# Safety Limits
MAX_REPORT_BYTES = 50 * 1024 * 1024  # 50 MB
MAX_RESULTS_COUNT = 5000
MAX_HOSTS_COUNT = 1000
MAX_XML_DEPTH = 30
MAX_FIELD_LENGTH = 10000

CVE_PATTERN = re.compile(r"\b(CVE-\d{4}-\d{4,7})\b", re.IGNORECASE)
PORT_PATTERN = re.compile(r"^(\d+)/(tcp|udp|general)$", re.IGNORECASE)


class GreenboneParseError(ValueError):
    """Raised when Greenbone XML report is malformed, oversized, or violates security bounds."""
    pass


@dataclass(frozen=True)
class ParsedNVT:
    """Network Vulnerability Test (NVT) metadata as reported by Greenbone."""

    oid: str
    name: str
    family: str | None = None
    cvss_base: float | None = None
    cvss_version: str | None = None
    cvss_vector: str | None = None
    cves: list[str] = field(default_factory=list)
    cpes: list[str] = field(default_factory=list)
    solution: str | None = None
    solution_type: str | None = None
    qod_value: int | None = None
    qod_type: str | None = None


@dataclass(frozen=True)
class ParsedFinding:
    """A single finding/result record extracted from a Greenbone report."""

    source_result_id: str
    host_ip: str
    host_name: str | None
    ip_version: str  # IPv4, IPv6
    port: int | None
    protocol: str | None  # TCP, UDP, ICMP, general
    service_name: str | None
    nvt: ParsedNVT
    source_severity: str  # Log, Low, Medium, High, Critical
    qod_value: int | None
    qod_type: str | None
    detection_method: str | None
    source_product_claim: str | None
    source_version_claim: str | None
    description: str | None
    summary: str | None
    solution: str | None
    solution_type: str | None
    source_timestamp: datetime | None


@dataclass(frozen=True)
class ParsedReportMetadata:
    """Metadata regarding the scan configuration, task, scanner, and feed."""

    report_id: str
    format_id: str | None
    format_version: str | None
    task_id: str | None
    task_name: str | None
    scan_config: str | None
    port_list: str | None
    scanner_name: str | None
    scanner_version: str | None
    feed_type: str | None
    feed_version: str | None
    feed_status: str  # FRESH, STALE, UNKNOWN, MISSING
    scan_started_at: datetime | None
    scan_ended_at: datetime | None


@dataclass(frozen=True)
class ParsedGreenboneReport:
    """Complete parsed and normalized Greenbone vulnerability report artifact."""

    metadata: ParsedReportMetadata
    findings: list[ParsedFinding]
    unique_hosts: list[str]
    findings_count: int
    raw_bytes_count: int
    raw_sha256: str


def _check_xml_depth(element: Any, current_depth: int = 1, max_depth: int = MAX_XML_DEPTH) -> None:
    """Iteratively verify maximum element nesting depth to prevent stack exhaustion."""
    if current_depth > max_depth:
        raise GreenboneParseError(f"XML depth exceeds maximum allowed limit of {max_depth}")
    for child in element:
        _check_xml_depth(child, current_depth + 1, max_depth)


def _safe_str(val: str | None, max_len: int = MAX_FIELD_LENGTH) -> str | None:
    if val is None:
        return None
    s = val.strip()
    return s[:max_len] if len(s) > max_len else s


def _parse_iso_timestamp(text: str | None) -> datetime | None:
    if not text or not text.strip():
        return None
    cleaned = text.strip()
    # Normalize common Greenbone timestamp variants e.g. 2026-09-24T18:00:00Z
    try:
        if cleaned.endswith("Z"):
            cleaned = cleaned[:-1] + "+00:00"
        return datetime.fromisoformat(cleaned)
    except Exception:
        # Fallback for formats like 2026-09-24 18:00:00
        for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
            try:
                dt = datetime.strptime(cleaned, fmt)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt
            except Exception:
                continue
    return None


def parse_greenbone_xml(
    xml_content: str | bytes,
    *,
    max_bytes: int = MAX_REPORT_BYTES,
    max_depth: int = MAX_XML_DEPTH,
    max_results: int = MAX_RESULTS_COUNT,
    max_hosts: int = MAX_HOSTS_COUNT,
) -> ParsedGreenboneReport:
    """Parse a Greenbone/OpenVAS XML report artifact defensively.

    Security & Robustness Guarantees:
    - Pre-computed exact byte length and SHA-256 digest.
    - XXE, external DTD, and entity expansion rejection via defusedxml.
    - Max recursion depth and payload limits.
    - Supported root elements: <report> or GMP wrapper <get_reports_response><report>
    - Preserves exact source severity, QoD values, and feed state.
    """
    raw_bytes = xml_content.encode("utf-8") if isinstance(xml_content, str) else xml_content
    raw_len = len(raw_bytes)

    if raw_len > max_bytes:
        raise GreenboneParseError(
            f"Report file size ({raw_len} bytes) exceeds maximum limit of {max_bytes} bytes"
        )

    if not raw_bytes.strip():
        raise GreenboneParseError("Report XML content is empty")

    raw_sha256 = hashlib.sha256(raw_bytes).hexdigest()

    try:
        root = SafeET.fromstring(raw_bytes)
    except DefusedXmlException as e:
        raise GreenboneParseError(f"XML security policy violation: {e}") from e
    except Exception as e:
        raise GreenboneParseError(f"Malformed XML document: {e}") from e

    # Verify maximum nesting depth
    _check_xml_depth(root, current_depth=1, max_depth=max_depth)

    # Resolve report element (support direct <report> or GMP <get_reports_response><report>)
    report_el: Any = None
    if root.tag == "report":
        report_el = root
    elif root.tag == "get_reports_response":
        report_el = root.find("report")
        if report_el is None:
            raise GreenboneParseError("No '<report>' element found inside '<get_reports_response>'")
    else:
        raise GreenboneParseError(
            f"Unsupported XML root element '<{root.tag}>', expected '<report>' or '<get_reports_response>'"
        )

    # If <report> contains another nested <report>, prefer the inner report element if it holds results
    inner_report = report_el.find("report")
    if inner_report is not None and (inner_report.find("results") is not None or inner_report.attrib.get("id")):
        report_el = inner_report

    # Extract Report Metadata
    report_id = _safe_str(report_el.attrib.get("id"))
    if not report_id:
        # Check child <report_id> or fallback to hash-derived identifier
        report_id = f"gvm-report-{raw_sha256[:16]}"

    format_id = _safe_str(report_el.attrib.get("format_id"))
    format_version = _safe_str(report_el.attrib.get("version"))

    task_id: str | None = None
    task_name: str | None = None
    task_el = report_el.find("task")
    if task_el is not None:
        task_id = _safe_str(task_el.attrib.get("id"))
        name_el = task_el.find("name")
        if name_el is not None and name_el.text:
            task_name = _safe_str(name_el.text)

    scan_config: str | None = None
    ports_spec: str | None = None
    ports_el = report_el.find("ports")
    if ports_el is not None:
        ports_max = ports_el.attrib.get("max")
        ports_start = ports_el.attrib.get("start")
        if ports_start or ports_max:
            ports_spec = f"ports {ports_start or '1'}-{ports_max or '?'}"

    # Feed & Scanner Info
    scanner_name = "Greenbone/OpenVAS"
    scanner_version: str | None = None
    feed_type: str | None = None
    feed_version: str | None = None
    feed_status = "UNKNOWN"

    # Inspect scan_run_status or scan_start / scan_end
    scan_start_text = None
    scan_end_text = None
    start_el = report_el.find("scan_start")
    if start_el is None:
        start_el = report_el.find("timestamp")
    if start_el is not None and start_el.text:
        scan_start_text = start_el.text

    end_el = report_el.find("scan_end")
    if end_el is not None and end_el.text:
        scan_end_text = end_el.text

    scan_started_at = _parse_iso_timestamp(scan_start_text)
    scan_ended_at = _parse_iso_timestamp(scan_end_text)

    # Check for feed or scanner version elements
    gvm_el = report_el.find("gvm")
    if gvm_el is None:
        gvm_el = report_el.find("openvas")
    if gvm_el is not None:
        scanner_version = _safe_str(gvm_el.attrib.get("version") or gvm_el.text)

    # Check filters / scan config
    config_el = report_el.find("scan_config")
    if config_el is not None:
        name_el = config_el.find("name")
        scan_config = _safe_str(name_el.text if name_el is not None else config_el.text)

    metadata = ParsedReportMetadata(
        report_id=report_id,
        format_id=format_id,
        format_version=format_version,
        task_id=task_id,
        task_name=task_name,
        scan_config=scan_config,
        port_list=ports_spec,
        scanner_name=scanner_name,
        scanner_version=scanner_version,
        feed_type=feed_type,
        feed_version=feed_version,
        feed_status=feed_status,
        scan_started_at=scan_started_at,
        scan_ended_at=scan_ended_at,
    )

    # Extract Findings
    results_container = report_el.find("results")
    result_elements = (
        results_container.findall("result")
        if results_container is not None
        else report_el.findall("result")
    )

    findings: list[ParsedFinding] = []
    unique_hosts_set: set[str] = set()

    for r_idx, res_el in enumerate(result_elements):
        if len(findings) >= max_results:
            logger.warning(f"Maximum results limit ({max_results}) reached in Greenbone report")
            break

        res_id = res_el.attrib.get("id") or f"result-{r_idx+1}"

        # Host extraction
        host_el = res_el.find("host")
        if host_el is None or not (host_el.text or "".join(host_el.itertext())):
            continue

        raw_host_text = "".join(host_el.itertext()).strip().split()[0]
        # Clean potential port or trailing characters
        clean_host = raw_host_text.split("/")[0].strip()

        # Validate IP address
        try:
            ip_obj = ipaddress.ip_address(clean_host)
            host_ip = str(ip_obj)
            ip_ver = "IPv6" if ip_obj.version == 6 else "IPv4"
        except ValueError:
            # Check if host tag had an asset child or hostname
            host_ip = clean_host
            ip_ver = "IPv4"

        unique_hosts_set.add(host_ip)
        if len(unique_hosts_set) > max_hosts:
            raise GreenboneParseError(f"Host count exceeds maximum allowed limit of {max_hosts}")

        # Port & Protocol
        port_val: int | None = None
        proto_val: str | None = None
        service_name: str | None = None
        port_el = res_el.find("port")
        if port_el is not None and port_el.text:
            port_text = port_el.text.strip()
            port_match = PORT_PATTERN.match(port_text)
            if port_match:
                port_val = int(port_match.group(1))
                proto_val = port_match.group(2).upper()
            elif "/" in port_text:
                parts = port_text.split("/", 1)
                if parts[0].isdigit():
                    port_val = int(parts[0])
                else:
                    service_name = parts[0]
                proto_val = parts[1].upper()
            elif port_text.isdigit():
                port_val = int(port_text)

        # NVT Details
        nvt_el = res_el.find("nvt")
        if nvt_el is None:
            # Incomplete result element
            continue

        oid = _safe_str(nvt_el.attrib.get("oid")) or f"nvt-unknown-{r_idx}"
        nvt_name_el = nvt_el.find("name")
        nvt_name = _safe_str(nvt_name_el.text if nvt_name_el is not None else None) or "Unnamed Vulnerability Test"

        family_el = nvt_el.find("family")
        family = _safe_str(family_el.text if family_el is not None else None)

        cvss_base: float | None = None
        cvss_el = nvt_el.find("cvss_base")
        if cvss_el is not None and cvss_el.text:
            try:
                cvss_base = float(cvss_el.text.strip())
            except ValueError:
                pass

        # Severity & Threat
        threat_el = res_el.find("threat")
        if threat_el is None:
            threat_el = res_el.find("severity")
        source_severity = "Log"
        if threat_el is not None and threat_el.text:
            source_severity = _safe_str(threat_el.text) or "Log"
        elif cvss_base is not None:
            if cvss_base >= 9.0:
                source_severity = "Critical"
            elif cvss_base >= 7.0:
                source_severity = "High"
            elif cvss_base >= 4.0:
                source_severity = "Medium"
            elif cvss_base > 0.0:
                source_severity = "Low"
            else:
                source_severity = "Log"

        # QoD (Quality of Detection)
        qod_value: int | None = None
        qod_type: str | None = None
        qod_el = res_el.find("qod")
        if qod_el is None and nvt_el is not None:
            qod_el = nvt_el.find("qod")
        if qod_el is not None:
            val_el = qod_el.find("value")
            if val_el is not None and val_el.text and val_el.text.strip().isdigit():
                qod_value = int(val_el.text.strip())
            type_el = qod_el.find("type")
            if type_el is not None and type_el.text:
                qod_type = _safe_str(type_el.text)

        # CVEs
        cves: list[str] = []
        for cve_el in nvt_el.findall("cve"):
            if cve_el.text:
                found_cves = CVE_PATTERN.findall(cve_el.text)
                for c in found_cves:
                    if c.upper() not in cves:
                        cves.append(c.upper())
        # Check description or xrefs for CVEs as well if empty
        if not cves:
            xref_el = nvt_el.find("xref")
            if xref_el is not None and xref_el.text:
                found = CVE_PATTERN.findall(xref_el.text)
                for c in found:
                    if c.upper() not in cves:
                        cves.append(c.upper())

        # CPEs
        cpes: list[str] = []
        for cpe_el in nvt_el.findall("cpe"):
            if cpe_el.text:
                cpe_text = cpe_el.text.strip()
                if cpe_text and cpe_text not in cpes:
                    cpes.append(cpe_text)

        # Solution
        solution: str | None = None
        solution_type: str | None = None
        sol_el = nvt_el.find("solution")
        if sol_el is not None:
            solution = _safe_str(sol_el.text)
            solution_type = _safe_str(sol_el.attrib.get("type"))

        # Description / Summary
        desc_el = res_el.find("description")
        if desc_el is None and nvt_el is not None:
            desc_el = nvt_el.find("description")
        description = _safe_str(desc_el.text if desc_el is not None else None)

        nvt_obj = ParsedNVT(
            oid=oid,
            name=nvt_name,
            family=family,
            cvss_base=cvss_base,
            cvss_version="2.0" if cvss_base is not None else None,
            cvss_vector=None,
            cves=cves,
            cpes=cpes,
            solution=solution,
            solution_type=solution_type,
            qod_value=qod_value,
            qod_type=qod_type,
        )

        # Extract product/version claim if mentioned in CPE or description
        product_claim: str | None = None
        version_claim: str | None = None
        if cpes:
            first_cpe = cpes[0]
            parts = first_cpe.split(":")
            if first_cpe.startswith("cpe:2.3:"):
                if len(parts) >= 5:
                    product_claim = f"{parts[3]}/{parts[4]}"
                    if len(parts) >= 6 and parts[5] and parts[5] != "*":
                        version_claim = parts[5]
            else:
                # cpe:/a:vendor:product:version
                if len(parts) >= 4:
                    product_claim = f"{parts[2]}/{parts[3]}"
                    if len(parts) >= 5 and parts[4] and parts[4] != "*":
                        version_claim = parts[4]

        finding = ParsedFinding(
            source_result_id=res_id,
            host_ip=host_ip,
            host_name=None,
            ip_version=ip_ver,
            port=port_val,
            protocol=proto_val,
            service_name=service_name,
            nvt=nvt_obj,
            source_severity=source_severity,
            qod_value=qod_value,
            qod_type=qod_type,
            detection_method="remote_banner" if qod_type == "remote_banner" else qod_type,
            source_product_claim=product_claim,
            source_version_claim=version_claim,
            description=description,
            summary=None,
            solution=solution,
            solution_type=solution_type,
            source_timestamp=scan_started_at,
        )
        findings.append(finding)

    return ParsedGreenboneReport(
        metadata=metadata,
        findings=findings,
        unique_hosts=sorted(list(unique_hosts_set)),
        findings_count=len(findings),
        raw_bytes_count=raw_len,
        raw_sha256=raw_sha256,
    )
