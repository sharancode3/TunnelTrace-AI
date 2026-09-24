"""Safe Nmap XML parser with defusedxml, strict size limits, and ambiguity preservation."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
import defusedxml.ElementTree as SafeET

from app.core.config import settings


class NmapParseError(ValueError):
    """Raised when Nmap XML output is malformed, oversized, or fails schema verification."""
    pass


@dataclass(frozen=True)
class ParsedServiceObservation:
    protocol: str  # TCP, UDP
    port: int
    state: str  # OPEN, CLOSED, FILTERED, OPEN_OR_FILTERED, UNFILTERED
    state_reason: str | None = None
    service_name: str | None = None
    product: str | None = None
    version: str | None = None
    extra_info: str | None = None
    confidence: float | None = None
    fingerprint: str | None = None


@dataclass(frozen=True)
class ParsedHostObservation:
    ip_address: str
    ip_version: str  # IPv4, IPv6
    state: str  # UP, DOWN, UNKNOWN
    hostnames: list[str] = field(default_factory=list)
    services: list[ParsedServiceObservation] = field(default_factory=list)


@dataclass(frozen=True)
class ParsedDiscoveryResult:
    tool_version: str | None
    hosts: list[ParsedHostObservation]
    hosts_up_count: int
    services_discovered_count: int
    has_ambiguity: bool


def parse_nmap_xml(xml_content: str | bytes, *, max_bytes: int | None = None) -> ParsedDiscoveryResult:
    """Parse Nmap machine-readable XML output safely.

    Uses defusedxml to prevent XML entity expansion (Billion Laughs) and external DTD attacks.
    Enforces maximum payload size limit.
    Preserves raw UDP ambiguous states (open|filtered).
    Extracts host and port observations without making vulnerability claims.
    """
    byte_limit = max_bytes or settings.DISCOVERY_MAX_OUTPUT_BYTES

    # Check input size
    raw_bytes = xml_content.encode("utf-8") if isinstance(xml_content, str) else xml_content
    if len(raw_bytes) > byte_limit:
        raise NmapParseError(
            f"Nmap XML output size ({len(raw_bytes)} bytes) exceeds maximum limit of {byte_limit} bytes"
        )

    if not raw_bytes.strip():
        raise NmapParseError("Nmap XML output is empty")

    try:
        root = SafeET.fromstring(raw_bytes)
    except Exception as e:
        raise NmapParseError(f"Malformed XML document: {e}") from e

    # Verify root element
    if root.tag != "nmaprun":
        raise NmapParseError(f"Unexpected XML root element '<{root.tag}>', expected '<nmaprun>'")

    scanner_attr = root.attrib.get("scanner", "").lower()
    if scanner_attr and scanner_attr != "nmap":
        raise NmapParseError(f"Unsupported scanner attribute '{scanner_attr}', expected 'nmap'")

    tool_version = root.attrib.get("version")

    hosts: list[ParsedHostObservation] = []
    hosts_up_count = 0
    services_discovered_count = 0
    has_ambiguity = False

    for host_el in root.findall("host"):
        # Determine host state
        status_el = host_el.find("status")
        state_str = status_el.attrib.get("state", "unknown").upper() if status_el is not None else "UNKNOWN"
        if state_str not in ("UP", "DOWN", "UNKNOWN"):
            state_str = "UNKNOWN"

        if state_str == "UP":
            hosts_up_count += 1

        # Extract address
        ip_addr = None
        ip_ver = "IPv4"
        for addr_el in host_el.findall("address"):
            addr_type = addr_el.attrib.get("addrtype", "")
            if addr_type in ("ipv4", "ipv6"):
                ip_addr = addr_el.attrib.get("addr")
                ip_ver = "IPv6" if addr_type == "ipv6" else "IPv4"
                break

        if not ip_addr:
            # Skip or treat as unknown host without address
            continue

        # Extract hostnames
        hostnames: list[str] = []
        hostnames_el = host_el.find("hostnames")
        if hostnames_el is not None:
            for hn_el in hostnames_el.findall("hostname"):
                name = hn_el.attrib.get("name")
                if name and name not in hostnames:
                    hostnames.append(name)

        # Extract ports / services
        services: list[ParsedServiceObservation] = []
        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                proto = port_el.attrib.get("protocol", "tcp").upper()
                try:
                    port_num = int(port_el.attrib.get("portid", 0))
                except (ValueError, TypeError):
                    continue

                state_el = port_el.find("state")
                raw_state = state_el.attrib.get("state", "unknown").lower() if state_el is not None else "unknown"
                state_reason = state_el.attrib.get("reason") if state_el is not None else None

                # Canonicalize state and preserve ambiguity
                if raw_state == "open":
                    port_state = "OPEN"
                elif raw_state in ("open|filtered", "open_or_filtered"):
                    port_state = "OPEN_OR_FILTERED"
                    has_ambiguity = True
                elif raw_state == "closed":
                    port_state = "CLOSED"
                elif raw_state == "filtered":
                    port_state = "FILTERED"
                elif raw_state == "unfiltered":
                    port_state = "UNFILTERED"
                else:
                    port_state = "UNKNOWN"
                    has_ambiguity = True

                # Extract service metadata
                svc_name = None
                product = None
                version = None
                extra_info = None
                confidence = None
                fingerprint = None

                svc_el = port_el.find("service")
                if svc_el is not None:
                    svc_name = svc_el.attrib.get("name")
                    product = svc_el.attrib.get("product")
                    version = svc_el.attrib.get("version")
                    extra_info = svc_el.attrib.get("extrainfo")
                    conf_str = svc_el.attrib.get("conf")
                    if conf_str is not None:
                        try:
                            confidence = float(conf_str)
                        except ValueError:
                            confidence = None
                    fingerprint = svc_el.attrib.get("servicefp")

                obs = ParsedServiceObservation(
                    protocol=proto,
                    port=port_num,
                    state=port_state,
                    state_reason=state_reason,
                    service_name=svc_name,
                    product=product,
                    version=version,
                    extra_info=extra_info,
                    confidence=confidence,
                    fingerprint=fingerprint,
                )
                services.append(obs)
                services_discovered_count += 1

        hosts.append(
            ParsedHostObservation(
                ip_address=ip_addr,
                ip_version=ip_ver,
                state=state_str,
                hostnames=hostnames,
                services=services,
            )
        )

    return ParsedDiscoveryResult(
        tool_version=tool_version,
        hosts=hosts,
        hosts_up_count=hosts_up_count,
        services_discovered_count=services_discovered_count,
        has_ambiguity=has_ambiguity,
    )
