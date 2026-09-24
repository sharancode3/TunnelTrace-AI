"""Deterministic parser for ike-scan stdout output.

Adheres strictly to observational facts:
- Distinguishes RESPONDED_HANDSHAKE, RESPONDED_NOTIFY, NO_RESPONSE, and TOOL_ERROR
- Does not assert security verdicts (vulnerable/secure)
- Labels IKEv2 probes as experimental
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class IkeScanParsedResponse:
    target_ip: str
    target_port: int
    response_category: str  # RESPONDED_HANDSHAKE, RESPONDED_NOTIFY, NO_RESPONSE, TOOL_ERROR, TOOL_UNAVAILABLE
    ike_version: str  # "IKEv1", "IKEv2", "UNKNOWN"
    handshake_type: str | None = None
    notify_code: int | None = None
    notify_message: str | None = None
    vendor_ids: list[str] = field(default_factory=list)
    transforms_returned: list[dict[str, Any]] = field(default_factory=list)
    rtt_ms: float | None = None
    is_experimental: bool = False
    raw_response_text: str | None = None
    summary: str = ""


# Regex patterns for ike-scan output lines
# Example line 1: 192.168.1.1	Main Mode Handshake returned
# Example line 2: 192.168.1.1	IKEv2 SA_INIT Handshake returned
HANDSHAKE_PATTERN = re.compile(
    r"^([0-9a-fA-F.:]+)\s+([^\n\r]+?Handshake\s+returned)",
    re.MULTILINE | re.IGNORECASE,
)

# Example line: 192.168.1.1	Notify message 14 (NO-PROPOSAL-CHOSEN)
NOTIFY_PATTERN = re.compile(
    r"^([0-9a-fA-F.:]+)\s+Notify\s+message\s+(\d+)\s*(?:\(([^)]+)\))?",
    re.MULTILINE | re.IGNORECASE,
)

# SA attribute parser: SA=(Enc=3DES Hash=SHA1 Auth=PSK Group=2:modp1024 LifeType=Seconds LifeDuration=28800)
SA_PATTERN = re.compile(r"SA=\(([^)]+)\)", re.IGNORECASE)

# VID pattern: VID=1234567890abcdef (Cisco Unity) or VID=1234567890abcdef
VID_PATTERN = re.compile(r"VID=([0-9a-fA-F]+(?:\s*\([^)]+\))?)", re.IGNORECASE)

# Summary line: Ending ike-scan 1.9: 1 hosts scanned in 0.052 seconds ... 1 returned handshake; 0 returned notify
SUMMARY_PATTERN = re.compile(
    r"Ending ike-scan.*?(\d+)\s+returned\s+handshake;\s*(\d+)\s+returned\s+notify",
    re.IGNORECASE,
)

# Time duration line: scanned in 0.052 seconds
DURATION_PATTERN = re.compile(r"scanned in ([0-9.]+)\s+seconds", re.IGNORECASE)


def parse_sa_attributes(sa_text: str) -> dict[str, Any]:
    """Parse key=value tokens from an SA=(...) string into a structured dictionary."""
    details: dict[str, Any] = {"raw_sa": sa_text.strip()}
    tokens = sa_text.strip().split()
    for token in tokens:
        if "=" in token:
            k, v = token.split("=", 1)
            key_clean = k.strip().lower()
            val_clean = v.strip()
            if key_clean == "enc":
                details["encr"] = val_clean
            elif key_clean == "hash":
                details["hash"] = val_clean
            elif key_clean == "auth":
                details["auth"] = val_clean
            elif key_clean == "group":
                details["dh_group"] = val_clean
            elif key_clean == "lifetype":
                details["life_type"] = val_clean
            elif key_clean == "lifeduration":
                details["life_duration"] = val_clean
            else:
                details[key_clean] = val_clean
    return details


def parse_ike_scan_output(
    raw_output: str,
    target_ip: str,
    target_port: int = 500,
    is_experimental: bool = False,
) -> IkeScanParsedResponse:
    """Parse raw stdout from ike-scan into a typed IkeScanParsedResponse."""
    text = raw_output or ""
    vendor_ids: list[str] = []
    transforms: list[dict[str, Any]] = []
    rtt_ms: float | None = None
    ike_version = "IKEv2" if is_experimental else "IKEv1"

    # Extract scan duration / RTT if available
    dur_match = DURATION_PATTERN.search(text)
    if dur_match:
        try:
            rtt_ms = round(float(dur_match.group(1)) * 1000.0, 2)
        except ValueError:
            pass

    # Extract Vendor IDs
    for vid_match in VID_PATTERN.finditer(text):
        vid_str = vid_match.group(1).strip()
        if vid_str and vid_str not in vendor_ids:
            vendor_ids.append(vid_str)

    # Extract SAs
    for sa_match in SA_PATTERN.finditer(text):
        sa_str = sa_match.group(1)
        parsed_sa = parse_sa_attributes(sa_str)
        transforms.append(parsed_sa)

    # 1. Check for Handshake
    hs_match = HANDSHAKE_PATTERN.search(text)
    if hs_match:
        hs_type = hs_match.group(2).strip()
        if "IKEv2" in hs_type or is_experimental:
            ike_version = "IKEv2"
        else:
            ike_version = "IKEv1"

        summary = f"Received {hs_type} from {target_ip}:{target_port}"
        if transforms:
            cipher = transforms[0].get("encr", "unknown")
            summary += f" with cipher {cipher}"

        return IkeScanParsedResponse(
            target_ip=target_ip,
            target_port=target_port,
            response_category="RESPONDED_HANDSHAKE",
            ike_version=ike_version,
            handshake_type=hs_type,
            vendor_ids=vendor_ids,
            transforms_returned=transforms,
            rtt_ms=rtt_ms,
            is_experimental=is_experimental,
            raw_response_text=text,
            summary=summary,
        )

    # 2. Check for Notify
    notify_match = NOTIFY_PATTERN.search(text)
    if notify_match:
        code_str = notify_match.group(2)
        notify_code = int(code_str) if code_str else None
        notify_msg = notify_match.group(3) or f"Notify {notify_code}"

        return IkeScanParsedResponse(
            target_ip=target_ip,
            target_port=target_port,
            response_category="RESPONDED_NOTIFY",
            ike_version=ike_version,
            notify_code=notify_code,
            notify_message=notify_msg,
            vendor_ids=vendor_ids,
            transforms_returned=transforms,
            rtt_ms=rtt_ms,
            is_experimental=is_experimental,
            raw_response_text=text,
            summary=f"Target {target_ip}:{target_port} returned notify code {notify_code} ({notify_msg})",
        )

    # 3. Check for 0 handshakes returned (No response)
    sum_match = SUMMARY_PATTERN.search(text)
    if sum_match:
        hs_count = int(sum_match.group(1))
        notify_count = int(sum_match.group(2))
        if hs_count == 0 and notify_count == 0:
            return IkeScanParsedResponse(
                target_ip=target_ip,
                target_port=target_port,
                response_category="NO_RESPONSE",
                ike_version=ike_version,
                vendor_ids=vendor_ids,
                transforms_returned=[],
                rtt_ms=rtt_ms,
                is_experimental=is_experimental,
                raw_response_text=text,
                summary=f"No IKE response received from {target_ip}:{target_port} within retry/timeout limits",
            )

    # 4. Fallback / Ambiguous / Error
    if "ERROR" in text.upper() or "FAILED" in text.upper():
        return IkeScanParsedResponse(
            target_ip=target_ip,
            target_port=target_port,
            response_category="TOOL_ERROR",
            ike_version=ike_version,
            is_experimental=is_experimental,
            raw_response_text=text,
            summary=f"Scanner execution returned an error while probing {target_ip}:{target_port}",
        )

    return IkeScanParsedResponse(
        target_ip=target_ip,
        target_port=target_port,
        response_category="NO_RESPONSE",
        ike_version=ike_version,
        is_experimental=is_experimental,
        raw_response_text=text,
        summary=f"No conclusive IKE response from {target_ip}:{target_port}",
    )
