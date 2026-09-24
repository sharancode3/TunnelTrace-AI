"""Scope validation and target canonicalization for Stage 2 Discovery."""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from app.core.config import settings
from app.discovery.profiles import DiscoveryProfile, SCAN_PROFILES


class ScopeValidationError(ValueError):
    """Raised when scan target, port, or scope fails validation."""
    pass


class AuthorizationError(PermissionError):
    """Raised when operator authorization attestation is missing or invalid."""
    pass


HOSTNAME_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
)


@dataclass(frozen=True)
class ValidatedScope:
    operator_id: str
    authorization_reference: str
    authorization_attestation: str
    authorized_at: datetime
    profile: DiscoveryProfile
    protocol: str
    requested_targets: list[str]
    canonical_targets: list[str]  # Exactly the discrete, resolved IP strings passed to scanner
    exclusions: list[str]
    permitted_ports: list[int]
    resolved_host_map: dict[str, list[str]] = field(default_factory=dict)

    @property
    def target_count(self) -> int:
        return len(self.canonical_targets)


def validate_scope_request(
    *,
    operator_id: str,
    authorization_reference: str,
    authorization_attestation: str,
    profile_name: str,
    requested_targets: list[str],
    exclusions: list[str] | None = None,
    permitted_ports: list[int] | None = None,
    max_targets: int | None = None,
    max_ports: int | None = None,
) -> ValidatedScope:
    """Validate and canonicalize all elements of a discovery request before execution.

    Enforces:
    - Master toggle: DISCOVERY_ENABLED must be True
    - Explicit non-empty operator ID and authorization reference
    - Explicit attestation statement (minimum 10 characters)
    - Profile allowlist matching
    - Canonical IP / CIDR validation, rejecting multicast, broadcast, and unspecified addresses
    - Hostname syntax validation and single-point-in-time DNS resolution pinning
    - Pre-execution exclusion filtering
    - Strict target expansion and port caps
    """
    if not settings.DISCOVERY_ENABLED:
        raise ScopeValidationError("Discovery subsystem is disabled by configuration (DISCOVERY_ENABLED=False)")

    # 1. Authorization checks
    op_id = (operator_id or "").strip()
    if not op_id:
        raise AuthorizationError("operator_id is required")

    auth_ref = (authorization_reference or "").strip()
    if not auth_ref:
        raise AuthorizationError("authorization_reference is required (e.g. ticket ID, engagement code)")

    auth_att = (authorization_attestation or "").strip()
    if len(auth_att) < 10:
        raise AuthorizationError(
            "authorization_attestation must contain an explicit statement confirming authorized testing scope"
        )

    # 2. Profile validation
    try:
        profile = DiscoveryProfile(profile_name)
    except ValueError:
        valid_names = [p.value for p in DiscoveryProfile]
        raise ScopeValidationError(f"Invalid profile '{profile_name}'. Must be one of: {valid_names}")

    profile_cfg = SCAN_PROFILES[profile]
    protocol = profile_cfg.default_protocol

    # 3. Ports validation
    port_cap = max_ports or settings.DISCOVERY_MAX_PORTS
    ports_to_use = permitted_ports if permitted_ports is not None and len(permitted_ports) > 0 else profile_cfg.default_ports
    
    unique_ports = sorted(list(set(ports_to_use)))
    if not unique_ports:
        raise ScopeValidationError("At least one permitted port must be specified or defaulted from profile")

    if len(unique_ports) > port_cap:
        raise ScopeValidationError(
            f"Requested {len(unique_ports)} ports exceeds maximum port limit of {port_cap}"
        )

    for p in unique_ports:
        if not isinstance(p, int) or p < 1 or p > 65535:
            raise ScopeValidationError(f"Invalid port '{p}'. Ports must be integers in the range 1-65535")

    # 4. Target expansion and canonicalization
    target_cap = max_targets or settings.DISCOVERY_MAX_TARGETS
    if not requested_targets or not isinstance(requested_targets, list) or len(requested_targets) == 0:
        raise ScopeValidationError("requested_targets cannot be empty. At least one target is required.")

    # Parse exclusions first
    parsed_exclusions: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    canonical_exclusions: list[str] = []
    if exclusions:
        for ex in exclusions:
            ex_str = str(ex).strip()
            if not ex_str:
                continue
            try:
                ex_net = ipaddress.ip_network(ex_str, strict=False)
                parsed_exclusions.append(ex_net)
                canonical_exclusions.append(str(ex_net))
            except ValueError as e:
                raise ScopeValidationError(f"Invalid exclusion '{ex_str}': {e}")

    # Process and expand targets
    candidate_ips: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    resolved_host_map: dict[str, list[str]] = {}

    for raw_target in requested_targets:
        target_str = str(raw_target).strip()
        if not target_str:
            continue

        # Check for disallowed wildcards / all keywords
        if target_str in ("*", "all", "0.0.0.0/0", "::/0"):
            raise ScopeValidationError(f"Wildcard target '{target_str}' is strictly prohibited.")

        # Attempt IP or CIDR parsing
        is_ip_net = False
        net = None
        try:
            net = ipaddress.ip_network(target_str, strict=False)
            is_ip_net = True
        except ValueError:
            pass

        if is_ip_net and net is not None:
            _validate_network_safety(net)

            # Check network size
            if net.num_addresses > target_cap:
                raise ScopeValidationError(
                    f"CIDR target '{target_str}' contains {net.num_addresses} addresses, "
                    f"exceeding max target cap of {target_cap}"
                )

            # For single IP (/32 or /128)
            if net.num_addresses == 1:
                candidate_ips.append(net.network_address)
            else:
                # Expand usable hosts
                for host in net.hosts():
                    candidate_ips.append(host)
            continue

        # Validate hostname syntax
        if len(target_str) > 253 or not HOSTNAME_REGEX.match(target_str):
            raise ScopeValidationError(f"Invalid target '{target_str}': neither a valid IP/CIDR nor a valid hostname")

        # Resolve hostname once beforehand to pin targets
        try:
            addr_infos = socket.getaddrinfo(target_str, None)
        except socket.gaierror as e:
            raise ScopeValidationError(f"Failed to resolve hostname '{target_str}': {e}")

        resolved_ips_for_host: list[str] = []
        for info in addr_infos:
            ip_str = info[4][0]
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                _validate_ip_safety(ip_obj)
                if ip_obj not in candidate_ips:
                    candidate_ips.append(ip_obj)
                if ip_str not in resolved_ips_for_host:
                    resolved_ips_for_host.append(ip_str)
            except ValueError as e:
                raise ScopeValidationError(f"Resolved IP '{ip_str}' for '{target_str}' is invalid: {e}")

        resolved_host_map[target_str] = resolved_ips_for_host

    # Deduplicate candidate IPs while preserving deterministic ordering
    unique_candidates: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    seen = set()
    for ip in candidate_ips:
        if ip not in seen:
            seen.add(ip)
            unique_candidates.append(ip)

    # 5. Apply exclusions
    final_ips: list[str] = []
    for ip in unique_candidates:
        excluded = False
        for ex_net in parsed_exclusions:
            if ip in ex_net:
                excluded = True
                break
        if not excluded:
            final_ips.append(str(ip))

    # 6. Final safety cap checks
    if len(final_ips) == 0:
        raise ScopeValidationError(
            "No executable targets remain after parsing and exclusion filtering."
        )

    if len(final_ips) > target_cap:
        raise ScopeValidationError(
            f"Expanded target set contains {len(final_ips)} IP addresses, "
            f"exceeding conservative cap of {target_cap}"
        )

    return ValidatedScope(
        operator_id=op_id,
        authorization_reference=auth_ref,
        authorization_attestation=auth_att,
        authorized_at=datetime.now(timezone.utc),
        profile=profile,
        protocol=protocol,
        requested_targets=requested_targets,
        canonical_targets=final_ips,
        exclusions=canonical_exclusions,
        permitted_ports=unique_ports,
        resolved_host_map=resolved_host_map,
    )


def _validate_network_safety(net: ipaddress.IPv4Network | ipaddress.IPv6Network) -> None:
    """Ensure network is not multicast, unspecified, or broadcast."""
    if net.is_multicast:
        raise ScopeValidationError(f"Multicast address range '{net}' is not permitted.")
    if net.is_unspecified:
        raise ScopeValidationError(f"Unspecified address range '{net}' (0.0.0.0 or ::) is not permitted.")
    if net.is_reserved:
        raise ScopeValidationError(f"Reserved address range '{net}' is not permitted.")


def _validate_ip_safety(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> None:
    """Ensure discrete IP is not multicast, unspecified, or reserved."""
    if ip.is_multicast:
        raise ScopeValidationError(f"Multicast IP '{ip}' is not permitted.")
    if ip.is_unspecified:
        raise ScopeValidationError(f"Unspecified IP '{ip}' is not permitted.")
    if ip.is_reserved:
        raise ScopeValidationError(f"Reserved IP '{ip}' is not permitted.")
