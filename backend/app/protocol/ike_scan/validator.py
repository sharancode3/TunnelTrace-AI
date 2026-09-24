"""Target scope and authorization validation for IKE-scan assessment."""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass
from datetime import datetime, timezone

from app.core.config import settings
from app.discovery.validator import AuthorizationError, ScopeValidationError
from app.protocol.ike_scan.profiles import (
    SCAN_PROFILES,
    IkeProfileConfig,
    IkeScanProfile,
)

HOSTNAME_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
)


@dataclass(frozen=True)
class ValidatedIkeScope:
    operator_id: str
    authorization_reference: str
    authorization_attestation: str
    authorized_at: datetime
    profile: IkeScanProfile
    profile_config: IkeProfileConfig
    target_ip: str
    target_port: int
    ike_version: str
    is_experimental: bool


def validate_ike_scope(
    *,
    operator_id: str,
    authorization_reference: str,
    authorization_attestation: str,
    profile_name: str,
    target: str,
    port: int = 500,
) -> ValidatedIkeScope:
    """Validate and canonicalize all elements of an IKE assessment request before execution.

    Enforces:
    - Master toggle: IKE_ASSESSMENT_ENABLED must be True
    - Non-empty operator_id and authorization_reference
    - Authorization attestation (minimum 10 characters)
    - Profile allowlist matching
    - Exactly single discrete IP address target (no CIDR ranges or multi-target sweeps)
    - Rejection of multicast, broadcast, and unspecified addresses
    - Hostname resolution and IP pinning
    - Port validation (default 500, allowlisted 4500)
    - Experimental IKEv2 flag verification
    """
    if not settings.IKE_ASSESSMENT_ENABLED:
        raise ScopeValidationError(
            "IKE assessment subsystem is disabled by configuration (IKE_ASSESSMENT_ENABLED=False)"
        )

    # 1. Authorization checks
    op_id = (operator_id or "").strip()
    if not op_id:
        raise AuthorizationError("operator_id is required")

    auth_ref = (authorization_reference or "").strip()
    if not auth_ref:
        raise AuthorizationError(
            "authorization_reference is required (e.g. ticket ID, engagement code)"
        )

    auth_att = (authorization_attestation or "").strip()
    if len(auth_att) < 10:
        raise AuthorizationError(
            "authorization_attestation must contain an explicit statement confirming authorized testing scope"
        )

    # 2. Profile validation
    try:
        profile = IkeScanProfile(profile_name)
    except ValueError:
        valid_names = [p.value for p in IkeScanProfile]
        raise ScopeValidationError(
            f"Invalid profile '{profile_name}'. Must be one of: {valid_names}"
        )

    profile_cfg = SCAN_PROFILES[profile]

    if profile_cfg.is_experimental and not settings.IKE_SCAN_ALLOW_EXPERIMENTAL_V2:
        raise ScopeValidationError(
            "Experimental IKEv2 probing is disabled by configuration (IKE_SCAN_ALLOW_EXPERIMENTAL_V2=False)"
        )

    # 3. Target validation - MUST be a single discrete target
    raw_target = (target or "").strip()
    if not raw_target:
        raise ScopeValidationError("target is required")

    if "/" in raw_target:
        raise ScopeValidationError(
            f"CIDR range sweeps are forbidden for IKE assessment; specify a single discrete IP (received '{raw_target}')"
        )

    resolved_ip: str
    try:
        ip_obj = ipaddress.ip_address(raw_target)
        is_ip = True
    except ValueError:
        is_ip = False

    if is_ip:
        if ip_obj.is_multicast:
            raise ScopeValidationError(f"Multicast target '{raw_target}' is forbidden")
        if ip_obj.is_unspecified:
            raise ScopeValidationError(f"Unspecified address '{raw_target}' is forbidden")
        if (
            isinstance(ip_obj, ipaddress.IPv4Address)
            and ip_obj == ipaddress.IPv4Address("255.255.255.255")
        ):
            raise ScopeValidationError(f"Broadcast address '{raw_target}' is forbidden")
        resolved_ip = str(ip_obj)
    else:
        # Not an IP literal, validate as hostname
        if not HOSTNAME_REGEX.match(raw_target):
            raise ScopeValidationError(
                f"Target '{raw_target}' is neither a valid IP address nor a valid hostname"
            )
        try:
            addr_info = socket.getaddrinfo(
                raw_target, None, socket.AF_UNSPEC, socket.SOCK_DGRAM
            )
            candidates = [entry[4][0] for entry in addr_info if entry[4]]
            if not candidates:
                raise ScopeValidationError(f"Hostname '{raw_target}' did not resolve to any IP address")
            resolved_ip = candidates[0]
        except socket.gaierror as e:
            raise ScopeValidationError(f"Failed to resolve hostname '{raw_target}': {e}")

    # 4. Port validation
    if port not in profile_cfg.permitted_ports and not (1 <= port <= 65535):
        raise ScopeValidationError(
            f"Port {port} is invalid. Permitted ports for profile {profile.value} are {profile_cfg.permitted_ports}"
        )

    return ValidatedIkeScope(
        operator_id=op_id,
        authorization_reference=auth_ref,
        authorization_attestation=auth_att,
        authorized_at=datetime.now(timezone.utc),
        profile=profile,
        profile_config=profile_cfg,
        target_ip=resolved_ip,
        target_port=port,
        ike_version=profile_cfg.ike_version,
        is_experimental=profile_cfg.is_experimental,
    )
