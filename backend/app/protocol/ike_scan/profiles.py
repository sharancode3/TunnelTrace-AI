"""Allowlisted scan profiles and forbidden argument enforcement for IKE-scan."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class IkeScanProfile(str, Enum):
    IKEV1_MAIN_MODE_DISCOVERY = "IKEV1_MAIN_MODE_DISCOVERY"
    IKEV2_DEFAULT_EXPERIMENTAL = "IKEV2_DEFAULT_EXPERIMENTAL"


@dataclass(frozen=True)
class IkeProfileConfig:
    profile: IkeScanProfile
    description: str
    ike_version: str  # "1" or "2"
    is_experimental: bool
    default_port: int = 500
    permitted_ports: tuple[int, ...] = (500, 4500)
    retries: int = 2
    timeout_ms: int = 2000
    backoff_factor: float = 2.0


SCAN_PROFILES: dict[IkeScanProfile, IkeProfileConfig] = {
    IkeScanProfile.IKEV1_MAIN_MODE_DISCOVERY: IkeProfileConfig(
        profile=IkeScanProfile.IKEV1_MAIN_MODE_DISCOVERY,
        description="Standard bounded IKEv1 Main Mode handshake and vendor ID probe",
        ike_version="1",
        is_experimental=False,
        default_port=500,
        permitted_ports=(500, 4500),
        retries=2,
        timeout_ms=2000,
        backoff_factor=2.0,
    ),
    IkeScanProfile.IKEV2_DEFAULT_EXPERIMENTAL: IkeProfileConfig(
        profile=IkeScanProfile.IKEV2_DEFAULT_EXPERIMENTAL,
        description="Experimental IKEv2 default proposal probe (ike-scan -2); does not enumerate proposals",
        ike_version="2",
        is_experimental=True,
        default_port=500,
        permitted_ports=(500, 4500),
        retries=2,
        timeout_ms=2000,
        backoff_factor=2.0,
    ),
}

# Explicitly forbidden flags that violate non-intrusive, observational safety contracts
FORBIDDEN_FLAGS: frozenset[str] = frozenset(
    [
        "--pskcrack",
        "-P",
        "--aggressive",
        "-A",
        "--fuzz",
        "--random",
        "--sport",
        "--source-ip",
        "--trans",
        "--vendor",
        "--cookie",
        "--header",
        "--nonce",
        "--payload",
        "--nat-t",
        "-u",
        "-M",
        "--multiline",
        "-s",
        "--showbackoff",
    ]
)


def assert_no_forbidden_arguments(argv: list[str]) -> None:
    """Validate an argument list and raise ValueError if any forbidden or intrusive flag is present."""
    for arg in argv:
        clean = arg.split("=")[0].strip()
        if clean in FORBIDDEN_FLAGS:
            raise ValueError(f"Forbidden or intrusive ike-scan argument rejected: '{arg}'")
        if clean.startswith("-P") or clean.startswith("-A"):
            raise ValueError(f"Forbidden or intrusive ike-scan argument rejected: '{arg}'")
