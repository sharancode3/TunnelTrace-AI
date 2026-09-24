"""Scan profiles for Stage 2 Authorized Asset Discovery."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class DiscoveryProfile(str, Enum):
    IKE_SERVICE_DISCOVERY = "IKE_SERVICE_DISCOVERY"
    VPN_MANAGEMENT_DISCOVERY = "VPN_MANAGEMENT_DISCOVERY"
    CUSTOM_BOUNDED = "CUSTOM_BOUNDED"


@dataclass(frozen=True)
class ProfileConfig:
    name: DiscoveryProfile
    description: str
    default_protocol: str  # "UDP" or "TCP"
    default_ports: list[int]
    timing_template: str  # "-T2" or "-T3"
    base_args: list[str]


SCAN_PROFILES: dict[DiscoveryProfile, ProfileConfig] = {
    DiscoveryProfile.IKE_SERVICE_DISCOVERY: ProfileConfig(
        name=DiscoveryProfile.IKE_SERVICE_DISCOVERY,
        description="Bounded low-rate UDP discovery for IKE (500) and IPsec NAT-Traversal (4500)",
        default_protocol="UDP",
        default_ports=[500, 4500],
        timing_template="-T3",
        base_args=["-sU", "-Pn", "-n"],
    ),
    DiscoveryProfile.VPN_MANAGEMENT_DISCOVERY: ProfileConfig(
        name=DiscoveryProfile.VPN_MANAGEMENT_DISCOVERY,
        description="Safe unprivileged TCP connect discovery for authorized VPN management portals (22, 443, 80, 8443)",
        default_protocol="TCP",
        default_ports=[22, 443, 80, 8443],
        timing_template="-T3",
        base_args=["-sT", "-Pn", "-n"],
    ),
    DiscoveryProfile.CUSTOM_BOUNDED: ProfileConfig(
        name=DiscoveryProfile.CUSTOM_BOUNDED,
        description="Strictly bounded custom port discovery within configured limits",
        default_protocol="UDP",
        default_ports=[500, 4500],
        timing_template="-T3",
        base_args=["-Pn", "-n"],
    ),
}
