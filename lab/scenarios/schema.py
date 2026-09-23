"""Structured, typed scenario specification schema for TunnelTrace AI testbed."""

import re
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, field_validator


class TopologyType(str, Enum):
    """Network topology architecture for IPsec testing."""

    TUNNEL_SITE_TO_SITE = "TUNNEL_SITE_TO_SITE"
    TRANSPORT_HOST_TO_HOST = "TRANSPORT_HOST_TO_HOST"


class IPVersion(str, Enum):
    """IP transport protocol version."""

    IPV4 = "IPV4"
    IPV6 = "IPV6"
    DUAL_STACK = "DUAL_STACK"


class IKEVersion(str, Enum):
    """Internet Key Exchange protocol version."""

    IKEV2 = "IKEV2"
    IKEV1 = "IKEV1"


class CryptoProfile(str, Enum):
    """Controlled cryptographic suite configurations for IKE and ESP."""

    IKEV2_AES256GCM_DH19_PFS = "IKEV2_AES256GCM_DH19_PFS"
    IKEV2_AES128GCM_DH14_PFS = "IKEV2_AES128GCM_DH14_PFS"
    IKEV2_AES256CBC_SHA256_DH14_NOPFS = "IKEV2_AES256CBC_SHA256_DH14_NOPFS"
    IKEV2_AES128CBC_SHA1_DH2_NOPFS = "IKEV2_AES128CBC_SHA1_DH2_NOPFS"
    IKEV1_AES256CBC_SHA1_DH14 = "IKEV1_AES256CBC_SHA1_DH14"


class PFSMode(str, Enum):
    """Perfect Forward Secrecy enforcement for Child SA key exchange."""

    ENABLED = "ENABLED"
    DISABLED = "DISABLED"


class EncapsulationMode(str, Enum):
    """Wire encapsulation mode (native ESP vs UDP-encapsulated NAT-T)."""

    NATIVE_ESP = "NATIVE_ESP"
    NAT_T = "NAT_T"


class CaptureProfile(str, Enum):
    """Target packet capture interfaces for the scenario."""

    WAN = "WAN"
    PLAINTEXT = "PLAINTEXT"
    BOTH = "BOTH"


class NetemConfig(BaseModel):
    """Linux tc/netem traffic impairment configuration with safety boundaries."""

    delay_ms: float = Field(0.0, ge=0.0, le=2000.0, description="Injected packet delay in ms")
    jitter_ms: float = Field(0.0, ge=0.0, le=500.0, description="Delay variation/jitter in ms")
    loss_pct: float = Field(0.0, ge=0.0, le=50.0, description="Packet loss percentage")
    rate_kbit: Optional[int] = Field(None, ge=64, le=1000000, description="Bandwidth throttling limit in kbps")
    corrupt_pct: float = Field(0.0, ge=0.0, le=20.0, description="Packet corruption percentage")

    @field_validator("jitter_ms")
    @classmethod
    def validate_jitter(cls, v: float, info) -> float:
        delay = info.data.get("delay_ms", 0.0) if info.data else 0.0
        if v > 0 and delay == 0:
            raise ValueError("Jitter cannot be specified without a baseline delay_ms > 0")
        if v > delay:
            raise ValueError(f"Jitter ({v}ms) cannot exceed baseline delay ({delay}ms)")
        return v

    @property
    def rate_kbps(self) -> Optional[int]:
        return self.rate_kbit

    def has_impairment(self) -> bool:
        """Returns True if any non-zero impairment parameter is configured."""
        return (
            (self.delay_ms is not None and self.delay_ms > 0.0)
            or (self.loss_pct is not None and self.loss_pct > 0.0)
            or (self.rate_kbit is not None and self.rate_kbit > 0)
            or (self.corrupt_pct is not None and self.corrupt_pct > 0.0)
        )



class TrafficProbeConfig(BaseModel):
    """Synthetic control traffic parameters to verify tunnel data plane transit."""

    packet_count: int = Field(5, ge=1, le=100, description="Number of test probe packets to transmit")
    interval_sec: float = Field(0.2, ge=0.05, le=5.0, description="Inter-packet dispatch interval")
    payload_size_bytes: int = Field(64, ge=32, le=1400, description="Probe ICMP/UDP payload size in bytes")


class ScenarioDefinition(BaseModel):
    """Canonical, versioned specification model defining an isolated IPsec lab experiment."""

    scenario_id: str = Field(..., description="Unique alphanumeric identifier (e.g. 'scn-tunnel-v4-gcm')")
    scenario_version: str = Field("1.0", description="Semantic version string for configuration audit")
    description: str = Field("", description="Human-readable operational intent and test hypothesis")

    topology: TopologyType = Field(TopologyType.TUNNEL_SITE_TO_SITE, description="Target topology layout")
    ip_version: IPVersion = Field(IPVersion.IPV4, description="Network addressing layer")
    ike_version: IKEVersion = Field(IKEVersion.IKEV2, description="IKE protocol version")
    crypto_profile: CryptoProfile = Field(
        CryptoProfile.IKEV2_AES256GCM_DH19_PFS, description="Negotiation proposal suite"
    )
    pfs: PFSMode = Field(PFSMode.ENABLED, description="Child SA Diffie-Hellman exchange requirement")
    encapsulation: EncapsulationMode = Field(
        EncapsulationMode.NATIVE_ESP, description="ESP encapsulation (native vs UDP/4500)"
    )

    netem: NetemConfig = Field(default_factory=NetemConfig, description="Optional WAN impairment profile")
    capture: CaptureProfile = Field(CaptureProfile.BOTH, description="Packet capture configuration")
    traffic_probe: TrafficProbeConfig = Field(default_factory=TrafficProbeConfig, description="Control traffic")
    sha256_hash: Optional[str] = Field(None, description="SHA-256 digest of original YAML source")

    @property
    def version(self) -> str:
        return self.scenario_version

    @field_validator("scenario_id")
    @classmethod
    def validate_scenario_id(cls, v: str) -> str:
        if not re.match(r"^[a-zA-Z0-9_\-]+$", v):
            raise ValueError(
                f"Invalid scenario_id '{v}': Must contain only alphanumeric characters, underscores, and hyphens."
            )
        if len(v) > 64:
            raise ValueError(f"scenario_id '{v}' exceeds maximum length of 64 characters.")
        return v

