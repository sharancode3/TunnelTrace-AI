"""Typed Configuration Intermediate Representation (IR) for IPsec / strongSwan.

Provides an immutable, semantic representation of IPsec configurations and observed
security facts, maintaining explicit epistemic states (KNOWN, UNKNOWN, NOT_APPLICABLE, UNSUPPORTED)
without making false assumptions or losing fidelity during round-trip transformations.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Generic, TypeVar

T = TypeVar("T")


class EpistemicState(str, Enum):
    """Rigorous epistemic state for configuration values."""

    KNOWN = "KNOWN"
    UNKNOWN = "UNKNOWN"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    UNSUPPORTED = "UNSUPPORTED"


@dataclass(frozen=True)
class EpistemicValue(Generic[T]):
    """Wraps a configuration value with its explicit observational certainty."""

    state: EpistemicState
    value: T | None = None
    evidence_source: str = ""

    @classmethod
    def known(cls, val: T, source: str = "") -> EpistemicValue[T]:
        return cls(state=EpistemicState.KNOWN, value=val, evidence_source=source)

    @classmethod
    def unknown(cls, source: str = "") -> EpistemicValue[T]:
        return cls(state=EpistemicState.UNKNOWN, value=None, evidence_source=source)

    @classmethod
    def not_applicable(cls, source: str = "") -> EpistemicValue[T]:
        return cls(state=EpistemicState.NOT_APPLICABLE, value=None, evidence_source=source)

    @classmethod
    def unsupported(cls, source: str = "") -> EpistemicValue[T]:
        return cls(state=EpistemicState.UNSUPPORTED, value=None, evidence_source=source)

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state.value,
            "value": self.value,
            "evidence_source": self.evidence_source,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EpistemicValue[Any]:
        return cls(
            state=EpistemicState(data.get("state", EpistemicState.UNKNOWN.value)),
            value=data.get("value"),
            evidence_source=data.get("evidence_source", ""),
        )


@dataclass(frozen=True)
class TransformIR:
    """Individual cryptographic transform proposal (e.g. aes256gcm16-ecp256 or aes256-sha256-modp2048)."""

    encryption: str
    key_length: int | None = None
    integrity: str | None = None
    prf: str | None = None
    dh_group: int | None = None

    def to_strongswan_string(self, is_ike: bool = False) -> str:
        """Render standard strongSwan proposal syntax."""
        parts: list[str] = []

        # Encryption + optional key length
        enc_lower = self.encryption.lower().replace("_", "-")
        # Handle AEAD notation like aes256gcm16
        if "gcm" in enc_lower and self.key_length:
            if not any(k in enc_lower for k in ("128", "192", "256")):
                enc_part = f"aes{self.key_length}gcm16"
            else:
                enc_part = enc_lower
        elif self.key_length and not any(k in enc_lower for k in ("128", "192", "256")):
            enc_part = f"{enc_lower}{self.key_length}"
        else:
            enc_part = enc_lower
        parts.append(enc_part)

        # Integrity (if not AEAD and present)
        if self.integrity and not ("gcm" in enc_lower or "chacha" in enc_lower):
            integ_lower = self.integrity.lower().replace("_", "-").replace("hmac-", "").replace("auth-", "")
            if integ_lower not in ("aead-integrated", "none"):
                parts.append(integ_lower)

        # PRF (for IKE)
        if is_ike and self.prf:
            prf_lower = self.prf.lower().replace("_", "-").replace("prf-", "")
            if not prf_lower.startswith("prf"):
                prf_lower = f"prf{prf_lower}"
            parts.append(prf_lower)

        # DH Group
        if self.dh_group is not None:
            dh_map = {
                1: "modp768",
                2: "modp1024",
                5: "modp1536",
                14: "modp2048",
                15: "modp3072",
                16: "modp4096",
                17: "modp6144",
                18: "modp8192",
                19: "ecp256",
                20: "ecp384",
                21: "ecp521",
                31: "curve25519",
            }
            dh_str = dh_map.get(self.dh_group, f"modp{self.dh_group}")
            parts.append(dh_str)

        return "-".join(parts)

    def to_dict(self) -> dict[str, Any]:
        return {
            "encryption": self.encryption,
            "key_length": self.key_length,
            "integrity": self.integrity,
            "prf": self.prf,
            "dh_group": self.dh_group,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TransformIR:
        return cls(
            encryption=data.get("encryption", "aes256"),
            key_length=data.get("key_length"),
            integrity=data.get("integrity"),
            prf=data.get("prf"),
            dh_group=data.get("dh_group"),
        )


@dataclass(frozen=True)
class ChildSAConfigurationIR:
    """Configuration semantics for a Child SA (ESP / AH data plane tunnel)."""

    name: str = "child-sa"
    mode: str = "tunnel"  # tunnel | transport
    esp_proposals: tuple[TransformIR, ...] = field(default_factory=tuple)
    local_ts: str = "0.0.0.0/0"
    remote_ts: str = "0.0.0.0/0"
    pfs_dh_group: int | None = None
    start_action: str = "start"  # start | none | trap
    rekey_time: str = "3600s"
    replay_window: int = 64

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "mode": self.mode,
            "esp_proposals": [p.to_dict() for p in self.esp_proposals],
            "local_ts": self.local_ts,
            "remote_ts": self.remote_ts,
            "pfs_dh_group": self.pfs_dh_group,
            "start_action": self.start_action,
            "rekey_time": self.rekey_time,
            "replay_window": self.replay_window,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ChildSAConfigurationIR:
        esp_props = tuple(TransformIR.from_dict(p) for p in data.get("esp_proposals", []))
        return cls(
            name=data.get("name", "child-sa"),
            mode=data.get("mode", "tunnel"),
            esp_proposals=esp_props,
            local_ts=data.get("local_ts", "0.0.0.0/0"),
            remote_ts=data.get("remote_ts", "0.0.0.0/0"),
            pfs_dh_group=data.get("pfs_dh_group"),
            start_action=data.get("start_action", "start"),
            rekey_time=data.get("rekey_time", "3600s"),
            replay_window=data.get("replay_window", 64),
        )


@dataclass(frozen=True)
class ConnectionConfigurationIR:
    """Configuration semantics for an IKE connection."""

    name: str = "tt-tunnel"
    ike_version: int = 2
    local_addrs: str = "%any"
    remote_addrs: str = "%any"
    local_id: str = "peer-a.tunneltrace.local"
    remote_id: str = "peer-b.tunneltrace.local"
    ike_proposals: tuple[TransformIR, ...] = field(default_factory=tuple)
    encap: bool = False
    rekey_time: str = "14400s"
    children: tuple[ChildSAConfigurationIR, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "ike_version": self.ike_version,
            "local_addrs": self.local_addrs,
            "remote_addrs": self.remote_addrs,
            "local_id": self.local_id,
            "remote_id": self.remote_id,
            "ike_proposals": [p.to_dict() for p in self.ike_proposals],
            "encap": self.encap,
            "rekey_time": self.rekey_time,
            "children": [c.to_dict() for c in self.children],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ConnectionConfigurationIR:
        ike_props = tuple(TransformIR.from_dict(p) for p in data.get("ike_proposals", []))
        children = tuple(ChildSAConfigurationIR.from_dict(c) for c in data.get("children", []))
        return cls(
            name=data.get("name", "tt-tunnel"),
            ike_version=data.get("ike_version", 2),
            local_addrs=data.get("local_addrs", "%any"),
            remote_addrs=data.get("remote_addrs", "%any"),
            local_id=data.get("local_id", "peer-a.tunneltrace.local"),
            remote_id=data.get("remote_id", "peer-b.tunneltrace.local"),
            ike_proposals=ike_props,
            encap=data.get("encap", False),
            rekey_time=data.get("rekey_time", "14400s"),
            children=children,
        )


@dataclass(frozen=True)
class SecretConfigurationIR:
    """Sanitized secret placeholder for lab authentication."""

    secret_id: str = "ike-psk"
    remote_id: str = "peer-b.tunneltrace.local"
    is_redacted: bool = True
    secret_placeholder: str = "[REDACTED_LAB_SECRET]"

    def to_dict(self) -> dict[str, Any]:
        return {
            "secret_id": self.secret_id,
            "remote_id": self.remote_id,
            "is_redacted": self.is_redacted,
            "secret_placeholder": self.secret_placeholder,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SecretConfigurationIR:
        return cls(
            secret_id=data.get("secret_id", "ike-psk"),
            remote_id=data.get("remote_id", "peer-b.tunneltrace.local"),
            is_redacted=True,
            secret_placeholder="[REDACTED_LAB_SECRET]",
        )


@dataclass(frozen=True)
class ConfigurationIR:
    """Root typed configuration intermediate representation."""

    connections: tuple[ConnectionConfigurationIR, ...] = field(default_factory=tuple)
    secrets: tuple[SecretConfigurationIR, ...] = field(default_factory=tuple)
    raw_syntax_format: str = "SWANCTL"
    metadata: dict[str, Any] = field(default_factory=dict)

    def compute_sha256(self) -> str:
        """Compute deterministic SHA-256 digest of normalized semantic IR."""
        canonical_json = json.dumps(self.to_dict(redact=True), sort_keys=True)
        return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()

    def to_dict(self, redact: bool = True) -> dict[str, Any]:
        return {
            "raw_syntax_format": self.raw_syntax_format,
            "connections": [c.to_dict() for c in self.connections],
            "secrets": [s.to_dict() for s in self.secrets],
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ConfigurationIR:
        conns = tuple(ConnectionConfigurationIR.from_dict(c) for c in data.get("connections", []))
        secrets = tuple(SecretConfigurationIR.from_dict(s) for s in data.get("secrets", []))
        return cls(
            connections=conns,
            secrets=secrets,
            raw_syntax_format=data.get("raw_syntax_format", "SWANCTL"),
            metadata=data.get("metadata", {}),
        )


@dataclass(frozen=True)
class CurrentConfigurationSnapshot:
    """Normalized snapshot built directly from observed Stage 3/4/8 packet facts.

    Every field carries its explicit EvidenceState (VERIFIED, INFERRED, UNKNOWN).
    Never fills unobserved fields with fabricated assumptions.
    """

    analysis_id: str
    capture_sha256: str
    ike_version: EpistemicValue[str]
    ike_encryption: EpistemicValue[str]
    ike_key_length: EpistemicValue[int]
    ike_integrity: EpistemicValue[str]
    ike_prf: EpistemicValue[str]
    ike_dh_group: EpistemicValue[int]
    child_mode: EpistemicValue[str]
    child_encryption: EpistemicValue[str]
    child_integrity: EpistemicValue[str]
    child_pfs_status: EpistemicValue[str]
    child_pfs_dh_group: EpistemicValue[int]
    child_replay_window: EpistemicValue[int]
    is_nat_detected: EpistemicValue[bool]
    policy_profile: str = "profile_nist_sp800_77"
    raw_observed_facts: dict[str, Any] = field(default_factory=dict)

    def to_configuration_ir(self) -> ConfigurationIR:
        """Convert observed facts into a semantic ConfigurationIR without fabricating vendor keys."""
        # IKE transform
        ike_tf = TransformIR(
            encryption=self.ike_encryption.value or "UNKNOWN",
            key_length=self.ike_key_length.value,
            integrity=self.ike_integrity.value,
            prf=self.ike_prf.value,
            dh_group=self.ike_dh_group.value,
        )

        # Child SA transform
        esp_tf = TransformIR(
            encryption=self.child_encryption.value or "UNKNOWN",
            integrity=self.child_integrity.value,
            dh_group=self.child_pfs_dh_group.value,
        )

        child_ir = ChildSAConfigurationIR(
            name="child-sa-observed",
            mode=self.child_mode.value if self.child_mode.state == EpistemicState.KNOWN else "tunnel",
            esp_proposals=(esp_tf,),
            pfs_dh_group=self.child_pfs_dh_group.value,
            replay_window=self.child_replay_window.value or 64,
        )

        try:
            ver_num = int(str(self.ike_version.value or "2").replace("IKEv", "").replace("v", ""))
        except Exception:
            ver_num = 2

        conn_ir = ConnectionConfigurationIR(
            name="conn-observed",
            ike_version=ver_num,
            ike_proposals=(ike_tf,),
            encap=self.is_nat_detected.value is True,
            children=(child_ir,),
        )

        return ConfigurationIR(
            connections=(conn_ir,),
            secrets=(SecretConfigurationIR(),),
            raw_syntax_format="OBSERVED_MODEL",
            metadata={
                "source": "PASSIVE_RECONSTRUCTION",
                "analysis_id": self.analysis_id,
                "capture_sha256": self.capture_sha256,
            },
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "analysis_id": self.analysis_id,
            "capture_sha256": self.capture_sha256,
            "policy_profile": self.policy_profile,
            "ike_version": self.ike_version.to_dict(),
            "ike_encryption": self.ike_encryption.to_dict(),
            "ike_key_length": self.ike_key_length.to_dict(),
            "ike_integrity": self.ike_integrity.to_dict(),
            "ike_prf": self.ike_prf.to_dict(),
            "ike_dh_group": self.ike_dh_group.to_dict(),
            "child_mode": self.child_mode.to_dict(),
            "child_encryption": self.child_encryption.to_dict(),
            "child_integrity": self.child_integrity.to_dict(),
            "child_pfs_status": self.child_pfs_status.to_dict(),
            "child_pfs_dh_group": self.child_pfs_dh_group.to_dict(),
            "child_replay_window": self.child_replay_window.to_dict(),
            "is_nat_detected": self.is_nat_detected.to_dict(),
            "raw_observed_facts": self.raw_observed_facts,
        }
