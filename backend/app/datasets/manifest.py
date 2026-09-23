"""Canonical JSON manifest serialization and cryptographic verification for dataset releases."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class SessionManifestItem:
    """Summary of an individual session inside a dataset release manifest."""

    session_id: str
    workload_class: str
    scenario_id: str
    mode: str
    ip_version: str
    cipher_suite: str
    pfs_status: str
    is_nat_t: bool
    network_impairment_profile: str | None
    encrypted_capture_sha256: str
    packet_count: int
    byte_count: int
    duration_seconds: float
    split_type: str | None
    group_id: str | None


@dataclass
class DatasetManifest:
    """Schema for a cryptographically verified dataset release manifest."""

    dataset_name: str
    version_tag: str
    vpn_technology: str
    role: str
    created_at: str
    total_sessions: int
    class_distribution: dict[str, int]
    split_distribution: dict[str, int]
    anti_shortcut_coverage: dict[str, Any]
    sessions: list[dict[str, Any]]
    manifest_sha256: str | None = None

    def to_canonical_dict(self) -> dict[str, Any]:
        """Returns the dictionary excluding the manifest_sha256 field itself."""
        return {
            "dataset_name": self.dataset_name,
            "version_tag": self.version_tag,
            "vpn_technology": self.vpn_technology,
            "role": self.role,
            "created_at": self.created_at,
            "total_sessions": self.total_sessions,
            "class_distribution": self.class_distribution,
            "split_distribution": self.split_distribution,
            "anti_shortcut_coverage": self.anti_shortcut_coverage,
            "sessions": sorted(self.sessions, key=lambda s: s["session_id"]),
        }

    def canonical_json(self) -> str:
        """Serializes the manifest content to canonical UTF-8 JSON (sorted keys, minimal whitespace)."""
        d = self.to_canonical_dict()
        return json.dumps(d, sort_keys=True, indent=None, separators=(",", ":"))

    def compute_sha256(self) -> str:
        """Computes the SHA-256 hash of the canonical JSON string."""
        raw = self.canonical_json().encode("utf-8")
        return hashlib.sha256(raw).hexdigest()


class DatasetManifestBuilder:
    """Builds and verifies release manifests for DatasetVersion snapshots."""

    @classmethod
    def build(
        cls,
        dataset_name: str,
        version_tag: str,
        vpn_technology: str = "IPSEC_NATIVE",
        role: str = "PRIMARY",
        sessions: Sequence[Any] = (),
        split_map: dict[str, tuple[str, str]] | None = None,  # session_id -> (split_type, group_id)
        anti_shortcut_coverage: dict[str, Any] | None = None,
    ) -> DatasetManifest:
        """Constructs a DatasetManifest from sessions and optional split mapping."""
        class_dist: dict[str, int] = {}
        split_dist: dict[str, int] = {}
        manifest_items: list[dict[str, Any]] = []

        split_map = split_map or {}

        for s in sessions:
            sid = str(getattr(s, "id", None) or s.get("id") or s.get("session_id"))
            w_class = getattr(s, "workload_class", None) or s.get("workload_class", "UNKNOWN")
            class_dist[w_class] = class_dist.get(w_class, 0) + 1

            split_info = split_map.get(sid, (None, None))
            split_type = split_info[0] or getattr(s, "split_type", None) or (s.get("split_type") if isinstance(s, dict) else None)
            group_id = split_info[1] or getattr(s, "group_id", None) or (s.get("group_id") if isinstance(s, dict) else None)

            if split_type:
                split_dist[split_type] = split_dist.get(split_type, 0) + 1

            item = SessionManifestItem(
                session_id=sid,
                workload_class=w_class,
                scenario_id=getattr(s, "scenario_id", None) or s.get("scenario_id", ""),
                mode=getattr(s, "mode", None) or s.get("mode", "TUNNEL"),
                ip_version=getattr(s, "ip_version", None) or s.get("ip_version", "IPv4"),
                cipher_suite=getattr(s, "cipher_suite", None) or s.get("cipher_suite", ""),
                pfs_status=getattr(s, "pfs_status", None) or s.get("pfs_status", "ENABLED"),
                is_nat_t=bool(getattr(s, "is_nat_t", False) if hasattr(s, "is_nat_t") else s.get("is_nat_t", False)),
                network_impairment_profile=getattr(s, "network_impairment_profile", None) or (s.get("network_impairment_profile") if isinstance(s, dict) else None),
                encrypted_capture_sha256=getattr(s, "encrypted_capture_sha256", None) or s.get("encrypted_capture_sha256", ""),
                packet_count=int(getattr(s, "packet_count", 0) if hasattr(s, "packet_count") else s.get("packet_count", 0)),
                byte_count=int(getattr(s, "byte_count", 0) if hasattr(s, "byte_count") else s.get("byte_count", 0)),
                duration_seconds=float(getattr(s, "duration_seconds", 0.0) if hasattr(s, "duration_seconds") else s.get("duration_seconds", 0.0)),
                split_type=split_type,
                group_id=group_id,
            )
            manifest_items.append(asdict(item))

        created_str = datetime.now(timezone.utc).isoformat()
        manifest = DatasetManifest(
            dataset_name=dataset_name,
            version_tag=version_tag,
            vpn_technology=vpn_technology,
            role=role,
            created_at=created_str,
            total_sessions=len(manifest_items),
            class_distribution=class_dist,
            split_distribution=split_dist,
            anti_shortcut_coverage=anti_shortcut_coverage or {},
            sessions=manifest_items,
        )
        manifest.manifest_sha256 = manifest.compute_sha256()
        return manifest

    @classmethod
    def save_to_file(cls, manifest: DatasetManifest, target_path: Path) -> str:
        """Saves the full manifest including sha256 to a formatted JSON file."""
        target_path.parent.mkdir(parents=True, exist_ok=True)
        data = manifest.to_canonical_dict()
        data["manifest_sha256"] = manifest.manifest_sha256 or manifest.compute_sha256()
        target_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return data["manifest_sha256"]

    @classmethod
    def verify_file(cls, manifest_path: Path) -> tuple[bool, str, str]:
        """Verifies if a manifest file's stored SHA-256 matches its canonical recalculation.

        Returns (is_valid, stored_sha256, recalculated_sha256).
        """
        raw = json.loads(manifest_path.read_text(encoding="utf-8"))
        stored_sha = raw.pop("manifest_sha256", "")
        canonical = json.dumps(raw, sort_keys=True, indent=None, separators=(",", ":"))
        recalculated_sha = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        return (stored_sha == recalculated_sha, stored_sha, recalculated_sha)
