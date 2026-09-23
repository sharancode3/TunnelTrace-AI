"""Read-only scanner and inventory catalog for external benchmark datasets (e.g. UNB/CIC ISCXVPN2016)."""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

DEFAULT_EXTERNAL_DIRS = [
    Path(r"C:\Users\tms10\Downloads\VPN-PCAPs-01"),
    Path(r"C:\Users\tms10\Downloads\VPN-PCAPs-02"),
]


@dataclass(frozen=True)
class ExternalPcapItem:
    """Metadata for an external benchmark capture file."""

    filename: str
    absolute_path: str
    size_bytes: int
    sha256_hash: str
    vpn_technology: str  # e.g. OPENVPN
    role: str  # SUPPORTING_BENCHMARK
    application_hint: str
    modified_at: str


@dataclass
class ExternalBenchmarkInventory:
    """Comprehensive read-only inventory of external benchmark PCAP assets."""

    dataset_name: str
    vpn_technology: str
    role: str
    scanned_at: str
    total_files: int
    total_bytes: int
    files: list[ExternalPcapItem]
    domain_shift_notice: str = (
        "DOMAIN SHIFT NOTICE: This dataset originates from OpenVPN encapsulation. "
        "It MUST NOT be pooled with native IPsec ESP/NAT-T partitions for primary model training. "
        "It is retained exclusively as an external cross-technology supporting benchmark."
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "dataset_name": self.dataset_name,
            "vpn_technology": self.vpn_technology,
            "role": self.role,
            "scanned_at": self.scanned_at,
            "total_files": self.total_files,
            "total_bytes": self.total_bytes,
            "domain_shift_notice": self.domain_shift_notice,
            "files": [asdict(f) for f in self.files],
        }


class ExternalDatasetScanner:
    """Non-destructive scanner for third-party benchmark PCAP directories."""

    APPLICATION_HINTS = [
        ("chat", "Chat/Messaging"),
        ("aim", "Chat/Messaging"),
        ("hangouts", "Chat/Messaging"),
        ("skype_chat", "Chat/Messaging"),
        ("email", "Email"),
        ("mail", "Email"),
        ("youtube", "Video Streaming"),
        ("netflix", "Video Streaming"),
        ("streaming", "Video Streaming"),
        ("vimeo", "Video Streaming"),
        ("spotify", "Audio/VoIP"),
        ("audio", "VoIP"),
        ("voip", "VoIP"),
        ("skype_audio", "VoIP"),
        ("ftps", "File Transfer"),
        ("sftp", "File Transfer"),
        ("bittorrent", "File Transfer"),
        ("torrent", "File Transfer"),
        ("scp", "File Transfer"),
    ]

    @classmethod
    def infer_application_hint(cls, filename: str) -> str:
        """Infers likely application category from filename conventions."""
        fn_lower = filename.lower()
        for kw, cat in cls.APPLICATION_HINTS:
            if kw in fn_lower:
                return cat
        return "Generic/Unclassified"

    @classmethod
    def compute_sha256(cls, file_path: Path, chunk_size: int = 1024 * 1024) -> str:
        """Computes SHA-256 hash in 1MB chunks to safely handle multi-gigabyte files."""
        hasher = hashlib.sha256()
        with file_path.open("rb") as f:
            while chunk := f.read(chunk_size):
                hasher.update(chunk)
        return hasher.hexdigest()

    @classmethod
    def scan_directories(
        cls,
        search_dirs: Sequence[Path] | None = None,
        compute_hashes: bool = True,
    ) -> ExternalBenchmarkInventory:
        """Scans the specified directories for PCAP files in strictly read-only mode."""
        dirs = list(search_dirs) if search_dirs is not None else DEFAULT_EXTERNAL_DIRS
        items: list[ExternalPcapItem] = []
        total_bytes = 0

        for d in dirs:
            if not d.exists() or not d.is_dir():
                logger.info("External directory %s does not exist or is not a directory; skipping", d)
                continue

            for pcap_path in sorted(d.glob("*.pcap*")):
                if not pcap_path.is_file():
                    continue

                size = pcap_path.stat().st_size
                mtime = datetime.fromtimestamp(
                    pcap_path.stat().st_mtime, tz=timezone.utc
                ).isoformat()
                sha_hash = cls.compute_sha256(pcap_path) if compute_hashes else "SKIPPED"
                app_hint = cls.infer_application_hint(pcap_path.name)

                items.append(
                    ExternalPcapItem(
                        filename=pcap_path.name,
                        absolute_path=str(pcap_path.resolve()),
                        size_bytes=size,
                        sha256_hash=sha_hash,
                        vpn_technology="OPENVPN",
                        role="SUPPORTING_BENCHMARK",
                        application_hint=app_hint,
                        modified_at=mtime,
                    )
                )
                total_bytes += size

        return ExternalBenchmarkInventory(
            dataset_name="UNB_CIC_ISCXVPN2016",
            vpn_technology="OPENVPN",
            role="SUPPORTING_BENCHMARK",
            scanned_at=datetime.now(timezone.utc).isoformat(),
            total_files=len(items),
            total_bytes=total_bytes,
            files=items,
        )
