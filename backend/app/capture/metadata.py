"""Capture structural metadata extraction using Capinfos / TShark."""

import csv
import io
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.core.errors import CaptureValidationError
from app.protocol.tshark.binary import get_toolchain

logger = logging.getLogger(__name__)


@dataclass
class CaptureMetadata:
    """Extracted structural metadata from a verified packet capture."""

    file_size_bytes: int
    packet_count: int | None
    duration_sec: float | None
    first_packet_at: datetime | None
    last_packet_at: datetime | None
    link_layer_type: str | None
    interface_metadata: dict[str, Any] | None


def parse_timestamp(ts_str: str) -> datetime | None:
    """Parse Capinfos timestamp string (e.g. '2026-09-23 17:47:45.960215') into UTC datetime."""
    if not ts_str or ts_str.strip() in ("", "n/a", "N/A"):
        return None
    cleaned = ts_str.strip()
    # Handle standard formats
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            dt = datetime.strptime(cleaned, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return None


def extract_capture_metadata(file_path: Path | str) -> CaptureMetadata:
    """Run Capinfos to extract structural packet metadata from the capture file.

    Args:
        file_path: Path to capture file.

    Returns:
        CaptureMetadata object with parsed metrics.

    Raises:
        CaptureValidationError: If Capinfos fails or file cannot be parsed.
    """
    path = Path(file_path)
    if not path.exists():
        raise CaptureValidationError(f"File not found: {path}", code="CAPTURE_NOT_FOUND")

    file_size = path.stat().st_size
    toolchain = get_toolchain()

    # Capinfos flags:
    # -T -m: CSV format
    # -c: count packets
    # -d: data size
    # -u: capture duration
    # -s: start time
    # -e: end time
    # -y: encapsulation
    # -a: start time
    # -E: data byte rate
    cmd = toolchain.resolve_command(
        "capinfos",
        ["-T", "-m", "-c", "-d", "-u", "-a", "-e", "-y", "-E", str(path)],
    )

    import subprocess

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            shell=False,
            timeout=15.0,
        )
    except Exception as exc:
        logger.warning(f"Capinfos execution failed: {exc}. Falling back to basic file metrics.")
        return CaptureMetadata(
            file_size_bytes=file_size,
            packet_count=None,
            duration_sec=None,
            first_packet_at=None,
            last_packet_at=None,
            link_layer_type=None,
            interface_metadata=None,
        )

    if proc.returncode != 0:
        logger.warning(
            f"Capinfos returned non-zero ({proc.returncode}): {proc.stderr}. Using basic file stats."
        )
        return CaptureMetadata(
            file_size_bytes=file_size,
            packet_count=None,
            duration_sec=None,
            first_packet_at=None,
            last_packet_at=None,
            link_layer_type=None,
            interface_metadata=None,
        )

    # Parse CSV output
    reader = csv.DictReader(io.StringIO(proc.stdout.strip()))
    row = next(reader, None)
    if not row:
        return CaptureMetadata(
            file_size_bytes=file_size,
            packet_count=None,
            duration_sec=None,
            first_packet_at=None,
            last_packet_at=None,
            link_layer_type=None,
            interface_metadata=None,
        )

    # Parse extracted values
    packet_count: int | None = None
    if "Number of packets" in row:
        try:
            packet_count = int(row["Number of packets"])
        except (ValueError, TypeError):
            pass

    duration_sec: float | None = None
    if "Capture duration (seconds)" in row:
        try:
            duration_sec = float(row["Capture duration (seconds)"])
        except (ValueError, TypeError):
            pass

    first_packet_at = parse_timestamp(row.get("Start time", ""))
    last_packet_at = parse_timestamp(row.get("End time", ""))
    link_layer = row.get("File encapsulation")

    return CaptureMetadata(
        file_size_bytes=file_size,
        packet_count=packet_count,
        duration_sec=duration_sec,
        first_packet_at=first_packet_at,
        last_packet_at=last_packet_at,
        link_layer_type=link_layer,
        interface_metadata={"encapsulation": link_layer},
    )
