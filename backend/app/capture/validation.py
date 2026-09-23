"""Packet capture format identification and structural validation."""

import struct
from enum import Enum
from pathlib import Path

from app.core.errors import CaptureValidationError


class CaptureFormat(str, Enum):
    """Supported packet capture file formats."""

    PCAP = "PCAP"
    PCAPNG = "PCAPNG"


class MagicType(str, Enum):
    """Recognized packet capture magic byte signatures."""

    PCAP_MICROSECOND_LE = "pcap_usec_le"
    PCAP_MICROSECOND_BE = "pcap_usec_be"
    PCAP_NANOSECOND_LE = "pcap_nsec_le"
    PCAP_NANOSECOND_BE = "pcap_nsec_be"
    PCAPNG_SHB = "pcapng_shb"


# Canonical 4-byte magic signatures
PCAP_MAGIC_MAP = {
    b"\xd4\xc3\xb2\xa1": (CaptureFormat.PCAP, MagicType.PCAP_MICROSECOND_LE),
    b"\xa1\xb2\xc3\xd4": (CaptureFormat.PCAP, MagicType.PCAP_MICROSECOND_BE),
    b"\x4d\x3c\xb2\xa1": (CaptureFormat.PCAP, MagicType.PCAP_NANOSECOND_LE),
    b"\xa1\xb2\x3c\x4d": (CaptureFormat.PCAP, MagicType.PCAP_NANOSECOND_BE),
    b"\x0a\x0d\x0d\x0a": (CaptureFormat.PCAPNG, MagicType.PCAPNG_SHB),
}

PCAP_GLOBAL_HEADER_LEN = 24
PCAPNG_MIN_SHB_LEN = 12
PCAPNG_BYTE_ORDER_MAGIC = b"\x1a\x2b\x3c\x4d"
PCAPNG_BYTE_ORDER_MAGIC_BE = b"\x4d\x3c\x2b\x1a"


def validate_capture_header(header_bytes: bytes) -> tuple[CaptureFormat, MagicType]:
    """Inspect leading bytes to deterministically identify and validate capture format.

    Args:
        header_bytes: Initial bytes of the capture file (at least 24 bytes recommended).

    Returns:
        tuple of (CaptureFormat, MagicType).

    Raises:
        CaptureValidationError: If bytes are empty, truncated, or unparseable.
    """
    if not header_bytes:
        raise CaptureValidationError("File is empty (0 bytes).", code="CAPTURE_EMPTY")

    if len(header_bytes) < 4:
        raise CaptureValidationError(
            "File header is truncated (less than 4 bytes).", code="CAPTURE_INVALID_FORMAT"
        )

    magic = header_bytes[:4]
    if magic not in PCAP_MAGIC_MAP:
        raise CaptureValidationError(
            f"Unsupported or invalid capture magic bytes: {magic.hex()}.",
            code="CAPTURE_INVALID_FORMAT",
        )

    fmt, magic_type = PCAP_MAGIC_MAP[magic]

    # Additional structural sanity check for PCAP global header
    if fmt == CaptureFormat.PCAP:
        if len(header_bytes) < PCAP_GLOBAL_HEADER_LEN:
            raise CaptureValidationError(
                f"PCAP file is smaller than canonical 24-byte global header ({len(header_bytes)} bytes).",
                code="CAPTURE_INVALID_FORMAT",
            )
        # Parse version major and minor
        endian = "<" if "le" in magic_type.value else ">"
        _, v_major, v_minor, _, _, snaplen, network = struct.unpack(
            f"{endian}IHHIIII", header_bytes[:PCAP_GLOBAL_HEADER_LEN]
        )
        if v_major != 2 or v_minor != 4:
            raise CaptureValidationError(
                f"Unsupported PCAP version: {v_major}.{v_minor} (expected 2.4).",
                code="CAPTURE_INVALID_FORMAT",
            )

    # Additional structural sanity check for PCAPNG Section Header Block
    elif fmt == CaptureFormat.PCAPNG:
        if len(header_bytes) < PCAPNG_MIN_SHB_LEN:
            raise CaptureValidationError(
                f"PCAPNG file is smaller than minimal 12-byte Section Header Block ({len(header_bytes)} bytes).",
                code="CAPTURE_INVALID_FORMAT",
            )
        bom = header_bytes[8:12]
        if bom not in (PCAPNG_BYTE_ORDER_MAGIC, PCAPNG_BYTE_ORDER_MAGIC_BE):
            raise CaptureValidationError(
                f"Invalid PCAPNG Byte-Order Magic in Section Header Block: {bom.hex()}.",
                code="CAPTURE_INVALID_FORMAT",
            )

    return fmt, magic_type


def validate_capture_file(file_path: Path | str) -> tuple[CaptureFormat, MagicType]:
    """Validate a local capture file by inspecting its header bytes.

    Args:
        file_path: Path to capture file.

    Returns:
        tuple of (CaptureFormat, MagicType).
    """
    path = Path(file_path)
    if not path.exists():
        raise CaptureValidationError(f"Capture file not found: {path}", code="CAPTURE_NOT_FOUND")

    file_size = path.stat().st_size
    if file_size == 0:
        raise CaptureValidationError("File is empty (0 bytes).", code="CAPTURE_EMPTY")

    with open(path, "rb") as f:
        header = f.read(PCAP_GLOBAL_HEADER_LEN)

    return validate_capture_header(header)
