"""Unit tests for packet capture format identification and header validation."""

import struct

import pytest

from app.capture.ingestion import sanitize_filename
from app.capture.validation import (
    CaptureFormat,
    MagicType,
    validate_capture_header,
)
from app.core.errors import CaptureValidationError


def _make_pcap_header(magic_bytes: bytes, v_maj: int = 2, v_min: int = 4, snaplen: int = 65535, network: int = 1) -> bytes:
    """Helper to synthesize valid 24-byte PCAP global header."""
    endian = "<" if magic_bytes in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
    return struct.pack(f"{endian}4sHHIIII", magic_bytes, v_maj, v_min, 0, 0, snaplen, network)


def _make_pcapng_shb(block_len: int = 32, bom: bytes = b"\x1a\x2b\x3c\x4d") -> bytes:
    """Helper to synthesize valid PCAPNG Section Header Block."""
    return b"\x0a\x0d\x0d\x0a" + struct.pack("<I", block_len) + bom + b"\x00" * (block_len - 12)


def test_validate_pcap_microsecond_le():
    """Verify standard PCAP little-endian microsecond magic detection."""
    header = _make_pcap_header(b"\xd4\xc3\xb2\xa1")
    fmt, m_type = validate_capture_header(header)
    assert fmt == CaptureFormat.PCAP
    assert m_type == MagicType.PCAP_MICROSECOND_LE


def test_validate_pcap_microsecond_be():
    """Verify standard PCAP big-endian microsecond magic detection."""
    header = _make_pcap_header(b"\xa1\xb2\xc3\xd4")
    fmt, m_type = validate_capture_header(header)
    assert fmt == CaptureFormat.PCAP
    assert m_type == MagicType.PCAP_MICROSECOND_BE


def test_validate_pcap_nanosecond_le():
    """Verify standard PCAP little-endian nanosecond magic detection."""
    header = _make_pcap_header(b"\x4d\x3c\xb2\xa1")
    fmt, m_type = validate_capture_header(header)
    assert fmt == CaptureFormat.PCAP
    assert m_type == MagicType.PCAP_NANOSECOND_LE


def test_validate_pcap_nanosecond_be():
    """Verify standard PCAP big-endian nanosecond magic detection."""
    header = _make_pcap_header(b"\xa1\xb2\x3c\x4d")
    fmt, m_type = validate_capture_header(header)
    assert fmt == CaptureFormat.PCAP
    assert m_type == MagicType.PCAP_NANOSECOND_BE


def test_validate_pcapng_shb():
    """Verify PCAPNG Section Header Block magic detection."""
    header = _make_pcapng_shb()
    fmt, m_type = validate_capture_header(header)
    assert fmt == CaptureFormat.PCAPNG
    assert m_type == MagicType.PCAPNG_SHB


def test_validate_empty_file_rejected():
    """Verify zero-byte capture is rejected with CAPTURE_EMPTY."""
    with pytest.raises(CaptureValidationError) as exc:
        validate_capture_header(b"")
    assert exc.value.code == "CAPTURE_EMPTY"


def test_validate_truncated_header_rejected():
    """Verify capture smaller than 4 bytes is rejected."""
    with pytest.raises(CaptureValidationError) as exc:
        validate_capture_header(b"\xd4\xc3")
    assert exc.value.code == "CAPTURE_INVALID_FORMAT"


def test_validate_unknown_magic_rejected():
    """Verify arbitrary binary data is rejected regardless of extension."""
    with pytest.raises(CaptureValidationError) as exc:
        validate_capture_header(b"PK\x03\x04zipfilepayloadcontenthere")
    assert exc.value.code == "CAPTURE_INVALID_FORMAT"


def test_validate_truncated_pcap_global_header():
    """Verify PCAP file shorter than 24 bytes is rejected."""
    short_header = b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00"  # 8 bytes only
    with pytest.raises(CaptureValidationError) as exc:
        validate_capture_header(short_header)
    assert "smaller than canonical 24-byte" in exc.value.message


def test_sanitize_filename_prevents_traversal():
    """Verify untrusted client filenames are sanitized to prevent directory traversal."""
    assert sanitize_filename("../../../../etc/passwd") == "passwd"
    assert sanitize_filename("..\\..\\Windows\\System32\\cmd.exe") == "cmd.exe"
    assert sanitize_filename(None) == "unnamed_capture.pcap"
    assert sanitize_filename("") == "unnamed_capture.pcap"
    assert sanitize_filename("capture with spaces and !@#$%^&*().pcap") == "capture_with_spaces_and___________.pcap"
