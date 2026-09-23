"""Unit tests for External Benchmark Dataset Scanner (UNB/CIC ISCXVPN2016)."""

from pathlib import Path

from app.datasets.external_inventory import (
    DEFAULT_EXTERNAL_DIRS,
    ExternalDatasetScanner,
)


def test_infer_application_hint():
    """Verify filename keyword categorization into traffic categories."""
    assert ExternalDatasetScanner.infer_application_hint("vpn_youtube_A.pcap") == "Video Streaming"
    assert ExternalDatasetScanner.infer_application_hint("vpn_netflix_A.pcap") == "Video Streaming"
    assert ExternalDatasetScanner.infer_application_hint("vpn_aim_chat1a.pcap") == "Chat/Messaging"
    assert ExternalDatasetScanner.infer_application_hint("vpn_email2a.pcap") == "Email"
    assert ExternalDatasetScanner.infer_application_hint("vpn_skype_audio1.pcap") == "VoIP"
    assert ExternalDatasetScanner.infer_application_hint("vpn_bittorrent.pcap") == "File Transfer"
    assert ExternalDatasetScanner.infer_application_hint("unknown_traffic.pcap") == "Generic/Unclassified"


def test_compute_sha256_chunked(tmp_path: Path):
    """Verify chunked SHA-256 computation matches standard hashlib result."""
    import hashlib

    dummy_file = tmp_path / "test_sample.pcap"
    content = b"TEST_PCAP_STREAM_CONTENT_CHUNKED" * 1000
    dummy_file.write_bytes(content)

    expected_sha = hashlib.sha256(content).hexdigest()
    computed_sha = ExternalDatasetScanner.compute_sha256(dummy_file, chunk_size=128)
    assert computed_sha == expected_sha


def test_scan_directories_with_mock_data(tmp_path: Path):
    """Verify directory scanner catalogs files with OPENVPN and SUPPORTING_BENCHMARK tags."""
    mock_dir = tmp_path / "mock_vpn_pcaps"
    mock_dir.mkdir()

    pcap1 = mock_dir / "vpn_chat_test.pcap"
    pcap1.write_bytes(b"chat_packets")
    pcap2 = mock_dir / "vpn_video_stream.pcap"
    pcap2.write_bytes(b"video_packets")

    inventory = ExternalDatasetScanner.scan_directories([mock_dir], compute_hashes=True)

    assert inventory.dataset_name == "UNB_CIC_ISCXVPN2016"
    assert inventory.vpn_technology == "OPENVPN"
    assert inventory.role == "SUPPORTING_BENCHMARK"
    assert inventory.total_files == 2
    assert inventory.total_bytes == len(b"chat_packets") + len(b"video_packets")
    assert "DOMAIN SHIFT NOTICE" in inventory.domain_shift_notice
    assert len(inventory.files) == 2


def test_scan_real_downloads_if_present():
    """If the real downloaded folders exist in the environment, verify non-destructive cataloging."""
    dirs_exist = any(d.exists() for d in DEFAULT_EXTERNAL_DIRS)
    if not dirs_exist:
        return

    # Run quick scan without full 2.5GB SHA256 computation for test speed
    inventory = ExternalDatasetScanner.scan_directories(compute_hashes=False)
    assert inventory.total_files == 31
    assert inventory.total_bytes > 2_000_000_000  # Over 2GB
    assert inventory.vpn_technology == "OPENVPN"
    assert inventory.role == "SUPPORTING_BENCHMARK"
