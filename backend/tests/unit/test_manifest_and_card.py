"""Unit tests for Canonical Dataset Manifest and Dataset Card Generator."""

import json
from pathlib import Path

from app.datasets.card import DatasetCardGenerator
from app.datasets.manifest import DatasetManifestBuilder


def make_sample_sessions() -> list[dict]:
    return [
        {
            "id": "11111111-1111-1111-1111-111111111111",
            "workload_class": "Web",
            "scenario_id": "scen_web_01",
            "mode": "TUNNEL",
            "ip_version": "IPv4",
            "cipher_suite": "aes128gcm16",
            "pfs_status": "ENABLED",
            "is_nat_t": False,
            "network_impairment_profile": None,
            "encrypted_capture_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "packet_count": 100,
            "byte_count": 25000,
            "duration_seconds": 5.0,
        },
        {
            "id": "22222222-2222-2222-2222-222222222222",
            "workload_class": "VoIP",
            "scenario_id": "scen_voip_01",
            "mode": "TRANSPORT",
            "ip_version": "IPv6",
            "cipher_suite": "chacha20poly1305",
            "pfs_status": "DISABLED",
            "is_nat_t": True,
            "network_impairment_profile": "loss_1pct",
            "encrypted_capture_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "packet_count": 250,
            "byte_count": 40000,
            "duration_seconds": 5.0,
        },
    ]


def test_manifest_builder_canonical_serialization_and_hash():
    sessions = make_sample_sessions()
    split_map = {
        "11111111-1111-1111-1111-111111111111": ("TRAIN", "group_1"),
        "22222222-2222-2222-2222-222222222222": ("TEST", "group_2"),
    }
    manifest = DatasetManifestBuilder.build(
        dataset_name="TunnelTrace_IPsec_Test",
        version_tag="v1.0.0",
        vpn_technology="IPSEC_NATIVE",
        role="PRIMARY",
        sessions=sessions,
        split_map=split_map,
        anti_shortcut_coverage={"cipher_suites": ["aes128gcm16", "chacha20poly1305"]},
    )

    assert manifest.total_sessions == 2
    assert manifest.class_distribution == {"Web": 1, "VoIP": 1}
    assert manifest.split_distribution == {"TRAIN": 1, "TEST": 1}
    assert manifest.manifest_sha256 is not None
    assert len(manifest.manifest_sha256) == 64

    # Canonical JSON string must be valid JSON
    canonical_str = manifest.canonical_json()
    parsed = json.loads(canonical_str)
    assert parsed["dataset_name"] == "TunnelTrace_IPsec_Test"


def test_manifest_file_save_and_verify_roundtrip(tmp_path: Path):
    sessions = make_sample_sessions()
    manifest = DatasetManifestBuilder.build(
        dataset_name="TestDataset",
        version_tag="v0.1.0",
        sessions=sessions,
    )
    manifest_path = tmp_path / "manifest.json"
    stored_sha = DatasetManifestBuilder.save_to_file(manifest, manifest_path)
    assert stored_sha == manifest.manifest_sha256

    is_valid, stored, recalced = DatasetManifestBuilder.verify_file(manifest_path)
    assert is_valid is True
    assert stored == recalced


def test_manifest_tamper_detection(tmp_path: Path):
    sessions = make_sample_sessions()
    manifest = DatasetManifestBuilder.build(
        dataset_name="TamperTest",
        version_tag="v0.1.0",
        sessions=sessions,
    )
    manifest_path = tmp_path / "manifest.json"
    DatasetManifestBuilder.save_to_file(manifest, manifest_path)

    # Tamper with file
    content = json.loads(manifest_path.read_text(encoding="utf-8"))
    content["total_sessions"] = 999  # Tamper
    manifest_path.write_text(json.dumps(content, indent=2), encoding="utf-8")

    is_valid, stored, recalced = DatasetManifestBuilder.verify_file(manifest_path)
    assert is_valid is False
    assert stored != recalced


def test_dataset_card_generator_markdown_structure():
    sessions = make_sample_sessions()
    split_map = {
        "11111111-1111-1111-1111-111111111111": ("TRAIN", "group_1"),
        "22222222-2222-2222-2222-222222222222": ("TEST", "group_2"),
    }
    manifest = DatasetManifestBuilder.build(
        dataset_name="TunnelTrace_Card_Test",
        version_tag="v1.0.0",
        sessions=sessions,
        split_map=split_map,
        anti_shortcut_coverage={"ciphers": 2},
    )

    card_md = DatasetCardGenerator.generate_markdown(manifest)
    assert "# Dataset Card: TunnelTrace_Card_Test (v1.0.0)" in card_md
    assert "NTRO Problem Statement 26160 / PS 160" in card_md
    assert "Dual-Capture Architecture" in card_md
    assert "Point A (Plaintext Internal)" in card_md
    assert "Point B (Encrypted WAN)" in card_md
    assert "POINT_A_PURGED_ENCRYPTED_WAN_ONLY" in card_md
    assert "VERIFIED_ZERO_LEAKAGE" in card_md
    assert "UNB/CIC ISCXVPN2016" in card_md
