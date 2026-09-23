"""
TunnelTrace AI - Lab Manifest Unit Tests
========================================
Verifies RunManifest schema, provenance fields, and zero-secrets guarantee.
"""

import json

from lab.agent.models.manifest import CaptureArtifact, RunManifest


class TestManifest:
    """Verifies manifest serialization and validation."""

    def test_manifest_creation_and_serialization(self) -> None:
        manifest = RunManifest(
            run_id="tt-test-12345",
            scenario_id="scn-01-tunnel-v4-gcm-pfs",
            topology_type="TUNNEL_SITE_TO_SITE",
            started_at_utc="2026-09-23T18:00:00Z",
            scenario_sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            namespaces=["tt-client", "tt-gw-a", "tt-wan", "tt-gw-b", "tt-server"],
            validation_status="VALIDATED",
            sa_established=True,
            traffic_probe_passed=True,
            captures=[
                CaptureArtifact(
                    capture_id="cap-wan",
                    role="WAN_ENCRYPTED",
                    interface="br-wan",
                    output_path="/tmp/wan.pcap",
                    file_size_bytes=1024,
                    packet_count=12,
                    sha256="a" * 64
                )
            ]
        )
        serialized = manifest.model_dump_json()
        data = json.loads(serialized)
        
        assert data["run_id"] == "tt-test-12345"
        assert data["validation_status"] == "VALIDATED"
        assert len(data["captures"]) == 1
        assert data["captures"][0]["packet_count"] == 12

        # Ensure no accidental secret keys exist in the schema
        assert "psk" not in serialized.lower()
        assert "secret" not in serialized.lower()
        assert "private_key" not in serialized.lower()
