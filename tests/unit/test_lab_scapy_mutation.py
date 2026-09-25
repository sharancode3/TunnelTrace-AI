"""
TunnelTrace AI - Scapy PCAP Mutation & Parser Resilience Unit Tests
====================================================================
Verifies typed mutation specification, offline PCAP mutation operators,
hash integrity, parser crash-resilience, and strict live transmission guards.
"""

import os
import tempfile
from pathlib import Path
import pytest
from pydantic import ValidationError

from lab.agent.mutation.scapy_mutator import (
    MutationConfig,
    MutationResult,
    MutationType,
    PcapMutator,
    SCAPY_AVAILABLE,
    SCAPY_VERSION,
)
from lab.agent.operations.runner import SecurityViolationError


@pytest.fixture
def real_esp_pcap_path() -> str:
    path = os.path.join(os.path.dirname(__file__), "..", "fixtures", "captures", "real_esp_only.pcap")
    return os.path.abspath(path)


class TestScapyMutation:
    """Verifies typed mutation engine and safety isolation."""

    def test_mutation_config_validation(self) -> None:
        """Validates configuration bounds, allowed packet limits, and ID sanitization."""
        # Valid config
        cfg = MutationConfig(
            mutation_id="mut-test-01",
            mutation_type=MutationType.TRUNCATE_HEADER,
            target_layer="ESP",
            max_packets=5,
        )
        assert cfg.mutation_id == "mut-test-01"
        assert cfg.max_packets == 5

        # Invalid max_packets (> 20)
        with pytest.raises(ValidationError):
            MutationConfig(
                mutation_id="mut-test-oversized",
                mutation_type=MutationType.TRUNCATE_HEADER,
                max_packets=50,
            )

        # Invalid mutation_id containing shell injection characters
        with pytest.raises(ValidationError):
            MutationConfig(
                mutation_id="mut; rm -rf /",
                mutation_type=MutationType.CORRUPT_SPI,
            )

    def test_offline_truncate_header_mutation(self, real_esp_pcap_path: str) -> None:
        """TRUNCATE_HEADER must alter packet bytes, preserve file format, and produce valid hashes."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_pcap = os.path.join(tmp_dir, "mutated_truncated.pcap")
            cfg = MutationConfig(
                mutation_id="mut-trunc-01",
                mutation_type=MutationType.TRUNCATE_HEADER,
                max_packets=3,
            )
            result = PcapMutator.mutate_pcap(real_esp_pcap_path, out_pcap, cfg)

            assert os.path.isfile(out_pcap)
            assert result.packets_processed > 0
            assert result.packets_mutated > 0
            assert len(result.source_pcap_sha256) == 64
            assert len(result.mutated_pcap_sha256) == 64
            assert result.source_pcap_sha256 != result.mutated_pcap_sha256
            assert result.live_transmission_status == "OFFLINE_ONLY"

    def test_offline_corrupt_spi_mutation(self, real_esp_pcap_path: str) -> None:
        """CORRUPT_SPI must zero out SPI bytes and alter hash without changing total packet count."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_pcap = os.path.join(tmp_dir, "mutated_corrupt_spi.pcap")
            cfg = MutationConfig(
                mutation_id="mut-spi-01",
                mutation_type=MutationType.CORRUPT_SPI,
                byte_offset=28,
                max_packets=2,
            )
            result = PcapMutator.mutate_pcap(real_esp_pcap_path, out_pcap, cfg)

            assert os.path.isfile(out_pcap)
            assert result.packets_mutated == 2
            assert result.source_pcap_sha256 != result.mutated_pcap_sha256

    def test_offline_reorder_packets_mutation(self, real_esp_pcap_path: str) -> None:
        """REORDER_PACKETS must swap consecutive records."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_pcap = os.path.join(tmp_dir, "mutated_reordered.pcap")
            cfg = MutationConfig(
                mutation_id="mut-reorder-01",
                mutation_type=MutationType.REORDER_PACKETS,
            )
            result = PcapMutator.mutate_pcap(real_esp_pcap_path, out_pcap, cfg)

            assert os.path.isfile(out_pcap)
            assert result.packets_mutated == 2
            assert result.source_pcap_sha256 != result.mutated_pcap_sha256

    def test_live_guard_rejects_physical_interfaces_and_external_namespaces(self) -> None:
        """Live guard must reject external namespaces, physical interfaces, and large packet counts."""
        # Non-lab namespace
        with pytest.raises(SecurityViolationError, match="namespace"):
            PcapMutator.transmit_mutated_live_guard("host-default", "veth-wan-a", 3)

        # Protected physical interface
        with pytest.raises(SecurityViolationError, match="protected physical interface"):
            PcapMutator.transmit_mutated_live_guard("tt-run1-gw_a", "eth0", 3)

        with pytest.raises(SecurityViolationError, match="protected physical interface"):
            PcapMutator.transmit_mutated_live_guard("tt-run1-gw_a", "Wi-Fi", 3)

        # Excessive packet count
        with pytest.raises(SecurityViolationError, match="packet count"):
            PcapMutator.transmit_mutated_live_guard("tt-run1-gw_a", "veth-wan-a", 25)

        # Valid lab parameters on Windows host return truthful BLOCKED status
        guard_res = PcapMutator.transmit_mutated_live_guard("tt-run1-gw_a", "veth-wan-a", 3)
        if os.name == "nt":
            assert guard_res["allowed"] is False
            assert guard_res["status"] == "BLOCKED"
            assert "Windows host" in guard_res["reason"]
        else:
            assert guard_res["allowed"] is True

    def test_parser_resilience_on_mutated_pcap(self, real_esp_pcap_path: str) -> None:
        """Structural validation and metadata extraction on mutated PCAP must complete without crashing."""
        from app.capture.metadata import extract_capture_metadata
        from app.capture.validation import validate_capture_file

        with tempfile.TemporaryDirectory() as tmp_dir:
            out_pcap = os.path.join(tmp_dir, "mutated_for_parser.pcap")
            cfg = MutationConfig(
                mutation_id="mut-resilience-01",
                mutation_type=MutationType.CORRUPT_PAYLOAD_LENGTH,
                max_packets=3,
            )
            result = PcapMutator.mutate_pcap(real_esp_pcap_path, out_pcap, cfg)
            assert os.path.isfile(out_pcap)

            fmt, magic = validate_capture_file(out_pcap)
            assert fmt in ("PCAP", "PCAPNG")
            assert magic is not None

            # Metadata extraction should process mutated file gracefully
            meta = extract_capture_metadata(Path(out_pcap))
            assert meta.file_size_bytes > 0

