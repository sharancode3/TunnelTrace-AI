"""Unit tests for TabularFeatureExtractor and numerical edge cases."""

from __future__ import annotations

import pytest

from app.ml.extractor import ExtractionError, TabularFeatureExtractor
from app.ml.schema import FeatureSchema


def test_hand_crafted_flow_extraction():
    """Verify feature values on a deterministically constructed 4-packet flow."""
    packets = [
        {"packet_time": 100.000, "packet_length": 100, "direction": 1},
        {"packet_time": 100.004, "packet_length": 200, "direction": 1},  # IAT = 4ms (burst)
        {"packet_time": 100.006, "packet_length": 300, "direction": -1},  # IAT = 2ms (burst)
        {"packet_time": 100.600, "packet_length": 400, "direction": -1},  # IAT = 594ms (idle)
    ]
    meta = {"flow_id": "test_flow_01", "session_id": "test_sess_01"}

    extractor = TabularFeatureExtractor(FeatureSchema(burst_threshold_ms=5.0, idle_threshold_ms=500.0, early_k=3))
    row, prov = extractor.extract_features(packets, meta)

    assert row["total_packets"] == 4.0
    assert row["total_bytes"] == 1000.0
    assert pytest.approx(row["duration_ms"], 1e-4) == 600.0
    assert pytest.approx(row["fwd_pkt_ratio"], 1e-4) == 0.5  # 2 fwd, 2 rev
    assert pytest.approx(row["byte_direction_ratio"], 1e-4) == 0.3  # (100 + 200) / 1000 = 0.3
    assert pytest.approx(row["pkt_len_mean"], 1e-4) == 250.0

    # Percentiles: 100, 200, 300, 400
    assert row["pkt_len_median"] == 250.0

    # IATs: [4.0, 2.0, 594.0] ms -> mean = 200.0 ms
    assert pytest.approx(row["iat_mean_ms"], 1e-4) == 200.0
    assert pytest.approx(row["iat_max_ms"], 1e-4) == 594.0

    # Rates: dur = 0.6s -> 4 / 0.6 = 6.6667 pkt/s, 1000 / 0.6 = 1666.67 byte/s
    assert pytest.approx(row["packets_per_second"], 1e-2) == 6.67
    assert pytest.approx(row["bytes_per_second"], 1e-1) == 1666.67

    # Burst count: 1 burst train containing pkts 0, 1, 2 (IATs 4ms and 2ms < 5ms)
    assert row["burst_count"] == 1.0
    assert row["burst_mean_bytes"] == 600.0  # 100 + 200 + 300 = 600

    # Idle ratio: 594ms > 500ms -> idle_ratio = 594 / 600 = 0.99
    assert pytest.approx(row["idle_ratio"], 1e-4) == 0.99

    # Early-k (k=3): 100 + 200 + 300 = 600 bytes
    assert row["first_k_bytes"] == 600.0

    # Provenance separation
    assert prov["flow_id"] == "test_flow_01"
    assert prov["packet_count_verified"] == 4


def test_single_packet_flow_safety():
    """Verify that a single-packet flow does not divide by zero or emit NaN."""
    packets = [{"packet_time": 50.0, "packet_length": 1500, "direction": 1}]
    extractor = TabularFeatureExtractor()
    row, prov = extractor.extract_features(packets)

    assert row["total_packets"] == 1.0
    assert row["total_bytes"] == 1500.0
    assert row["duration_ms"] == 0.0
    assert row["fwd_pkt_ratio"] == 1.0
    assert row["byte_direction_ratio"] == 1.0
    assert row["pkt_len_mean"] == 1500.0
    assert row["pkt_len_std"] == 0.0
    assert row["pkt_len_skew"] == 0.0
    assert row["pkt_len_median"] == 1500.0
    assert row["iat_mean_ms"] == 0.0
    assert row["iat_std_ms"] == 0.0
    assert row["iat_max_ms"] == 0.0
    assert row["fwd_iat_mean_ms"] == 0.0
    assert row["rev_iat_mean_ms"] == 0.0
    assert row["packets_per_second"] == 0.0
    assert row["bytes_per_second"] == 0.0
    assert row["burst_count"] == 0.0
    assert row["idle_ratio"] == 0.0
    assert row["first_k_bytes"] == 1500.0


def test_zero_duration_multi_packet_flow():
    """Verify multiple packets arriving at the identical timestamp."""
    packets = [
        {"packet_time": 10.0, "packet_length": 500, "direction": 1},
        {"packet_time": 10.0, "packet_length": 500, "direction": 1},
        {"packet_time": 10.0, "packet_length": 500, "direction": -1},
    ]
    extractor = TabularFeatureExtractor()
    row, _ = extractor.extract_features(packets)

    assert row["total_packets"] == 3.0
    assert row["duration_ms"] == 0.0
    assert row["packets_per_second"] == 0.0
    assert row["bytes_per_second"] == 0.0
    assert row["iat_mean_ms"] == 0.0


def test_rejection_of_corrupt_data():
    """Verify that corrupt packets (empty, negative lengths, NaN, inversions) raise ExtractionError."""
    extractor = TabularFeatureExtractor()

    # Empty
    with pytest.raises(ExtractionError, match="NO_PACKETS"):
        extractor.extract_features([])

    # Negative packet length
    with pytest.raises(ExtractionError, match="NEGATIVE_PACKET_LENGTH"):
        extractor.extract_features([{"packet_time": 1.0, "packet_length": -50}])

    # NaN in time
    with pytest.raises(ExtractionError, match="NAN_DETECTED"):
        extractor.extract_features([{"packet_time": float("nan"), "packet_length": 100}])

    # Timestamp inversion
    with pytest.raises(ExtractionError, match="TIMESTAMP_INVERSION"):
        extractor.extract_features([
            {"packet_time": 10.0, "packet_length": 100},
            {"packet_time": 5.0, "packet_length": 100},
        ])
