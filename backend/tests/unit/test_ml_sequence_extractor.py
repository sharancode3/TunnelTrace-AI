"""Unit tests for SequenceExtractor: 3-channel construction, padding, masking, and edge cases."""

from __future__ import annotations

import numpy as np
import pytest

from app.ml.extractor import ExtractionError
from app.ml.sequence_extractor import SequenceExtractor
from app.ml.sequence_schema import SequenceSchema


@pytest.fixture
def sequence_extractor():
    return SequenceExtractor(SequenceSchema(default_horizon=32, length_norm_factor=1000.0, delta_time_clip=2.0))


def test_sequence_extractor_basic(sequence_extractor):
    """Verify standard sequence tensor construction and channel values."""
    packets = [
        {"packet_time": 0.0, "packet_length": 500, "direction": 1},
        {"packet_time": 0.05, "packet_length": 800, "direction": -1},
        {"packet_time": 0.15, "packet_length": 1200, "direction": 1},
    ]

    tensor, mask, meta = sequence_extractor.extract_sequence(packets, N=10)

    assert tensor.shape == (3, 10)
    assert mask.shape == (10,)
    assert tensor.dtype == np.float32

    # First packet: fwd, 500/1000 = 0.5, delta_t = 0.0
    assert tensor[0, 0] == 1.0
    assert tensor[1, 0] == pytest.approx(0.5)
    assert tensor[2, 0] == 0.0
    assert mask[0] is True or mask[0] == 1

    # Second packet: rev, 800/1000 = 0.8, delta_t = 0.05
    assert tensor[0, 1] == -1.0
    assert tensor[1, 1] == pytest.approx(0.8)
    assert tensor[2, 1] == pytest.approx(0.05)
    assert mask[1] is True or mask[1] == 1

    # Third packet: fwd, 1200/1000 = 1.2, delta_t = 0.10
    assert tensor[0, 2] == 1.0
    assert tensor[1, 2] == pytest.approx(1.2)
    assert tensor[2, 2] == pytest.approx(0.10)
    assert mask[2] is True or mask[2] == 1

    # Padded steps (indices 3..9)
    for j in range(3, 10):
        assert tensor[0, j] == 0.0
        assert tensor[1, j] == 0.0
        assert tensor[2, j] == 0.0
        assert mask[j] == 0 or mask[j] is False

    assert meta["actual_length"] == 3
    assert meta["total_packets"] == 3
    assert meta["is_eligible"] is True


def test_sequence_extractor_truncation(sequence_extractor):
    """Verify that sequences longer than N are truncated to the first N packets."""
    packets = [
        {"packet_time": i * 0.01, "packet_length": 100 + i * 10, "direction": 1}
        for i in range(50)
    ]

    tensor, mask, meta = sequence_extractor.extract_sequence(packets, N=16)

    assert tensor.shape == (3, 16)
    assert mask.shape == (16,)
    assert np.all(mask)  # All 16 slots are valid unpadded packets
    assert meta["actual_length"] == 16
    assert meta["total_packets"] == 50


def test_sequence_extractor_delta_time_clipping(sequence_extractor):
    """Verify that delta times exceeding the clip threshold are capped at delta_time_clip."""
    packets = [
        {"packet_time": 0.0, "packet_length": 100, "direction": 1},
        {"packet_time": 10.0, "packet_length": 200, "direction": 1},  # 10.0s gap > clip=2.0s
    ]

    tensor, mask, meta = sequence_extractor.extract_sequence(packets, N=5)
    assert tensor[2, 1] == pytest.approx(2.0)  # Clipped to 2.0s


def test_sequence_extractor_short_flow_ineligible(sequence_extractor):
    """Verify that flows with fewer than min_cnn_packets have is_eligible=False."""
    packets = [
        {"packet_time": 0.0, "packet_length": 100, "direction": 1},
        {"packet_time": 0.02, "packet_length": 200, "direction": -1},
    ]  # 2 packets < min=3

    tensor, mask, meta = sequence_extractor.extract_sequence(packets, N=10)
    assert meta["is_eligible"] is False
    assert meta["actual_length"] == 2


def test_sequence_extractor_empty_packets(sequence_extractor):
    """Verify that empty packet sequence raises ExtractionError."""
    with pytest.raises(ExtractionError, match="NO_PACKETS"):
        sequence_extractor.extract_sequence([])


def test_sequence_extractor_timestamp_inversion(sequence_extractor):
    """Verify that non-monotonic timestamps raise ExtractionError."""
    packets = [
        {"packet_time": 1.0, "packet_length": 100, "direction": 1},
        {"packet_time": 0.5, "packet_length": 100, "direction": 1},
    ]
    with pytest.raises(ExtractionError, match="TIMESTAMP_INVERSION"):
        sequence_extractor.extract_sequence(packets)


def test_sequence_extractor_negative_length(sequence_extractor):
    """Verify that negative packet length raises ExtractionError."""
    packets = [
        {"packet_time": 0.0, "packet_length": -50, "direction": 1},
    ]
    with pytest.raises(ExtractionError, match="NEGATIVE_PACKET_LENGTH"):
        sequence_extractor.extract_sequence(packets)
