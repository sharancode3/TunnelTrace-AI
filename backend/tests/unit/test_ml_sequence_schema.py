"""Unit tests for SequenceSchema definition, serialization, and SHA-256 hashing."""

from __future__ import annotations

import json

from app.ml.sequence_schema import SequenceSchema


def test_sequence_schema_defaults():
    """Verify default parameters of the canonical SequenceSchema."""
    schema = SequenceSchema.canonical_schema()
    assert schema.version == "1.0.0"
    assert schema.channels == ["direction", "packet_length", "delta_time"]
    assert schema.candidate_horizons == [32, 64, 128]
    assert schema.default_horizon == 64
    assert schema.length_norm_factor == 1500.0
    assert schema.delta_time_clip == 5.0
    assert schema.direction_forward == 1.0
    assert schema.direction_reverse == -1.0
    assert schema.padding_value == 0.0
    assert schema.min_cnn_packets == 3
    assert schema.dtype == "float32"


def test_sequence_schema_serialization_and_hash():
    """Verify deterministic JSON serialization and SHA-256 schema hashing."""
    schema = SequenceSchema.canonical_schema()
    json_str = schema.to_json()
    parsed = json.loads(json_str)

    assert parsed["version"] == "1.0.0"
    assert len(parsed["channels"]) == 3

    h1 = schema.schema_hash()
    h2 = schema.schema_hash()
    assert h1 == h2
    assert len(h1) == 64

    # Roundtrip from dict
    restored = SequenceSchema.from_dict(parsed)
    assert restored.schema_hash() == h1
    assert restored.default_horizon == 64


def test_sequence_schema_custom_parameters():
    """Verify custom parameters in SequenceSchema."""
    custom = SequenceSchema(
        default_horizon=128,
        length_norm_factor=1420.0,
        min_cnn_packets=5,
    )
    assert custom.default_horizon == 128
    assert custom.length_norm_factor == 1420.0
    assert custom.min_cnn_packets == 5
    assert custom.schema_hash() != SequenceSchema.canonical_schema().schema_hash()
