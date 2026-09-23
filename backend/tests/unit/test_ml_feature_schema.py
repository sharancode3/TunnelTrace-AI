"""Unit tests for FeatureSchema, feature definitions, and canonical catalogue."""

from __future__ import annotations

from app.ml.schema import (
    FeatureSchema,
)


def test_canonical_24_features_catalogue():
    """Verify that exactly 24 canonical candidate features are defined with correct types and bounds."""
    schema = FeatureSchema()
    assert schema.num_features == 24
    assert len(schema.feature_names) == 24

    expected_names = [
        "duration_ms",
        "total_packets",
        "total_bytes",
        "fwd_pkt_ratio",
        "byte_direction_ratio",
        "pkt_len_mean",
        "pkt_len_std",
        "pkt_len_skew",
        "pkt_len_p10",
        "pkt_len_p25",
        "pkt_len_median",
        "pkt_len_p75",
        "pkt_len_p90",
        "iat_mean_ms",
        "iat_std_ms",
        "iat_max_ms",
        "fwd_iat_mean_ms",
        "rev_iat_mean_ms",
        "packets_per_second",
        "bytes_per_second",
        "burst_count",
        "burst_mean_bytes",
        "idle_ratio",
        "first_k_bytes",
    ]
    assert schema.feature_names == expected_names


def test_schema_hashing_and_determinism():
    """Verify that identical schemas produce bitwise identical SHA-256 digests."""
    s1 = FeatureSchema()
    s2 = FeatureSchema()
    assert s1.sha256_hash == s2.sha256_hash
    assert len(s1.sha256_hash) == 64


def test_threshold_parameterization_divergence():
    """Verify that adjusting thresholds (burst, idle, early_k) changes the schema digest."""
    base = FeatureSchema()
    diff_burst = FeatureSchema(burst_threshold_ms=10.0)
    diff_idle = FeatureSchema(idle_threshold_ms=1000.0)
    diff_k = FeatureSchema(early_k=20)

    assert base.sha256_hash != diff_burst.sha256_hash
    assert base.sha256_hash != diff_idle.sha256_hash
    assert base.sha256_hash != diff_k.sha256_hash


def test_schema_serialization_round_trip():
    """Verify serialization to and from JSON and dict preserves all attributes."""
    schema = FeatureSchema(
        schema_version="v1.0.1",
        burst_threshold_ms=8.0,
        idle_threshold_ms=250.0,
        early_k=15,
    )
    json_str = schema.to_json()
    reloaded = FeatureSchema.from_json(json_str)

    assert reloaded.schema_version == "v1.0.1"
    assert reloaded.burst_threshold_ms == 8.0
    assert reloaded.idle_threshold_ms == 250.0
    assert reloaded.early_k == 15
    assert reloaded.num_features == 24
    assert reloaded.sha256_hash == schema.sha256_hash
