"""Versioned Feature Schema for Encrypted ESP Flow Tabular Side-Channels."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class FeatureDefinition:
    """Metadata specification for an individual tabular side-channel feature."""

    name: str
    category: str  # FLOW, DIRECTIONAL, SIZE, TIMING, RATE, BURST, IDLE, EARLY
    unit: str  # ms, count, bytes, ratio, scalar, pkt/s, byte/s
    description: str
    missing_policy: str
    min_bound: float | None = None
    max_bound: float | None = None


# Canonical candidate 24-feature catalogue
DEFAULT_FEATURE_DEFINITIONS: list[FeatureDefinition] = [
    FeatureDefinition(
        name="duration_ms",
        category="FLOW",
        unit="ms",
        description="Total elapsed time between first and last packet of the flow",
        missing_policy="ZERO_IF_SINGLE_PACKET",
        min_bound=0.0,
    ),
    FeatureDefinition(
        name="total_packets",
        category="FLOW",
        unit="count",
        description="Total packet count in flow (forward + reverse)",
        missing_policy="NEVER_MISSING",
        min_bound=1.0,
    ),
    FeatureDefinition(
        name="total_bytes",
        category="FLOW",
        unit="bytes",
        description="Total wire byte count in flow (forward + reverse)",
        missing_policy="NEVER_MISSING",
        min_bound=0.0,
    ),
    FeatureDefinition(
        name="fwd_pkt_ratio",
        category="DIRECTIONAL",
        unit="ratio",
        description="Ratio of forward packets to total packets: K_fwd / (K_fwd + K_rev)",
        missing_policy="HALF_IF_ZERO_PACKETS",
        min_bound=0.0,
        max_bound=1.0,
    ),
    FeatureDefinition(
        name="byte_direction_ratio",
        category="DIRECTIONAL",
        unit="ratio",
        description="Ratio of forward bytes to total bytes: Bytes_fwd / Total_bytes",
        missing_policy="HALF_IF_ZERO_BYTES",
        min_bound=0.0,
        max_bound=1.0,
    ),
    FeatureDefinition(
        name="pkt_len_mean",
        category="SIZE",
        unit="bytes",
        description="Arithmetic mean of all packet wire lengths in flow",
        missing_policy="NEVER_MISSING",
        min_bound=0.0,
    ),
    FeatureDefinition(
        name="pkt_len_std",
        category="SIZE",
        unit="bytes",
        description="Standard deviation of packet wire lengths",
        missing_policy="ZERO_IF_SINGLE_PACKET",
        min_bound=0.0,
    ),
    FeatureDefinition(
        name="pkt_len_skew",
        category="SIZE",
        unit="scalar",
        description="Fisher-Pearson skewness of packet wire lengths clipped to [-3, 3]",
        missing_policy="ZERO_IF_VARIANCE_ZERO",
        min_bound=-3.0,
        max_bound=3.0,
    ),
    FeatureDefinition(
        name="pkt_len_p10",
        category="SIZE",
        unit="bytes",
        description="10th percentile of packet wire lengths",
        missing_policy="FIRST_PACKET_LENGTH_IF_SINGLE",
        min_bound=0.0,
    ),
    FeatureDefinition(
        name="pkt_len_p25",
        category="SIZE",
        unit="bytes",
        description="25th percentile of packet wire lengths",
        missing_policy="FIRST_PACKET_LENGTH_IF_SINGLE",
        min_bound=0.0,
    ),
    FeatureDefinition(
        name="pkt_len_median",
        category="SIZE",
        unit="bytes",
        description="50th percentile (median) of packet wire lengths",
        missing_policy="FIRST_PACKET_LENGTH_IF_SINGLE",
        min_bound=0.0,
    ),
    FeatureDefinition(
        name="pkt_len_p75",
        category="SIZE",
        unit="bytes",
        description="75th percentile of packet wire lengths",
        missing_policy="FIRST_PACKET_LENGTH_IF_SINGLE",
        min_bound=0.0,
    ),
    FeatureDefinition(
        name="pkt_len_p90",
        category="SIZE",
        unit="bytes",
        description="90th percentile of packet wire lengths",
        missing_policy="FIRST_PACKET_LENGTH_IF_SINGLE",
        min_bound=0.0,
    ),
    FeatureDefinition(
        name="iat_mean_ms",
        category="TIMING",
        unit="ms",
        description="Arithmetic mean of inter-packet arrival times in milliseconds",
        missing_policy="ZERO_IF_SINGLE_PACKET",
        min_bound=0.0,
    ),
    FeatureDefinition(
        name="iat_std_ms",
        category="TIMING",
        unit="ms",
        description="Sample standard deviation of inter-packet arrival times in milliseconds",
        missing_policy="ZERO_IF_FEWER_THAN_THREE_PACKETS",
        min_bound=0.0,
    ),
    FeatureDefinition(
        name="iat_max_ms",
        category="TIMING",
        unit="ms",
        description="Maximum inter-packet arrival time in milliseconds",
        missing_policy="ZERO_IF_SINGLE_PACKET",
        min_bound=0.0,
    ),
    FeatureDefinition(
        name="fwd_iat_mean_ms",
        category="TIMING",
        unit="ms",
        description="Arithmetic mean of forward stream inter-packet arrival times in milliseconds",
        missing_policy="ZERO_IF_FEWER_THAN_TWO_FWD_PACKETS",
        min_bound=0.0,
    ),
    FeatureDefinition(
        name="rev_iat_mean_ms",
        category="TIMING",
        unit="ms",
        description="Arithmetic mean of reverse stream inter-packet arrival times in milliseconds",
        missing_policy="ZERO_IF_FEWER_THAN_TWO_REV_PACKETS",
        min_bound=0.0,
    ),
    FeatureDefinition(
        name="packets_per_second",
        category="RATE",
        unit="pkt/s",
        description="Total packet rate: K / (duration_sec + epsilon)",
        missing_policy="ZERO_IF_ZERO_DURATION",
        min_bound=0.0,
    ),
    FeatureDefinition(
        name="bytes_per_second",
        category="RATE",
        unit="byte/s",
        description="Total byte rate: total_bytes / (duration_sec + epsilon)",
        missing_policy="ZERO_IF_ZERO_DURATION",
        min_bound=0.0,
    ),
    FeatureDefinition(
        name="burst_count",
        category="BURST",
        unit="count",
        description="Number of packet trains where inter-arrival times are strictly below burst_threshold_ms",
        missing_policy="ZERO_IF_NO_BURSTS",
        min_bound=0.0,
    ),
    FeatureDefinition(
        name="burst_mean_bytes",
        category="BURST",
        unit="bytes",
        description="Average total wire bytes per burst train",
        missing_policy="ZERO_IF_NO_BURSTS",
        min_bound=0.0,
    ),
    FeatureDefinition(
        name="idle_ratio",
        category="IDLE",
        unit="ratio",
        description="Ratio of cumulative idle time (IAT > idle_threshold_ms) to total flow duration",
        missing_policy="ZERO_IF_NO_IDLES_OR_ZERO_DURATION",
        min_bound=0.0,
        max_bound=1.0,
    ),
    FeatureDefinition(
        name="first_k_bytes",
        category="EARLY",
        unit="bytes",
        description="Cumulative wire bytes transmitted in the first K packets of the flow",
        missing_policy="SUM_OF_AVAILABLE_PACKETS",
        min_bound=0.0,
    ),
]


@dataclass
class FeatureSchema:
    """Versioned schema controlling tabular side-channel feature extraction.

    Parameters such as burst_threshold_ms, idle_threshold_ms, and early_k are
    explicitly parameterized and tracked in the schema hash.
    """

    schema_version: str = "v1.0.0"
    burst_threshold_ms: float = 5.0
    idle_threshold_ms: float = 500.0
    early_k: int = 10
    features: list[FeatureDefinition] = field(default_factory=lambda: list(DEFAULT_FEATURE_DEFINITIONS))

    @property
    def feature_names(self) -> list[str]:
        """Return the strict deterministic ordered list of feature column names."""
        return [f.name for f in self.features]

    @property
    def num_features(self) -> int:
        """Return total number of features in schema."""
        return len(self.features)

    def to_dict(self) -> dict[str, Any]:
        """Export schema definition as a canonical dictionary."""
        return {
            "schema_version": self.schema_version,
            "burst_threshold_ms": self.burst_threshold_ms,
            "idle_threshold_ms": self.idle_threshold_ms,
            "early_k": self.early_k,
            "num_features": self.num_features,
            "feature_names": self.feature_names,
            "features": [asdict(f) for f in self.features],
        }

    def to_json(self, indent: int | None = 2) -> str:
        """Export schema definition as a canonical JSON string."""
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    @property
    def sha256_hash(self) -> str:
        """Compute cryptographic SHA-256 digest of canonical schema definition."""
        canonical_json = json.dumps(self.to_dict(), sort_keys=True)
        return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()

    def schema_hash(self) -> str:
        """Alias method for sha256_hash."""
        return self.sha256_hash

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FeatureSchema:
        """Construct FeatureSchema from serialized dictionary."""
        feat_defs = [
            FeatureDefinition(
                name=f["name"],
                category=f["category"],
                unit=f["unit"],
                description=f["description"],
                missing_policy=f["missing_policy"],
                min_bound=f.get("min_bound"),
                max_bound=f.get("max_bound"),
            )
            for f in data.get("features", [])
        ]
        return cls(
            schema_version=data.get("schema_version", "v1.0.0"),
            burst_threshold_ms=float(data.get("burst_threshold_ms", 5.0)),
            idle_threshold_ms=float(data.get("idle_threshold_ms", 500.0)),
            early_k=int(data.get("early_k", 10)),
            features=feat_defs if feat_defs else list(DEFAULT_FEATURE_DEFINITIONS),
        )

    @classmethod
    def from_json(cls, json_str: str) -> FeatureSchema:
        """Construct FeatureSchema from JSON string."""
        return cls.from_dict(json.loads(json_str))
