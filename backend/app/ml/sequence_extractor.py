"""Sequence Extractor for Stage 7 1D-CNN Encrypted Flow Representation."""

from __future__ import annotations

from typing import Any

import numpy as np

from app.ml.extractor import ExtractionError
from app.ml.sequence_schema import SequenceSchema


class SequenceExtractor:
    """Extracts 3-channel sequence tensors from outer encrypted ESP packet streams for 1D-CNN inference.

    Channels:
        0: Direction (+1.0 forward, -1.0 reverse, 0.0 pad)
        1: Normalized packet length (length / length_norm_factor, 0.0 pad)
        2: Inter-arrival time (nonnegative seconds clipped at delta_time_clip, 0.0 pad)

    Strict zero payload inspection. Outer transport metadata only.
    """

    def __init__(self, schema: SequenceSchema | None = None) -> None:
        self.schema = schema or SequenceSchema()

    def extract_sequence(
        self,
        packets: list[dict[str, Any]],
        flow_metadata: dict[str, Any] | None = None,
        N: int | None = None,
    ) -> tuple[np.ndarray, np.ndarray, dict[str, Any]]:
        """Extract a (3, N) sequence array, (N,) mask, and diagnostic metadata.

        Args:
            packets: List of packet dicts containing 'packet_time', 'packet_length', and 'direction' or 'spi'.
            flow_metadata: Optional dict containing flow parameters (e.g. forward 'spi') to resolve direction.
            N: Sequence horizon (defaults to schema.default_horizon).

        Returns:
            tuple of:
                - tensor_array: np.ndarray of shape (3, N), dtype float32
                - mask: np.ndarray of shape (N,), dtype bool (True for valid packet, False for pad)
                - metadata: dict containing actual_length, total_packets, is_eligible, duration_ms
        """
        if not packets:
            raise ExtractionError("NO_PACKETS: Packet sequence is empty.")

        horizon = N if N is not None else self.schema.default_horizon
        if horizon <= 0:
            raise ValueError(f"Sequence horizon N must be positive, got {horizon}")

        # Check for timestamp inversions
        raw_times = [float(p.get("packet_time", 0.0)) for p in packets]
        if len(raw_times) > 1 and any(raw_times[i] < raw_times[i - 1] for i in range(1, len(raw_times))):
            raise ExtractionError("TIMESTAMP_INVERSION: Packet timestamps are not monotonically non-decreasing.")

        # Sort chronologically by packet_time
        sorted_pkts = sorted(packets, key=lambda p: float(p.get("packet_time", 0.0)))
        total_k = len(sorted_pkts)

        times = np.array([float(p["packet_time"]) for p in sorted_pkts], dtype=np.float64)
        lengths = np.array([float(p["packet_length"]) for p in sorted_pkts], dtype=np.float64)

        if np.any(lengths < 0):
            raise ExtractionError("NEGATIVE_PACKET_LENGTH: Sequence contains negative packet lengths.")
        if np.any(np.isnan(times)) or np.any(np.isnan(lengths)):
            raise ExtractionError("NAN_DETECTED: Sequence contains NaN values.")
        if np.any(np.isinf(times)) or np.any(np.isinf(lengths)):
            raise ExtractionError("INF_DETECTED: Sequence contains infinite values.")

        # Direction resolution
        directions = []
        for p in sorted_pkts:
            d = p.get("direction")
            if d is None:
                if flow_metadata and "spi" in flow_metadata and p.get("spi"):
                    d = 1.0 if str(p["spi"]).lower() == str(flow_metadata["spi"]).lower() else -1.0
                else:
                    d = 1.0
            directions.append(self.schema.direction_forward if float(d) > 0 else self.schema.direction_reverse)

        # Truncate to first min(total_k, horizon) packets
        k = min(total_k, horizon)

        # Allocate (3, N) array and mask
        tensor = np.full((3, horizon), self.schema.padding_value, dtype=np.float32)
        mask = np.zeros(horizon, dtype=bool)

        for i in range(k):
            # Channel 0: Direction
            tensor[0, i] = directions[i]

            # Channel 1: Normalized Packet Length
            norm_len = lengths[i] / float(self.schema.length_norm_factor)
            tensor[1, i] = float(norm_len)

            # Channel 2: Delta Time (first packet is 0.0)
            if i == 0:
                delta_t = 0.0
            else:
                raw_delta = max(0.0, float(times[i] - times[i - 1]))
                delta_t = min(raw_delta, float(self.schema.delta_time_clip))
            tensor[2, i] = float(delta_t)

            mask[i] = True

        duration_ms = float((times[k - 1] - times[0]) * 1000.0) if k > 1 else 0.0

        metadata = {
            "actual_length": k,
            "total_packets": total_k,
            "is_eligible": bool(total_k >= self.schema.min_cnn_packets),
            "sequence_horizon": horizon,
            "duration_ms": duration_ms,
            "schema_hash": self.schema.schema_hash(),
        }

        return tensor, mask, metadata
