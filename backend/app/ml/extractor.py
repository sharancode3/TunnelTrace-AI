"""Tabular Feature Extractor for Encrypted ESP Flows."""

from __future__ import annotations

import math
from typing import Any

import numpy as np

from app.ml.schema import FeatureSchema


class ExtractionError(Exception):
    """Raised when flow packet sequence cannot be extracted or is numerically invalid."""


class TabularFeatureExtractor:
    """Computes leakage-safe macroscopic side-channel tabular features from encrypted ESP packet streams.

    Operates strictly on outer WAN transport metadata:
    - Packet arrival timestamps
    - Wire lengths
    - Relative packet direction (+1 for forward, -1 for reverse)

    Zero payload inspection. Zero cryptographic parameter leakage.
    """

    def __init__(self, schema: FeatureSchema | None = None) -> None:
        self.schema = schema or FeatureSchema()

    def extract_features(
        self,
        packets: list[dict[str, Any]],
        flow_metadata: dict[str, Any] | None = None,
    ) -> tuple[dict[str, float], dict[str, Any]]:
        """Extract tabular features from an ordered sequence of ESP packets for a single flow.

        Args:
            packets: List of packet dicts, each containing:
                - 'packet_time' (float, seconds)
                - 'packet_length' (int/float, bytes)
                - 'direction' (int, +1 for fwd, -1 for rev, or inferred from SPI)
            flow_metadata: Optional dict containing flow/session provenance for auditing.

        Returns:
            tuple of (feature_row_dict, provenance_metadata_dict)

        Raises:
            ExtractionError: If packets list is empty or numerical corruption is detected.
        """
        if not packets:
            raise ExtractionError("NO_PACKETS: Packet sequence is empty.")

        # Check for timestamp inversions in raw input
        raw_times = [float(p.get("packet_time", 0.0)) for p in packets]
        if len(raw_times) > 1 and any(raw_times[i] < raw_times[i - 1] for i in range(1, len(raw_times))):
            raise ExtractionError("TIMESTAMP_INVERSION: Packet timestamps are not monotonically non-decreasing.")

        # Sort chronologically by packet_time
        sorted_pkts = sorted(packets, key=lambda p: float(p.get("packet_time", 0.0)))
        k = len(sorted_pkts)

        times = np.array([float(p["packet_time"]) for p in sorted_pkts], dtype=np.float64)
        lengths = np.array([float(p["packet_length"]) for p in sorted_pkts], dtype=np.float64)

        # Detect negative packet lengths or invalid timestamps
        if np.any(lengths < 0):
            raise ExtractionError("NEGATIVE_PACKET_LENGTH: Flow contains negative packet lengths.")
        if np.any(np.isnan(times)) or np.any(np.isnan(lengths)):
            raise ExtractionError("NAN_DETECTED: Packet sequence contains NaN values.")
        if np.any(np.isinf(times)) or np.any(np.isinf(lengths)):
            raise ExtractionError("INF_DETECTED: Packet sequence contains infinite values.")

        # Resolve direction (+1 = forward, -1 = reverse)
        directions = []
        for p in sorted_pkts:
            d = p.get("direction")
            if d is None:
                # If flow_metadata has forward spi, check packet spi
                if flow_metadata and "spi" in flow_metadata and p.get("spi"):
                    d = 1 if str(p["spi"]).lower() == str(flow_metadata["spi"]).lower() else -1
                else:
                    d = 1
            directions.append(1 if d > 0 else -1)
        directions = np.array(directions, dtype=np.int32)

        # ----------------------------------------------------------------------
        # 1. Flow-Level Metrics
        # ----------------------------------------------------------------------
        duration_sec = float(times[-1] - times[0]) if k > 1 else 0.0
        if duration_sec < 0.0:
            duration_sec = 0.0
        duration_ms = duration_sec * 1000.0

        total_packets = float(k)
        total_bytes = float(np.sum(lengths))

        # ----------------------------------------------------------------------
        # 2. Directional Metrics
        # ----------------------------------------------------------------------
        fwd_mask = directions == 1
        rev_mask = directions == -1
        k_fwd = int(np.sum(fwd_mask))
        k_rev = int(np.sum(rev_mask))

        bytes_fwd = float(np.sum(lengths[fwd_mask])) if k_fwd > 0 else 0.0

        fwd_pkt_ratio = float(k_fwd / k) if k > 0 else 0.5
        byte_direction_ratio = float(bytes_fwd / total_bytes) if total_bytes > 0.0 else 0.5

        # Bound to [0.0, 1.0]
        fwd_pkt_ratio = max(0.0, min(1.0, fwd_pkt_ratio))
        byte_direction_ratio = max(0.0, min(1.0, byte_direction_ratio))

        # ----------------------------------------------------------------------
        # 3. Size Metrics
        # ----------------------------------------------------------------------
        pkt_len_mean = float(np.mean(lengths))
        pkt_len_std = float(np.std(lengths, ddof=1)) if k > 1 else 0.0

        # Fisher-Pearson skewness
        if k >= 3 and pkt_len_std > 1e-6:
            m3 = float(np.mean((lengths - pkt_len_mean) ** 3))
            m2 = float(np.mean((lengths - pkt_len_mean) ** 2))
            skew_val = m3 / (m2 ** 1.5) if m2 > 1e-12 else 0.0
            pkt_len_skew = float(max(-3.0, min(3.0, skew_val)))
        else:
            pkt_len_skew = 0.0

        pkt_len_p10 = float(np.percentile(lengths, 10))
        pkt_len_p25 = float(np.percentile(lengths, 25))
        pkt_len_median = float(np.percentile(lengths, 50))
        pkt_len_p75 = float(np.percentile(lengths, 75))
        pkt_len_p90 = float(np.percentile(lengths, 90))

        # ----------------------------------------------------------------------
        # 4. Timing Metrics (Inter-Arrival Times)
        # ----------------------------------------------------------------------
        if k > 1:
            iats_sec = np.diff(times)
            iats_ms = iats_sec * 1000.0
            iat_mean_ms = float(np.mean(iats_ms))
            iat_std_ms = float(np.std(iats_ms, ddof=1)) if len(iats_ms) >= 2 else 0.0
            iat_max_ms = float(np.max(iats_ms))
        else:
            iats_ms = np.array([], dtype=np.float64)
            iat_mean_ms = 0.0
            iat_std_ms = 0.0
            iat_max_ms = 0.0

        # Forward stream IAT
        if k_fwd >= 2:
            fwd_times = times[fwd_mask]
            fwd_iats_ms = np.diff(fwd_times) * 1000.0
            fwd_iat_mean_ms = float(np.mean(fwd_iats_ms))
        else:
            fwd_iat_mean_ms = 0.0

        # Reverse stream IAT
        if k_rev >= 2:
            rev_times = times[rev_mask]
            rev_iats_ms = np.diff(rev_times) * 1000.0
            rev_iat_mean_ms = float(np.mean(rev_iats_ms))
        else:
            rev_iat_mean_ms = 0.0

        # ----------------------------------------------------------------------
        # 5. Rate Metrics
        # ----------------------------------------------------------------------
        if duration_sec > 1e-6:
            packets_per_second = float(k / duration_sec)
            bytes_per_second = float(total_bytes / duration_sec)
        else:
            packets_per_second = 0.0
            bytes_per_second = 0.0

        # ----------------------------------------------------------------------
        # 6. Burst Metrics
        # ----------------------------------------------------------------------
        burst_thresh = self.schema.burst_threshold_ms
        burst_count = 0.0
        burst_bytes_list: list[float] = []

        if len(iats_ms) > 0:
            in_burst = False
            current_burst_bytes = 0.0
            for i, iat in enumerate(iats_ms):
                if iat < burst_thresh:
                    if not in_burst:
                        in_burst = True
                        current_burst_bytes = lengths[i] + lengths[i + 1]
                    else:
                        current_burst_bytes += lengths[i + 1]
                else:
                    if in_burst:
                        burst_count += 1.0
                        burst_bytes_list.append(current_burst_bytes)
                        in_burst = False
                        current_burst_bytes = 0.0
            if in_burst:
                burst_count += 1.0
                burst_bytes_list.append(current_burst_bytes)

        burst_mean_bytes = float(np.mean(burst_bytes_list)) if burst_bytes_list else 0.0

        # ----------------------------------------------------------------------
        # 7. Idle Metrics
        # ----------------------------------------------------------------------
        idle_thresh = self.schema.idle_threshold_ms
        if duration_ms > 1e-6 and len(iats_ms) > 0:
            idle_iats = iats_ms[iats_ms > idle_thresh]
            total_idle_ms = float(np.sum(idle_iats))
            idle_ratio = max(0.0, min(1.0, float(total_idle_ms / duration_ms)))
        else:
            idle_ratio = 0.0

        # ----------------------------------------------------------------------
        # 8. Early-Flow Aggregate (First K Packets)
        # ----------------------------------------------------------------------
        early_k = self.schema.early_k
        first_k_bytes = float(np.sum(lengths[:early_k]))

        # Assemble the dictionary in strict schema order
        row: dict[str, float] = {
            "duration_ms": duration_ms,
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "fwd_pkt_ratio": fwd_pkt_ratio,
            "byte_direction_ratio": byte_direction_ratio,
            "pkt_len_mean": pkt_len_mean,
            "pkt_len_std": pkt_len_std,
            "pkt_len_skew": pkt_len_skew,
            "pkt_len_p10": pkt_len_p10,
            "pkt_len_p25": pkt_len_p25,
            "pkt_len_median": pkt_len_median,
            "pkt_len_p75": pkt_len_p75,
            "pkt_len_p90": pkt_len_p90,
            "iat_mean_ms": iat_mean_ms,
            "iat_std_ms": iat_std_ms,
            "iat_max_ms": iat_max_ms,
            "fwd_iat_mean_ms": fwd_iat_mean_ms,
            "rev_iat_mean_ms": rev_iat_mean_ms,
            "packets_per_second": packets_per_second,
            "bytes_per_second": bytes_per_second,
            "burst_count": burst_count,
            "burst_mean_bytes": burst_mean_bytes,
            "idle_ratio": idle_ratio,
            "first_k_bytes": first_k_bytes,
        }

        # Validate that all features are finite
        for fname, fval in row.items():
            if math.isnan(fval) or math.isinf(fval):
                raise ExtractionError(f"CORRUPT_FEATURE: Feature '{fname}' produced non-finite value {fval}.")

        # Provenance metadata kept separate from features
        provenance = dict(flow_metadata) if flow_metadata else {}
        provenance["packet_count_verified"] = k
        provenance["duration_sec_verified"] = duration_sec

        return row, provenance
