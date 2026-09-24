"""Deterministic Side-Channel Metadata Distinguishability Components.

Computes 6 independent side-channel distinguishability metrics from
outer packet headers, encrypted flow aggregations, and Stage-7 calibrated predictions.
Every component produces a normalized score in [0.0, 100.0] with zero NaN/Inf risk.
"""

from __future__ import annotations

import math

from app.security.fingerprintability.models import FingerprintabilityComponent


def compute_classifier_distinguishability(
    calibrated_confidence: float | None,
    is_calibrated: bool,
    weight: float = 0.25,
) -> FingerprintabilityComponent:
    """Compute ML empirical classifier distinguishability from calibrated confidence.

    If Stage-7 calibrated prediction is unavailable or uncalibrated,
    this component is marked unavailable rather than using uncalibrated scores.
    """
    if not is_calibrated or calibrated_confidence is None:
        return FingerprintabilityComponent(
            name="classifier_distinguishability",
            score=0.0,
            weight=weight,
            is_available=False,
            rationale="Stage-7 calibrated ML inference unavailable or uncalibrated.",
        )

    score = max(0.0, min(100.0, float(calibrated_confidence) * 100.0))
    if math.isnan(score) or math.isinf(score):
        score = 0.0

    return FingerprintabilityComponent(
        name="classifier_distinguishability",
        score=score,
        weight=weight,
        is_available=True,
        rationale=f"Calibrated empirical model classification confidence: {score:.1f}%.",
    )


def compute_predictive_entropy_complement(
    normalized_entropy: float | None,
    is_calibrated: bool,
    weight: float = 0.15,
) -> FingerprintabilityComponent:
    """Compute concentration of predictive class distribution (1.0 - normalized entropy).

    High complement indicates crisp, non-uniform class assignment distinguishable
    from isotropic/noisy traffic.
    """
    if not is_calibrated or normalized_entropy is None:
        return FingerprintabilityComponent(
            name="predictive_entropy_complement",
            score=0.0,
            weight=weight,
            is_available=False,
            rationale="Predictive entropy unavailable without calibrated Stage-7 prediction.",
        )

    ent = max(0.0, min(1.0, float(normalized_entropy)))
    if math.isnan(ent) or math.isinf(ent):
        ent = 1.0

    score = (1.0 - ent) * 100.0
    return FingerprintabilityComponent(
        name="predictive_entropy_complement",
        score=score,
        weight=weight,
        is_available=True,
        rationale=f"Predictive class probability concentration: {score:.1f}% certainty complement.",
    )


def compute_packet_size_regularity(
    pkt_len_mean: float,
    pkt_len_std: float,
    total_packets: int,
    weight: float = 0.20,
) -> FingerprintabilityComponent:
    """Compute packet length regularity via inverse coefficient of variation.

    Low variance in packet lengths (e.g. constant bitrate audio or heartbeat beacons)
    exposes high structural distinguishability through outer packet sizes.
    """
    if total_packets <= 1 or pkt_len_mean <= 0.0:
        return FingerprintabilityComponent(
            name="packet_size_regularity",
            score=50.0,
            weight=weight,
            is_available=True,
            rationale="Single packet flow; neutral packet size regularity baseline.",
        )

    cv = pkt_len_std / pkt_len_mean
    if math.isnan(cv) or math.isinf(cv):
        cv = 1.0

    # cv = 0.0 -> score = 100.0; cv >= 1.0 -> score = 0.0
    score = max(0.0, min(100.0, (1.0 - min(1.0, cv)) * 100.0))
    return FingerprintabilityComponent(
        name="packet_size_regularity",
        score=score,
        weight=weight,
        is_available=True,
        rationale=f"Packet length CV={cv:.3f} indicates {score:.1f}% sizing regularity.",
    )


def compute_timing_regularity(
    iat_mean: float,
    iat_std: float,
    total_packets: int,
    weight: float = 0.15,
) -> FingerprintabilityComponent:
    """Compute inter-arrival timing regularity via inverse timing coefficient of variation.

    Periodic/isochronous transmission bursts reveal observable temporal fingerprints.
    """
    if total_packets <= 2 or iat_mean <= 0.0:
        return FingerprintabilityComponent(
            name="timing_regularity",
            score=50.0,
            weight=weight,
            is_available=True,
            rationale="Insufficient inter-arrival packet samples; neutral timing baseline.",
        )

    cv = iat_std / iat_mean
    if math.isnan(cv) or math.isinf(cv):
        cv = 1.0

    score = max(0.0, min(100.0, (1.0 - min(1.0, cv)) * 100.0))
    return FingerprintabilityComponent(
        name="timing_regularity",
        score=score,
        weight=weight,
        is_available=True,
        rationale=f"Inter-arrival timing CV={cv:.3f} indicates {score:.1f}% timing regularity.",
    )


def compute_directional_asymmetry(
    fwd_pkt_ratio: float,
    byte_direction_ratio: float | None = None,
    weight: float = 0.15,
) -> FingerprintabilityComponent:
    """Compute directional imbalance between forward and reverse transmission.

    Highly asymmetrical flows (bulk download or data exfiltration) display distinct
    directional bias observable on outer headers.
    """
    ratio = max(0.0, min(1.0, float(fwd_pkt_ratio)))
    pkt_asym = abs(ratio - 0.5) * 2.0  # 0.5 -> 0.0; 0.0 or 1.0 -> 1.0

    if byte_direction_ratio is not None:
        b_ratio = max(0.0, min(1.0, float(byte_direction_ratio)))
        byte_asym = abs(b_ratio - 0.5) * 2.0
        combined_asym = (pkt_asym + byte_asym) / 2.0
    else:
        combined_asym = pkt_asym

    score = max(0.0, min(100.0, combined_asym * 100.0))
    return FingerprintabilityComponent(
        name="directional_asymmetry",
        score=score,
        weight=weight,
        is_available=True,
        rationale=f"Directional transmission ratio={ratio:.2f} reveals {score:.1f}% directional asymmetry.",
    )


def compute_burst_distinguishability(
    burst_count: int,
    total_packets: int,
    duration_ms: float,
    weight: float = 0.10,
) -> FingerprintabilityComponent:
    """Compute burst pattern distinguishability across the flow lifecycle."""
    if total_packets < 4 or duration_ms <= 0.0:
        return FingerprintabilityComponent(
            name="burst_distinguishability",
            score=30.0,
            weight=weight,
            is_available=True,
            rationale="Short duration flow; baseline burst distinguishability.",
        )

    # Bursts per second of flow
    duration_s = duration_ms / 1000.0
    burst_rate = burst_count / duration_s

    # Modulate score: 0 to 5 bursts/sec indicates distinguishable periodic pulsing
    norm_rate = min(1.0, burst_rate / 5.0)
    score = max(0.0, min(100.0, norm_rate * 100.0))

    return FingerprintabilityComponent(
        name="burst_distinguishability",
        score=score,
        weight=weight,
        is_available=True,
        rationale=f"Burst rate {burst_rate:.1f} bursts/sec maps to {score:.1f}% burst distinguishability.",
    )
