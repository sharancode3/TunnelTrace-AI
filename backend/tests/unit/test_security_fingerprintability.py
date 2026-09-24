"""Unit tests for Metadata Fingerprintability (Side-Channel Distinguishability)."""

from __future__ import annotations

import pytest

from app.security.fingerprintability.components import (
    compute_classifier_distinguishability,
    compute_directional_asymmetry,
    compute_packet_size_regularity,
    compute_predictive_entropy_complement,
)
from app.security.fingerprintability.engine import MetadataFingerprintabilityEngine
from app.security.fingerprintability.models import CalibrationStatus, FingerprintabilityStatus


class TestMetadataFingerprintability:
    """Tests for side-channel distinguishability calculations and bounds."""

    @pytest.fixture
    def mfi_engine(self):
        return MetadataFingerprintabilityEngine()

    def test_classifier_distinguishability_uncalibrated_failsafe(self) -> None:
        """Uncalibrated raw prediction must NOT be used as calibrated distinguishability."""
        comp_uncal = compute_classifier_distinguishability(
            calibrated_confidence=0.95,
            is_calibrated=False,
        )
        assert not comp_uncal.is_available
        assert comp_uncal.score == 0.0

        comp_cal = compute_classifier_distinguishability(
            calibrated_confidence=0.92,
            is_calibrated=True,
        )
        assert comp_cal.is_available
        assert comp_cal.score == pytest.approx(92.0, 0.1)

    def test_predictive_entropy_complement(self) -> None:
        """Low entropy (high certainty) yields high distinguishability complement."""
        comp_crisp = compute_predictive_entropy_complement(
            normalized_entropy=0.10,
            is_calibrated=True,
        )
        assert comp_crisp.is_available
        assert comp_crisp.score == pytest.approx(90.0, 0.1)

        comp_uniform = compute_predictive_entropy_complement(
            normalized_entropy=0.95,
            is_calibrated=True,
        )
        assert comp_uniform.is_available
        assert comp_uniform.score == pytest.approx(5.0, 0.1)

    def test_packet_size_regularity(self) -> None:
        """Constant packet size (CV=0) indicates 100% sizing regularity."""
        comp_const = compute_packet_size_regularity(
            pkt_len_mean=1420.0,
            pkt_len_std=0.0,
            total_packets=50,
        )
        assert comp_const.is_available
        assert comp_const.score == 100.0

        comp_mixed = compute_packet_size_regularity(
            pkt_len_mean=800.0,
            pkt_len_std=800.0,  # CV = 1.0
            total_packets=50,
        )
        assert comp_mixed.is_available
        assert comp_mixed.score == 0.0

    def test_directional_asymmetry(self) -> None:
        """Balanced traffic (50/50) yields 0% asymmetry; pure forward yields 100% asymmetry."""
        comp_sym = compute_directional_asymmetry(fwd_pkt_ratio=0.5)
        assert comp_sym.score == pytest.approx(0.0, 0.1)

        comp_asym = compute_directional_asymmetry(fwd_pkt_ratio=1.0)
        assert comp_asym.score == pytest.approx(100.0, 0.1)

    def test_full_engine_evaluation_with_ml(self, mfi_engine) -> None:
        flow_features = {
            "flow_id": "flow-1",
            "pkt_len_mean": 1200.0,
            "pkt_len_std": 120.0,
            "total_packets": 100,
            "fwd_pkt_ratio": 0.85,
            "iat_mean": 25.0,
            "iat_std": 5.0,
            "burst_count": 4,
            "duration_ms": 2000.0,
        }
        ml_pred = {
            "is_calibrated": True,
            "calibrated_confidence": 0.91,
            "normalized_entropy": 0.15,
        }

        res = mfi_engine.assess_flow(
            analysis_id="analysis-1",
            flow_id="flow-1",
            flow_features=flow_features,
            ml_prediction=ml_pred,
        )
        assert res.overall_index is not None
        assert 0.0 <= res.overall_index <= 100.0
        assert res.status == FingerprintabilityStatus.EXPERIMENTAL
        assert res.calibration_status == CalibrationStatus.CALIBRATED
        assert "NOT plaintext leakage percentage" in res.disclaimer
        assert "percent plaintext leaked" not in res.disclaimer.lower()

    def test_graceful_degradation_without_ml(self, mfi_engine) -> None:
        """When ML is absent, non-ML components evaluate gracefully."""
        flow_features = {
            "flow_id": "flow-no-ml",
            "pkt_len_mean": 1000.0,
            "pkt_len_std": 200.0,
            "total_packets": 20,
            "fwd_pkt_ratio": 0.5,
            "iat_mean": 10.0,
            "iat_std": 2.0,
            "burst_count": 1,
            "duration_ms": 500.0,
        }

        res = mfi_engine.assess_flow(
            analysis_id="analysis-1",
            flow_id="flow-no-ml",
            flow_features=flow_features,
            ml_prediction=None,
        )
        assert res.overall_index is not None
        assert 0.0 <= res.overall_index <= 100.0
        assert not res.components["classifier_distinguishability"].is_available
        assert res.components["packet_size_regularity"].is_available
