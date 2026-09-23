"""
Unit tests for Stage 7 Behavioral Anomaly Detector (Isolation Forest).
Tests training on benign flows, threshold calibration on benign validation,
safe zero-pickle JSON serialization/deserialization, exact scoring, and explicit
'STATISTICAL_BEHAVIORAL_ANOMALY' naming (zero 'attack' / 'malware' claims).
"""

from pathlib import Path

import numpy as np
import pytest

from app.ml.anomaly import (
    AnomalyDecision,
    AnomalyFeatureSchema,
    IsolationForestAnomalyDetector,
)
from app.ml.auditor import LeakageDetectedError


class TestAnomalyFeatureSchema:
    def test_default_schema_valid_and_hashed(self) -> None:
        schema = AnomalyFeatureSchema()
        assert len(schema.features) > 0
        assert len(schema.schema_hash()) == 64

    def test_leakage_detection(self) -> None:
        bad_features = ["packet_count", "source_ip", "duration_seconds"]
        schema = AnomalyFeatureSchema(features=bad_features)
        detector = IsolationForestAnomalyDetector(schema=schema)
        with pytest.raises(LeakageDetectedError):
            detector.fit(np.zeros((5, 3)))


class TestIsolationForestAnomalyDetector:
    @pytest.fixture
    def benign_data(self) -> tuple[np.ndarray, np.ndarray, list[str]]:
        np.random.seed(42)
        feature_names = [
            "f15_total_packets",
            "f16_total_bytes",
            "f17_flow_duration_ms",
            "f18_packet_rate_pps",
            "f19_byte_rate_bps",
        ]
        # Benign training data: Gaussian distribution centered at 0
        x_train = np.random.randn(100, len(feature_names))
        # Benign validation data: same distribution
        x_val = np.random.randn(40, len(feature_names))
        return x_train, x_val, feature_names

    def test_training_and_scoring(
        self, benign_data: tuple[np.ndarray, np.ndarray, list[str]]
    ) -> None:
        x_train, x_val, feature_names = benign_data
        schema = AnomalyFeatureSchema(features=feature_names)
        detector = IsolationForestAnomalyDetector(schema=schema)

        detector.fit(x_train, n_estimators=20)
        assert len(detector.trees_data) == 20

        # Score benign samples
        scores = detector.score_samples(x_val)
        assert scores.shape == (40,)
        # Anomaly scores should be bounded within [0, 1]
        assert np.all(scores >= 0.0)
        assert np.all(scores <= 1.0)

    def test_calibrate_threshold_and_detect_outlier(
        self, benign_data: tuple[np.ndarray, np.ndarray, list[str]]
    ) -> None:
        x_train, x_val, feature_names = benign_data
        schema = AnomalyFeatureSchema(features=feature_names)
        detector = IsolationForestAnomalyDetector(schema=schema)
        detector.fit(x_train, n_estimators=30)

        # Calibrate threshold on benign validation with target max FPR = 0.05
        thresh = detector.tune_threshold(x_val, target_fpr=0.05)
        assert 0.0 < thresh < 1.0
        assert detector.operational_threshold == thresh

        # Test normal benign flow
        benign_dict = dict.fromkeys(feature_names, 0.0)
        benign_decision: AnomalyDecision = detector.evaluate_flow(benign_dict)
        assert benign_decision.status == "NORMAL_BEHAVIOR"
        assert benign_decision.is_anomaly is False

        # Test extreme outlier sample
        outlier_dict = dict.fromkeys(feature_names, 50.0)
        anomaly_decision: AnomalyDecision = detector.evaluate_flow(outlier_dict)
        assert anomaly_decision.status == "STATISTICAL_BEHAVIORAL_ANOMALY"
        assert anomaly_decision.is_anomaly is True
        # Verify no "attack", "malware", or "zero-day" in status
        assert "attack" not in anomaly_decision.status.lower()
        assert "malware" not in anomaly_decision.status.lower()
        assert "zero_day" not in anomaly_decision.status.lower()

    def test_safe_json_serialization_and_reload(
        self, benign_data: tuple[np.ndarray, np.ndarray, list[str]], tmp_path: Path
    ) -> None:
        x_train, x_val, feature_names = benign_data
        schema = AnomalyFeatureSchema(features=feature_names)
        detector = IsolationForestAnomalyDetector(schema=schema)
        detector.fit(x_train, n_estimators=15)
        detector.tune_threshold(x_val, target_fpr=0.05)

        test_points = np.random.randn(10, len(feature_names))
        orig_scores = detector.score_samples(test_points)

        # Save to JSON
        json_path = tmp_path / "isolation_forest.json"
        detector.save_json(json_path)

        # Confirm file is text/json, not pickle binary
        content = json_path.read_text(encoding="utf-8")
        assert "num_trees" in content
        assert "trees_data" in content
        assert "operational_threshold" in content

        # Reload from JSON
        loaded = IsolationForestAnomalyDetector.load_json(json_path, schema=schema)
        assert len(loaded.trees_data) == 15
        assert loaded.operational_threshold == detector.operational_threshold

        # Loaded scores should match exactly
        loaded_scores = loaded.score_samples(test_points)
        np.testing.assert_allclose(orig_scores, loaded_scores, rtol=1e-5)
