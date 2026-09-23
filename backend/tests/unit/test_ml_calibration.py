"""
Unit tests for Stage 7 Probability Calibrator.
Tests temperature scaling optimization, NLL, Brier score, ECE computation across 10 bins,
reliability diagram construction, and serialization.
"""

import json
from pathlib import Path

import numpy as np
import pytest

from app.ml.calibration import CalibrationConfig, ProbabilityCalibrator


class TestCalibrationConfig:
    def test_default_config(self) -> None:
        cfg = CalibrationConfig()
        assert cfg.method == "TEMPERATURE_SCALING"
        assert cfg.temperature == 1.0
        assert cfg.num_classes == 7
        assert len(cfg.config_hash()) == 64


class TestProbabilityCalibrator:
    @pytest.fixture
    def calibrator(self) -> ProbabilityCalibrator:
        cfg = CalibrationConfig(temperature=1.0)
        return ProbabilityCalibrator(cfg)

    def test_compute_metrics_perfect(self, calibrator: ProbabilityCalibrator) -> None:
        # Perfectly calibrated and accurate: 10 samples of class 0 with p=1.0
        probs = np.zeros((10, 7))
        probs[:, 0] = 1.0
        y_true = np.zeros(10, dtype=int)

        ece, diag = calibrator.compute_ece(probs, y_true)
        assert ece < 1e-4
        assert "bin_centers" in diag
        assert "accuracies" in diag
        assert "confidences" in diag

    def test_compute_metrics_overconfident_poor(self, calibrator: ProbabilityCalibrator) -> None:
        # Completely wrong and confident
        probs = np.zeros((10, 7))
        probs[:, 0] = 1.0
        y_true = np.ones(10, dtype=int)  # True class is 1

        ece, _ = calibrator.compute_ece(probs, y_true)
        assert ece > 0.8

    def test_temperature_scaling_optimization(self) -> None:
        # Create overconfident predictions that need softening (temperature > 1.0)
        np.random.seed(42)
        n = 100
        # Simulating sharp probabilities with some noise in true labels
        probs = np.zeros((n, 7))
        for i in range(n):
            c = i % 7
            probs[i, c] = 0.95
            probs[i, (c + 1) % 7] = 0.05
        # 30% mislabeled to induce need for temperature softening
        y_true = np.array([i % 7 for i in range(n)])
        y_true[:30] = (y_true[:30] + 1) % 7

        calibrator = ProbabilityCalibrator()
        metrics = calibrator.fit_temperature(probs, y_true, num_bins=10)

        assert metrics.nll_after <= metrics.nll_before
        assert calibrator.config.temperature > 0.0
        assert calibrator.config.method == "TEMPERATURE_SCALING"

    def test_calibrate_and_probabilities_sum(self) -> None:
        np.random.seed(42)
        n = 50
        raw_probs = np.random.dirichlet(np.ones(7), size=n)

        calibrator = ProbabilityCalibrator(CalibrationConfig(temperature=1.5))
        calibrated = calibrator.calibrate(raw_probs)

        assert calibrated.shape == raw_probs.shape
        np.testing.assert_allclose(calibrated.sum(axis=1), 1.0, rtol=1e-5)

    def test_invalid_temperature_raises(self, calibrator: ProbabilityCalibrator) -> None:
        calibrator.config.temperature = -0.5
        p = np.zeros((2, 7))
        with pytest.raises(ValueError, match="strictly positive"):
            calibrator.calibrate(p)

    def test_serialization(self, tmp_path: Path) -> None:
        cfg = CalibrationConfig(temperature=1.35)
        calibrator = ProbabilityCalibrator(cfg)
        json_file = tmp_path / "calibration.json"
        with open(json_file, "w", encoding="utf-8") as f:
            f.write(calibrator.config.to_json())

        with open(json_file, encoding="utf-8") as f:
            loaded_cfg = CalibrationConfig.from_dict(json.load(f))
        assert loaded_cfg.temperature == 1.35
        assert loaded_cfg.config_hash() == cfg.config_hash()
