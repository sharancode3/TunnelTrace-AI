"""
Unit tests for Stage 7 Open-Set Recognition / Out-of-Distribution (OOD) Gating.
Tests Shannon entropy, normalized entropy, dual-threshold gating, UNKNOWN_UNSEEN rejection,
and validation threshold tuning.
"""

import json
from pathlib import Path

import numpy as np
import pytest

from app.ml.ood import OODConfig, OODDetector


class TestOODConfig:
    def test_default_config(self) -> None:
        cfg = OODConfig()
        assert cfg.entropy_threshold == 1.8
        assert cfg.min_confidence_threshold == 0.45
        assert cfg.num_classes == 7
        assert len(cfg.config_hash()) == 64


class TestOODDetector:
    @pytest.fixture
    def detector(self) -> OODDetector:
        cfg = OODConfig(entropy_threshold=1.2, min_confidence_threshold=0.5, num_classes=7)
        return OODDetector(cfg)

    def test_compute_entropy_extremes(self, detector: OODDetector) -> None:
        # Uniform distribution: maximum entropy = log2(7) ≈ 2.80735
        p_uniform = np.ones((1, 7)) / 7.0
        h, h_norm = detector.compute_entropy(p_uniform)
        assert np.isclose(h[0], np.log2(7), atol=1e-4)
        assert np.isclose(h_norm[0], 1.0, atol=1e-4)

        # Deterministic distribution: minimum entropy = 0.0
        p_sharp = np.zeros((1, 7))
        p_sharp[0, 0] = 1.0
        h_sharp, h_sharp_norm = detector.compute_entropy(p_sharp)
        assert np.isclose(h_sharp[0], 0.0, atol=1e-4)
        assert np.isclose(h_sharp_norm[0], 0.0, atol=1e-4)

    def test_evaluate_flow_known_acceptance(self, detector: OODDetector) -> None:
        # High confidence, low entropy -> Known class accepted
        p_known = np.array([0.85, 0.05, 0.02, 0.02, 0.02, 0.02, 0.02])
        decision = detector.evaluate_flow(p_known)

        assert decision.is_ood is False
        assert decision.status == "KNOWN_ACCEPTED"
        assert decision.rejection_reason is None
        assert decision.max_confidence == 0.85

    def test_evaluate_flow_entropy_rejection(self, detector: OODDetector) -> None:
        # Flat distribution -> high entropy > 1.2 -> rejected as UNKNOWN_UNSEEN
        p_diffuse = np.array([0.25, 0.20, 0.15, 0.15, 0.10, 0.10, 0.05])
        decision = detector.evaluate_flow(p_diffuse)

        assert decision.is_ood is True
        assert decision.status == "UNKNOWN_UNSEEN"
        assert decision.rejection_reason in ("HIGH_ENTROPY", "DUAL_TRIGGER", "LOW_CONFIDENCE")

    def test_evaluate_flow_confidence_rejection(self, detector: OODDetector) -> None:
        # Max prob < 0.50 -> rejected as UNKNOWN_UNSEEN
        p_low_max = np.array([0.45, 0.45, 0.02, 0.02, 0.02, 0.02, 0.02])
        decision = detector.evaluate_flow(p_low_max)

        assert decision.is_ood is True
        assert decision.status == "UNKNOWN_UNSEEN"

    def test_tune_thresholds(self) -> None:
        # Known validation samples: sharp distribution
        np.random.seed(42)
        n_known = 50
        val_known_probs = np.zeros((n_known, 7))
        for i in range(n_known):
            c = i % 7
            val_known_probs[i, c] = 0.90
            val_known_probs[i, (c + 1) % 7] = 0.10

        # OOD validation samples: uniform/diffuse distribution
        n_ood = 30
        val_ood_probs = np.random.dirichlet(np.ones(7), size=n_ood)

        detector = OODDetector()
        metrics = detector.tune_thresholds(
            val_known_probs, val_ood_probs, target_frr=0.05
        )

        assert detector.config.min_confidence_threshold > 0.0
        assert detector.config.entropy_threshold > 0.0
        assert "auroc" in metrics
        assert "aupr" in metrics

    def test_serialization(self, tmp_path: Path) -> None:
        cfg = OODConfig(entropy_threshold=1.33, min_confidence_threshold=0.48)
        detector = OODDetector(cfg)
        json_file = tmp_path / "ood.json"
        with open(json_file, "w", encoding="utf-8") as f:
            f.write(detector.config.to_json())

        with open(json_file, encoding="utf-8") as f:
            loaded_cfg = OODConfig.from_dict(json.load(f))
        assert loaded_cfg.entropy_threshold == 1.33
        assert loaded_cfg.min_confidence_threshold == 0.48
        assert loaded_cfg.config_hash() == cfg.config_hash()
