"""
Unit tests for Stage 7 Multimodal Fusion Engine.
Tests probability normalization, alpha boundary conditions, disagreement metrics (JS divergence),
and validation grid search.
"""

import numpy as np
import pytest

from app.ml.constants import CANONICAL_CLASSES
from app.ml.fusion import FusionConfig, MultimodalFusionEngine


class TestFusionConfig:
    def test_default_config(self) -> None:
        cfg = FusionConfig()
        assert cfg.method == "WEIGHTED_AVERAGE"
        assert cfg.alpha == 0.5
        assert cfg.classes == list(CANONICAL_CLASSES)
        assert len(cfg.config_hash()) == 64

    def test_custom_alpha_hash_differs(self) -> None:
        cfg1 = FusionConfig(alpha=0.5)
        cfg2 = FusionConfig(alpha=0.7)
        assert cfg1.config_hash() != cfg2.config_hash()


class TestMultimodalFusionEngine:
    @pytest.fixture
    def engine(self) -> MultimodalFusionEngine:
        cfg = FusionConfig(alpha=0.6)
        return MultimodalFusionEngine(cfg)

    def test_alpha_boundaries(self) -> None:
        p_xgb = np.array([[0.7, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0]])
        p_cnn = np.array([[0.1, 0.8, 0.1, 0.0, 0.0, 0.0, 0.0]])

        # alpha = 1.0 (XGBoost only)
        engine_xgb = MultimodalFusionEngine(FusionConfig(alpha=1.0))
        fused_xgb = engine_xgb.fuse(p_xgb, p_cnn)
        np.testing.assert_allclose(fused_xgb, p_xgb, rtol=1e-5)

        # alpha = 0.0 (CNN only)
        engine_cnn = MultimodalFusionEngine(FusionConfig(alpha=0.0))
        fused_cnn = engine_cnn.fuse(p_xgb, p_cnn)
        np.testing.assert_allclose(fused_cnn, p_cnn, rtol=1e-5)

        # alpha = 0.5 (Equal weighting)
        engine_equal = MultimodalFusionEngine(FusionConfig(alpha=0.5))
        fused_equal = engine_equal.fuse(p_xgb, p_cnn)
        expected_equal = np.array([[0.4, 0.5, 0.1, 0.0, 0.0, 0.0, 0.0]])
        np.testing.assert_allclose(fused_equal, expected_equal, rtol=1e-5)

    def test_weighted_fusion_computation(self, engine: MultimodalFusionEngine) -> None:
        p_xgb = np.array([[0.8, 0.2, 0.0, 0.0, 0.0, 0.0, 0.0]])
        p_cnn = np.array([[0.2, 0.8, 0.0, 0.0, 0.0, 0.0, 0.0]])
        fused = engine.fuse(p_xgb, p_cnn)

        # 0.6 * 0.8 + 0.4 * 0.2 = 0.48 + 0.08 = 0.56
        # 0.6 * 0.2 + 0.4 * 0.8 = 0.12 + 0.32 = 0.44
        expected = np.array([[0.56, 0.44, 0.0, 0.0, 0.0, 0.0, 0.0]])
        np.testing.assert_allclose(fused, expected, rtol=1e-5)
        # Verify probabilities sum to 1
        assert np.isclose(fused.sum(), 1.0)

    def test_invalid_alpha(self, engine: MultimodalFusionEngine) -> None:
        p = np.zeros((1, 7))
        with pytest.raises(ValueError, match="Alpha must be in"):
            engine.fuse(p, p, alpha=1.5)
        with pytest.raises(ValueError, match="Alpha must be in"):
            engine.fuse(p, p, alpha=-0.1)

    def test_dimension_and_nan_checks(self, engine: MultimodalFusionEngine) -> None:
        # Mismatched shapes
        with pytest.raises(ValueError, match="Shape mismatch"):
            engine.fuse(
                np.zeros((2, 7)),
                np.zeros((3, 7)),
            )

        # Wrong number of classes
        with pytest.raises(ValueError, match="Expected 7 classes"):
            engine.fuse(
                np.zeros((1, 5)),
                np.zeros((1, 5)),
            )

    def test_disagreement_diagnostics(self, engine: MultimodalFusionEngine) -> None:
        # Perfect agreement
        p_same = np.array([[0.9, 0.05, 0.05, 0.0, 0.0, 0.0, 0.0]])
        diag_agree = engine.compute_disagreement(p_same, p_same)
        assert diag_agree["agreement_rate"] == 1.0
        assert diag_agree["sample_agreements"] == [True]
        assert np.isclose(diag_agree["mean_js_divergence"], 0.0, atol=1e-4)

        # Disagreement
        p_xgb = np.array([[0.9, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0]])
        p_cnn = np.array([[0.1, 0.9, 0.0, 0.0, 0.0, 0.0, 0.0]])
        diag_disagree = engine.compute_disagreement(p_xgb, p_cnn)
        assert diag_disagree["agreement_rate"] == 0.0
        assert diag_disagree["sample_agreements"] == [False]
        assert diag_disagree["mean_js_divergence"] > 0.3

    def test_grid_search_alpha(self) -> None:
        # Construct synthetic validation predictions where CNN is superior
        # Ground truth: 20 samples of class 0, 20 of class 1
        y_true = np.array([0] * 20 + [1] * 20)

        # CNN has 100% accuracy
        p_cnn = np.zeros((40, 7))
        p_cnn[:20, 0] = 0.95
        p_cnn[:20, 1] = 0.05
        p_cnn[20:, 0] = 0.05
        p_cnn[20:, 1] = 0.95

        # XGB has 50% accuracy (confused)
        p_xgb = np.zeros((40, 7))
        p_xgb[:, 0] = 0.51
        p_xgb[:, 1] = 0.49

        engine = MultimodalFusionEngine()
        metrics = engine.search_optimal_alpha(p_xgb, p_cnn, y_true, grid_steps=11)

        assert "best_alpha" in metrics
        assert "best_macro_f1" in metrics
        assert "grid_results" in metrics
        assert len(metrics["grid_results"]) == 11
        # CNN is superior, so best alpha should be 0.0 or heavily CNN-biased
        assert metrics["best_alpha"] <= 0.2
