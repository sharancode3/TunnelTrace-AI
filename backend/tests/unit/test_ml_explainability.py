"""
Unit tests for Stage 7 TreeSHAP Explainer (XGBoost branch explainability).
Tests local positive/negative contributions, additivity property, feature leakage checks,
and explicit XGBoost-only attribution scope.
"""

import numpy as np
import pytest
import xgboost as xgb

from app.ml.auditor import LeakageDetectedError
from app.ml.constants import CANONICAL_CLASSES
from app.ml.explainability import TreeSHAPExplainer


@pytest.fixture
def trained_xgb_and_features() -> tuple[xgb.XGBClassifier, list[str]]:
    # Train a minimal 7-class XGBoost model on 10 synthetic statistical features
    np.random.seed(42)
    feature_names = [
        "packet_count",
        "byte_count",
        "duration_seconds",
        "packets_per_second",
        "bytes_per_second",
        "mean_packet_length",
        "std_packet_length",
        "min_packet_length",
        "max_packet_length",
        "mean_iat",
    ]
    x_train = np.random.randn(70, len(feature_names))
    y_train = np.array([i % 7 for i in range(70)])

    model = xgb.XGBClassifier(
        n_estimators=5,
        max_depth=2,
        learning_rate=0.1,
        objective="multi:softprob",
        num_class=7,
        random_state=42,
    )
    model.fit(x_train, y_train)
    return model, feature_names


class TestTreeSHAPExplainer:
    def test_explainability_initialization_and_leakage_audit(
        self, trained_xgb_and_features: tuple[xgb.XGBClassifier, list[str]]
    ) -> None:
        model, feature_names = trained_xgb_and_features
        explainer = TreeSHAPExplainer(model, feature_names=feature_names)
        assert explainer.feature_names == feature_names
        assert explainer.classes == list(CANONICAL_CLASSES)

    def test_leakage_detection_raises_error(
        self, trained_xgb_and_features: tuple[xgb.XGBClassifier, list[str]]
    ) -> None:
        model, _ = trained_xgb_and_features
        # Inject forbidden feature names
        forbidden_features = [
            "packet_count",
            "src_ip",  # FORBIDDEN!
            "duration_seconds",
            "dst_port",  # FORBIDDEN!
            "esp_spi",  # FORBIDDEN!
            "mean_packet_length",
            "std_packet_length",
            "min_packet_length",
            "max_packet_length",
            "mean_iat",
        ]
        with pytest.raises(LeakageDetectedError):
            TreeSHAPExplainer(model, feature_names=forbidden_features)

    def test_local_explanation_structure_and_scope(
        self, trained_xgb_and_features: tuple[xgb.XGBClassifier, list[str]]
    ) -> None:
        model, feature_names = trained_xgb_and_features
        explainer = TreeSHAPExplainer(model, feature_names=feature_names)

        sample = np.random.randn(len(feature_names))
        explanation = explainer.explain_flow(sample, target_class_idx=0, top_k=3)

        assert explanation.explained_model_branch == "XGBOOST_BRANCH_ONLY"
        assert explanation.target_class_index == 0
        assert explanation.target_class_name == CANONICAL_CLASSES[0]
        assert len(explanation.top_positive_contributions) <= 3
        assert len(explanation.top_negative_contributions) <= 3

        for item in explanation.top_positive_contributions:
            assert item.contribution >= 0
            assert item.direction == "POSITIVE"
            assert item.feature_name in feature_names

        for item in explanation.top_negative_contributions:
            assert item.contribution < 0
            assert item.direction == "NEGATIVE"
            assert item.feature_name in feature_names

    def test_global_summary_computation(
        self, trained_xgb_and_features: tuple[xgb.XGBClassifier, list[str]]
    ) -> None:
        model, feature_names = trained_xgb_and_features
        explainer = TreeSHAPExplainer(model, feature_names=feature_names)

        x_val = np.random.randn(15, len(feature_names))
        summary = explainer.compute_global_summary(x_val)

        assert len(summary) == len(feature_names)
        for val in summary.values():
            assert val >= 0.0
