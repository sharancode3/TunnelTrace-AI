"""Unit tests for train-only preprocessing and sample weighting."""

from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from app.ml.preprocessing import FeaturePreprocessor
from app.ml.weighting import SampleWeightComputer


def test_train_only_fit_scoping():
    """Verify that preprocessing parameters are derived strictly from TRAIN partition."""
    # Training data: values [10, 20, 30] -> median 20
    df_train = pd.DataFrame({
        "duration_ms": [10.0, 20.0, 30.0],
        "total_packets": [10.0, 20.0, 30.0],
    })

    # Test data: extreme outlier [1000, 2000, 3000]
    df_test = pd.DataFrame({
        "duration_ms": [1000.0, 2000.0, 3000.0],
        "total_packets": [1000.0, 2000.0, 3000.0],
    })

    preprocessor = FeaturePreprocessor(apply_log1p=False, scaling_strategy="ROBUST_SCALER")
    preprocessor.fit(df_train)

    # Median and IQR must equal training statistics
    assert preprocessor.center_params["duration_ms"] == 20.0
    assert preprocessor.center_params["total_packets"] == 20.0

    # Transforming test data must NOT change fitted parameters
    preprocessor.transform(df_test)
    assert preprocessor.center_params["duration_ms"] == 20.0


def test_preprocessor_column_order_guard():
    """Verify that transforming a DataFrame with mismatched column order raises ValueError."""
    df_train = pd.DataFrame({"col_a": [1.0, 2.0], "col_b": [3.0, 4.0]})
    df_swapped = pd.DataFrame({"col_b": [3.0, 4.0], "col_a": [1.0, 2.0]})

    preprocessor = FeaturePreprocessor(scaling_strategy="STANDARD_SCALER")
    preprocessor.fit(df_train)

    with pytest.raises(ValueError, match="FEATURE_SCHEMA_MISMATCH"):
        preprocessor.transform(df_swapped)


def test_preprocessor_json_serialization_roundtrip():
    """Verify serialization to and from JSON without pickle."""
    df_train = pd.DataFrame({"feat_1": [1.0, 5.0, 10.0], "duration_ms": [100.0, 200.0, 300.0]})
    preproc = FeaturePreprocessor(apply_log1p=True, scaling_strategy="ROBUST_SCALER")
    preproc.fit(df_train)

    json_str = preproc.to_json()
    reloaded = FeaturePreprocessor.from_json(json_str)

    assert reloaded.is_fitted is True
    assert reloaded.scaling_strategy == "ROBUST_SCALER"
    assert reloaded.center_params == preproc.center_params
    assert reloaded.scale_params == preproc.scale_params


def test_sample_weight_computation():
    """Verify sample weighting profiles (NONE, CLASS_BALANCED, SESSION_CLASS_BALANCED)."""
    # 3 samples: 2 of class 0, 1 of class 1 (imbalanced 2:1)
    y_train = np.array([0, 0, 1], dtype=np.int32)
    groups = np.array(["sess_a", "sess_a", "sess_b"])

    # 1. NONE
    w_none = SampleWeightComputer("NONE").compute_weights(y_train, groups)
    assert np.all(w_none == 1.0)

    # 2. CLASS_BALANCED:
    # N=3, M=2. Class 0 count=2 -> w = 3 / (2 * 2) = 0.75. Class 1 count=1 -> w = 3 / (2 * 1) = 1.5
    w_bal = SampleWeightComputer("CLASS_BALANCED").compute_weights(y_train, groups)
    assert pytest.approx(w_bal[0], 1e-4) == 0.75
    assert pytest.approx(w_bal[1], 1e-4) == 0.75
    assert pytest.approx(w_bal[2], 1e-4) == 1.5

    # 3. SESSION_CLASS_BALANCED:
    # Sess_a has 2 flows, so its weights are divided by 2
    w_sess = SampleWeightComputer("SESSION_CLASS_BALANCED").compute_weights(y_train, groups)
    assert len(w_sess) == 3
    assert np.all(w_sess > 0)
    assert np.all(np.isfinite(w_sess))
