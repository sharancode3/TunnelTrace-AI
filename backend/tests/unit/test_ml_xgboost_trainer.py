"""Unit tests for XGBoost baseline training, comparators, negative control, and serialization."""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from app.ml.dataset import MLDatasetPartition
from app.ml.manifest import ModelManifestBuilder
from app.ml.schema import FeatureSchema
from app.ml.trainer import TrainingConfig, XGBoostTrainer


@pytest.fixture
def synthetic_partitions(tmp_path: Path):
    """Generate deterministic, synthetic train, val, and test partitions with 3 classes."""
    schema = FeatureSchema()
    feature_cols = schema.feature_names

    # 3 classes, 6 sessions (2 sessions per class)
    # Class 0: values centered at 10.0
    # Class 1: values centered at 50.0
    # Class 2: values centered at 100.0

    def make_partition(split_name: str, n_per_class: int):
        rows = []
        labels = []
        groups = []
        meta = []
        for c in range(3):
            base_val = 10.0 if c == 0 else (50.0 if c == 1 else 100.0)
            for i in range(n_per_class):
                sess_id = f"sess_{split_name}_{c}_{i % 2}"
                row_dict = {col: base_val + float(i) * 0.1 for col in feature_cols}
                rows.append(row_dict)
                labels.append(c)
                groups.append(sess_id)
                meta.append({"session_id": sess_id, "workload_class": f"Class_{c}"})

        df_X = pd.DataFrame(rows)[feature_cols]
        y_arr = np.array(labels, dtype=np.int32)
        groups_arr = np.array(groups, dtype=object)
        meta_df = pd.DataFrame(meta)

        return MLDatasetPartition(
            split_type=split_name,
            X=df_X,
            y=y_arr,
            groups=groups_arr,
            metadata=meta_df,
            dataset_version_id="ver_synth_01",
            manifest_hash="hash_manifest_01",
            split_manifest_hash="hash_split_01",
            feature_schema_hash=schema.sha256_hash,
        )

    train_p = make_partition("TRAIN", 10)  # 30 rows
    val_p = make_partition("VAL", 4)  # 12 rows
    test_p = make_partition("TEST", 4)  # 12 rows

    return train_p, val_p, test_p


def test_xgboost_training_and_comparators(synthetic_partitions, tmp_path: Path):
    """Verify XGBoost training, CV candidates, comparators, negative control, and held-out test."""
    train_p, val_p, test_p = synthetic_partitions

    config = TrainingConfig(
        experiment_id="exp_test_01",
        num_classes=3,
        cv_folds=2,
        param_grid=[
            {"max_depth": 2, "learning_rate": 0.1, "n_estimators": 20},
            {"max_depth": 4, "learning_rate": 0.1, "n_estimators": 20},
        ],
    )
    trainer = XGBoostTrainer(config)
    result = trainer.train_experiment(train_p, val_p, test_p)

    assert result.status == "COMPLETED"
    assert len(result.cv_results) == 2
    assert "macro_f1" in result.validation_metrics
    assert result.validation_metrics["macro_f1"] > 0.80  # Linearly separable synthetic data

    # Verify comparators exist
    assert "dummy_majority" in result.comparator_metrics
    assert "logistic_regression" in result.comparator_metrics

    # Verify shuffled negative control
    assert "macro_f1" in result.shuffled_control_metrics
    # XGBoost on random shuffled labels should have significantly lower Macro-F1
    assert result.shuffled_control_metrics["macro_f1"] < result.validation_metrics["macro_f1"]

    # Verify held-out test was evaluated
    assert "macro_f1" in result.test_metrics
    assert result.test_metrics["macro_f1"] > 0.80

    # Test artifact bundle export
    bundle_dir = tmp_path / "model_bundle"
    manifest = ModelManifestBuilder.export_bundle(
        result=result,
        schema=FeatureSchema(),
        output_dir=bundle_dir,
        dataset_version_id="ver_synth_01",
        manifest_hash="hash_manifest_01",
        split_manifest_hash="hash_split_01",
    )

    assert manifest["artifact_state"] == "EXPERIMENTAL"
    assert manifest["is_active"] is False
    assert (bundle_dir / "model" / "xgboost.json").exists()
    assert (bundle_dir / "feature_schema.json").exists()
    assert (bundle_dir / "model_manifest.json").exists()

    # Test reload and verify
    preds, probs = ModelManifestBuilder.reload_and_verify(bundle_dir, test_p.X)
    assert len(preds) == len(test_p.X)
    assert probs.shape == (len(test_p.X), 3)

    # Test schema mismatch guard on reload
    df_broken = test_p.X.drop(columns=[test_p.X.columns[0]])
    with pytest.raises(ValueError, match="FEATURE_SCHEMA_MISMATCH"):
        ModelManifestBuilder.reload_and_verify(bundle_dir, df_broken)
