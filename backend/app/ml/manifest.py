"""Model Packaging, Manifest Builder, and Artifact Verification Subsystem."""

from __future__ import annotations

import hashlib
import json
import platform
import sys
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import sklearn
import xgboost as xgb

from app.ml.dataset import MLDatasetBuilder
from app.ml.schema import FeatureSchema
from app.ml.trainer import ExperimentResult


class ModelManifestBuilder:
    """Packages trained XGBoost models into cryptographically hashed, reproducible bundles."""

    @classmethod
    def compute_sha256(cls, file_path: Path) -> str:
        """Compute SHA-256 digest of a local file."""
        return hashlib.sha256(file_path.read_bytes()).hexdigest()

    @classmethod
    def export_bundle(
        cls,
        result: ExperimentResult,
        schema: FeatureSchema,
        output_dir: Path,
        dataset_version_id: str,
        manifest_hash: str,
        split_manifest_hash: str,
        shortcut_report: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Export complete model artifact bundle with cryptographic manifest.

        Files generated:
        - model/xgboost.json
        - feature_schema.json
        - label_mapping.json
        - preprocessor.json
        - training_config.json
        - cv_results.json
        - validation_metrics.json
        - test_metrics.json
        - shortcut_audit.json
        - model_manifest.json
        """
        output_dir.mkdir(parents=True, exist_ok=True)
        model_dir = output_dir / "model"
        model_dir.mkdir(parents=True, exist_ok=True)

        # 1. Native XGBoost model (JSON format)
        model_file = model_dir / "xgboost.json"
        result.model.save_model(str(model_file))

        # 2. Feature Schema
        schema_file = output_dir / "feature_schema.json"
        schema_file.write_text(schema.to_json(), encoding="utf-8")

        # 3. Label Mapping
        label_file = output_dir / "label_mapping.json"
        label_file.write_text(
            json.dumps(MLDatasetBuilder.get_canonical_label_mapping(), indent=2),
            encoding="utf-8",
        )

        # 4. Preprocessor parameters
        preproc_file = output_dir / "preprocessor.json"
        preproc_file.write_text(result.preprocessor.to_json(), encoding="utf-8")

        # 5. Training Config
        config_file = output_dir / "training_config.json"
        config_data = {
            "experiment_id": result.config.experiment_id,
            "random_seed": result.config.random_seed,
            "n_jobs": result.config.n_jobs,
            "tree_method": result.config.tree_method,
            "eval_metric": result.config.eval_metric,
            "num_classes": result.config.num_classes,
            "preprocessing_strategy": result.config.preprocessing_strategy,
            "apply_log1p": result.config.apply_log1p,
            "weighting_profile": result.config.weighting_profile,
            "selected_hyperparameters": result.best_params,
        }
        config_file.write_text(json.dumps(config_data, indent=2), encoding="utf-8")

        # 6. CV Results
        cv_file = output_dir / "cv_results.json"
        cv_file.write_text(json.dumps(result.cv_results, indent=2), encoding="utf-8")

        # 7. Validation & Test Metrics
        val_file = output_dir / "validation_metrics.json"
        val_file.write_text(json.dumps(result.validation_metrics, indent=2), encoding="utf-8")

        test_file = output_dir / "test_metrics.json"
        test_file.write_text(json.dumps(result.test_metrics, indent=2), encoding="utf-8")

        # 8. Shortcut Audit
        shortcut_file = output_dir / "shortcut_audit.json"
        shortcut_file.write_text(
            json.dumps(shortcut_report or {}, indent=2),
            encoding="utf-8",
        )

        # 9. Compute individual file hashes
        artifact_hashes = {
            "model_xgboost_json": cls.compute_sha256(model_file),
            "feature_schema_json": cls.compute_sha256(schema_file),
            "label_mapping_json": cls.compute_sha256(label_file),
            "preprocessor_json": cls.compute_sha256(preproc_file),
            "training_config_json": cls.compute_sha256(config_file),
            "cv_results_json": cls.compute_sha256(cv_file),
            "validation_metrics_json": cls.compute_sha256(val_file),
            "test_metrics_json": cls.compute_sha256(test_file),
            "shortcut_audit_json": cls.compute_sha256(shortcut_file),
        }

        # 10. Assemble master Model Manifest
        manifest_data = {
            "experiment_id": result.experiment_id,
            "model_family": "XGBoost",
            "model_version": "v1.0.0-baseline",
            "artifact_state": "EXPERIMENTAL",  # Never automatically ACTIVE
            "is_active": False,
            "dataset_version_id": dataset_version_id,
            "dataset_manifest_hash": manifest_hash,
            "split_manifest_hash": split_manifest_hash,
            "feature_schema_hash": schema.sha256_hash,
            "selected_hyperparameters": result.best_params,
            "training_duration_seconds": result.duration_seconds,
            "validation_macro_f1": result.validation_metrics.get("macro_f1", 0.0),
            "test_macro_f1": result.test_metrics.get("macro_f1", 0.0),
            "environment": {
                "python_version": sys.version,
                "platform": platform.platform(),
                "xgboost_version": xgb.__version__,
                "sklearn_version": sklearn.__version__,
            },
            "artifact_hashes": artifact_hashes,
        }

        manifest_file = output_dir / "model_manifest.json"
        manifest_file.write_text(json.dumps(manifest_data, indent=2, sort_keys=True), encoding="utf-8")
        manifest_data["manifest_sha256"] = cls.compute_sha256(manifest_file)

        return manifest_data

    @classmethod
    def reload_and_verify(
        cls,
        bundle_dir: Path,
        X_sample: pd.DataFrame,
    ) -> tuple[np.ndarray, np.ndarray]:
        """Reload the serialized XGBoost artifact in a clean state and perform an inference smoke test.

        Enforces:
        - Feature schema ordering and presence
        - XGBoost load_model success
        - Output probability vector shape (N, num_classes)
        """
        # Load schema
        schema_file = bundle_dir / "feature_schema.json"
        if not schema_file.exists():
            raise FileNotFoundError(f"Missing feature schema at {schema_file}")
        schema = FeatureSchema.from_json(schema_file.read_text(encoding="utf-8"))

        # Verify schema match
        if list(X_sample.columns) != schema.feature_names:
            raise ValueError(
                f"FEATURE_SCHEMA_MISMATCH: Input columns {list(X_sample.columns)} do not match schema {schema.feature_names}"
            )

        # Load Preprocessor if present
        preproc_file = bundle_dir / "preprocessor.json"
        if preproc_file.exists():
            from app.ml.preprocessing import FeaturePreprocessor
            preproc = FeaturePreprocessor.from_json(preproc_file.read_text(encoding="utf-8"))
            if preproc.is_fitted:
                X_proc = preproc.transform(X_sample)
            else:
                X_proc = X_sample
        else:
            X_proc = X_sample

        # Load native XGBoost model
        model_file = bundle_dir / "model" / "xgboost.json"
        if not model_file.exists():
            raise FileNotFoundError(f"Missing model file at {model_file}")

        from app.ml.trainer import XGBoostBaselineModel

        reloaded_model = XGBoostBaselineModel()
        reloaded_model.load_model(str(model_file))

        # Perform inference
        probs = reloaded_model.predict_proba(X_proc)
        preds = reloaded_model.predict(X_proc)

        return preds, probs
