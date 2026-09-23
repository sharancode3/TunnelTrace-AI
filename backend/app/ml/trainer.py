"""XGBoost Baseline Classifier Trainer & Experiment Runner."""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.dummy import DummyClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import GroupKFold

from app.ml.auditor import LeakageAuditor
from app.ml.dataset import MLDatasetPartition
from app.ml.evaluator import MLEvaluator
from app.ml.preprocessing import FeaturePreprocessor
from app.ml.weighting import SampleWeightComputer


class XGBoostBaselineModel:
    """Wrapper managing XGBoost training, contiguous class mapping, and canonical vector projection."""

    def __init__(
        self,
        num_classes: int = 7,
        **xgb_kwargs: Any,
    ) -> None:
        self.total_num_classes = num_classes
        self.xgb_kwargs = xgb_kwargs
        self.classes_in_training_: list[int] = []
        self.inner_model: xgb.XGBClassifier | None = None

    @property
    def model(self) -> xgb.XGBClassifier | None:
        """Alias for inner_model."""
        return self.inner_model

    def fit(
        self,
        X: pd.DataFrame,
        y: np.ndarray,
        sample_weight: np.ndarray | None = None,
    ) -> XGBoostBaselineModel:
        unique_classes = sorted(np.unique(y))
        self.classes_in_training_ = [int(c) for c in unique_classes]
        k = len(unique_classes)

        label_to_mapped = {c: i for i, c in enumerate(unique_classes)}
        y_mapped = np.array([label_to_mapped[val] for val in y], dtype=np.int32)

        if k <= 1:
            self.inner_model = None
            return self

        # Objective: multi:softprob for multiclass (or binary:logistic for 2 classes)
        objective = "binary:logistic" if k == 2 else "multi:softprob"
        self.inner_model = xgb.XGBClassifier(
            objective=objective,
            num_class=k if k > 2 else None,
            **self.xgb_kwargs,
        )
        self.inner_model.fit(X, y_mapped, sample_weight=sample_weight)
        return self

    def predict(self, X: pd.DataFrame) -> np.ndarray:
        if not self.classes_in_training_:
            return np.zeros(len(X), dtype=np.int32)
        if self.inner_model is None or len(self.classes_in_training_) == 1:
            return np.full(len(X), self.classes_in_training_[0], dtype=np.int32)

        mapped_preds = self.inner_model.predict(X)
        return np.array([self.classes_in_training_[int(m)] for m in mapped_preds], dtype=np.int32)

    def predict_proba(self, X: pd.DataFrame) -> np.ndarray:
        n = len(X)
        probs = np.zeros((n, self.total_num_classes), dtype=np.float64)
        if not self.classes_in_training_:
            return probs

        if self.inner_model is None or len(self.classes_in_training_) == 1:
            only_c = self.classes_in_training_[0]
            if only_c < self.total_num_classes:
                probs[:, only_c] = 1.0
            return probs

        raw_probs = self.inner_model.predict_proba(X)
        if len(self.classes_in_training_) == 2:
            c0, c1 = self.classes_in_training_
            probs[:, c0] = raw_probs[:, 0]
            probs[:, c1] = raw_probs[:, 1]
        else:
            for mapped_idx, orig_c in enumerate(self.classes_in_training_):
                if orig_c < self.total_num_classes:
                    probs[:, orig_c] = raw_probs[:, mapped_idx]

        return probs

    def save_model(self, file_path: str) -> None:
        if self.inner_model is not None:
            self.inner_model.save_model(file_path)
        else:
            # Fallback dummy file
            dummy = xgb.XGBClassifier()
            dummy.save_model(file_path)

        meta_path = Path(file_path).with_suffix(".meta.json")
        meta_data = {
            "total_num_classes": self.total_num_classes,
            "classes_in_training": self.classes_in_training_,
            "xgb_kwargs": {k: v for k, v in self.xgb_kwargs.items() if isinstance(v, (int, float, str, bool))},
        }
        meta_path.write_text(json.dumps(meta_data, indent=2), encoding="utf-8")

    def load_model(self, file_path: str) -> None:
        meta_path = Path(file_path).with_suffix(".meta.json")
        if meta_path.exists():
            meta_data = json.loads(meta_path.read_text(encoding="utf-8"))
            self.total_num_classes = meta_data.get("total_num_classes", 7)
            self.classes_in_training_ = meta_data.get("classes_in_training", [])
            self.xgb_kwargs = meta_data.get("xgb_kwargs", {})

        k = len(self.classes_in_training_)
        if k > 1 and Path(file_path).exists():
            self.inner_model = xgb.XGBClassifier()
            self.inner_model.load_model(file_path)
        else:
            self.inner_model = None


@dataclass
class TrainingConfig:
    """Hyperparameter and execution configuration for XGBoost baseline training."""

    experiment_id: str = field(default_factory=lambda: f"exp_{uuid.uuid4().hex[:12]}")
    random_seed: int = 42
    n_jobs: int = 4
    tree_method: str = "hist"
    eval_metric: str = "mlogloss"
    num_classes: int = 7
    # Candidate hyperparameter grid for tuning
    param_grid: list[dict[str, Any]] = field(default_factory=lambda: [
        {"max_depth": 4, "learning_rate": 0.05, "n_estimators": 100, "subsample": 0.8, "colsample_bytree": 0.8},
        {"max_depth": 6, "learning_rate": 0.05, "n_estimators": 100, "subsample": 0.8, "colsample_bytree": 0.8},
        {"max_depth": 4, "learning_rate": 0.1, "n_estimators": 50, "subsample": 0.9, "colsample_bytree": 1.0},
    ])
    preprocessing_strategy: str = "NONE"  # NONE, ROBUST_SCALER, STANDARD_SCALER
    apply_log1p: bool = True
    weighting_profile: str = "NONE"  # NONE, CLASS_BALANCED, SESSION_CLASS_BALANCED
    cv_folds: int = 3


@dataclass
class ExperimentResult:
    """Complete experimental execution result holding candidate scores, validation, and test metrics."""

    experiment_id: str
    status: str  # COMPLETED, FAILED, EXPERIMENTAL_DATA_INSUFFICIENT
    best_params: dict[str, Any]
    cv_results: list[dict[str, Any]]
    validation_metrics: dict[str, Any]
    test_metrics: dict[str, Any]
    comparator_metrics: dict[str, Any]
    shuffled_control_metrics: dict[str, Any]
    duration_seconds: float
    model: XGBoostBaselineModel
    preprocessor: FeaturePreprocessor
    config: TrainingConfig


class XGBoostTrainer:
    """Manages the full lifecycle of training, tuning, and evaluating the baseline classifier."""

    def __init__(self, config: TrainingConfig | None = None) -> None:
        self.config = config or TrainingConfig()
        self.evaluator = MLEvaluator()

    def train_experiment(
        self,
        train_partition: MLDatasetPartition,
        val_partition: MLDatasetPartition,
        test_partition: MLDatasetPartition | None = None,
    ) -> ExperimentResult:
        """Execute the end-to-end Stage 6 training workflow.

        Lifecycle:
        1. Audit forbidden feature columns.
        2. Fit preprocessor strictly on TRAIN.
        3. Compute sample weights strictly on TRAIN.
        4. Run grouped cross-validation on TRAIN across parameter candidates.
        5. Select best candidate based on Validation Macro-F1.
        6. Train sanity comparators (Dummy, Logistic Regression) on TRAIN.
        7. Train negative-control model on shuffled TRAIN labels.
        8. Evaluate best model on held-out TEST partition (once).
        """
        start_time = time.perf_counter()

        X_tr = train_partition.X
        y_tr = train_partition.y
        groups_tr = train_partition.groups

        X_val = val_partition.X
        y_val = val_partition.y
        groups_val = val_partition.groups

        # Step 1: Leakage Audit
        LeakageAuditor.audit_forbidden_columns(list(X_tr.columns))

        # Check data sufficiency
        unique_classes_tr = np.unique(y_tr)
        if len(unique_classes_tr) < self.config.num_classes:
            status = "EXPERIMENTAL_DATA_INSUFFICIENT"
        else:
            status = "COMPLETED"

        # Step 2: Fit preprocessor strictly on TRAIN
        preprocessor = FeaturePreprocessor(
            apply_log1p=self.config.apply_log1p,
            scaling_strategy=self.config.preprocessing_strategy,
        )
        X_tr_proc = preprocessor.fit_transform(X_tr)
        X_val_proc = preprocessor.transform(X_val)

        # Step 3: Compute sample weights strictly on TRAIN
        weight_computer = SampleWeightComputer(self.config.weighting_profile)
        sample_weights_tr = weight_computer.compute_weights(y_tr, groups_tr)

        # Step 4: Grouped Cross-Validation on TRAIN
        n_groups = len(np.unique(groups_tr))
        n_splits = min(self.config.cv_folds, max(2, n_groups)) if n_groups >= 2 else 2

        cv_results: list[dict[str, Any]] = []
        best_candidate: dict[str, Any] = self.config.param_grid[0]
        best_val_macro_f1 = -1.0
        best_model: XGBoostBaselineModel | None = None

        for candidate_params in self.config.param_grid:
            fold_macro_f1s = []
            if n_groups >= 2:
                gkf = GroupKFold(n_splits=n_splits)
                for tr_idx, h_idx in gkf.split(X_tr_proc, y_tr, groups_tr):
                    x_f_tr, y_f_tr = X_tr_proc.iloc[tr_idx], y_tr[tr_idx]
                    x_f_h, y_f_h = X_tr_proc.iloc[h_idx], y_tr[h_idx]
                    w_f_tr = sample_weights_tr[tr_idx]

                    # If fold has < 2 unique classes, skip fold evaluation
                    if len(np.unique(y_f_tr)) < 2:
                        continue

                    fold_clf = XGBoostBaselineModel(
                        num_classes=self.config.num_classes,
                        tree_method=self.config.tree_method,
                        eval_metric=self.config.eval_metric,
                        random_state=self.config.random_seed,
                        n_jobs=self.config.n_jobs,
                        **candidate_params,
                    )
                    fold_clf.fit(x_f_tr, y_f_tr, sample_weight=w_f_tr)
                    preds_h = fold_clf.predict(x_f_h)
                    fold_eval = self.evaluator.evaluate(y_f_h, preds_h)
                    fold_macro_f1s.append(fold_eval["macro_f1"])

            mean_cv_macro_f1 = float(np.mean(fold_macro_f1s)) if fold_macro_f1s else 0.0

            # Fit on full TRAIN partition to evaluate on Validation partition
            candidate_model = XGBoostBaselineModel(
                num_classes=self.config.num_classes,
                tree_method=self.config.tree_method,
                eval_metric=self.config.eval_metric,
                random_state=self.config.random_seed,
                n_jobs=self.config.n_jobs,
                **candidate_params,
            )
            candidate_model.fit(X_tr_proc, y_tr, sample_weight=sample_weights_tr)

            # Evaluate candidate on Validation partition (decision criterion)
            val_preds = candidate_model.predict(X_val_proc)
            val_probs = candidate_model.predict_proba(X_val_proc)
            candidate_val_eval = self.evaluator.evaluate(y_val, val_preds, val_probs, groups_val)

            cv_results.append({
                "params": candidate_params,
                "cv_macro_f1": mean_cv_macro_f1,
                "val_macro_f1": candidate_val_eval["macro_f1"],
                "val_accuracy": candidate_val_eval["accuracy"],
            })

            if candidate_val_eval["macro_f1"] > best_val_macro_f1:
                best_val_macro_f1 = candidate_val_eval["macro_f1"]
                best_candidate = candidate_params
                best_model = candidate_model

        if best_model is None:
            best_model = XGBoostBaselineModel(
                num_classes=self.config.num_classes,
                tree_method=self.config.tree_method,
                eval_metric=self.config.eval_metric,
                random_state=self.config.random_seed,
                n_jobs=self.config.n_jobs,
                **self.config.param_grid[0],
            )
            best_model.fit(X_tr_proc, y_tr, sample_weight=sample_weights_tr)

        # Final Validation metrics using best selected model
        val_preds = best_model.predict(X_val_proc)
        val_probs = best_model.predict_proba(X_val_proc)
        val_metrics = self.evaluator.evaluate(y_val, val_preds, val_probs, groups_val)

        # Step 6: Simple Baseline Comparators on same TRAIN/VAL
        comparator_metrics: dict[str, Any] = {}
        # 6a. Dummy Classifier (majority class)
        dummy = DummyClassifier(strategy="most_frequent")
        dummy.fit(X_tr_proc, y_tr)
        dummy_preds = dummy.predict(X_val_proc)
        comparator_metrics["dummy_majority"] = self.evaluator.evaluate(y_val, dummy_preds)

        # 6b. Multinomial Logistic Regression
        try:
            lr = LogisticRegression(max_iter=200, random_state=self.config.random_seed)
            lr.fit(X_tr_proc, y_tr)
            lr_preds = lr.predict(X_val_proc)
            comparator_metrics["logistic_regression"] = self.evaluator.evaluate(y_val, lr_preds)
        except Exception as e:
            comparator_metrics["logistic_regression"] = {"status": "FAILED", "error": str(e)}

        # Step 7: Label-Shuffle Negative Control
        shuffled_y_tr = np.random.RandomState(self.config.random_seed).permutation(y_tr)
        ctrl_model = XGBoostBaselineModel(
            num_classes=self.config.num_classes,
            tree_method=self.config.tree_method,
            eval_metric=self.config.eval_metric,
            random_state=self.config.random_seed,
            n_jobs=self.config.n_jobs,
            **best_candidate,
        )
        ctrl_model.fit(X_tr_proc, shuffled_y_tr)
        ctrl_preds = ctrl_model.predict(X_val_proc)
        shuffled_control_metrics = self.evaluator.evaluate(y_val, ctrl_preds)

        # Step 8: Final Held-Out TEST Evaluation (Touch once after candidate frozen)
        test_metrics: dict[str, Any] = {}
        if test_partition is not None and test_partition.num_rows > 0:
            X_test_proc = preprocessor.transform(test_partition.X)
            test_preds = best_model.predict(X_test_proc)
            test_probs = best_model.predict_proba(X_test_proc)
            test_metrics = self.evaluator.evaluate(
                test_partition.y,
                test_preds,
                test_probs,
                test_partition.groups,
            )

        duration = time.perf_counter() - start_time

        return ExperimentResult(
            experiment_id=self.config.experiment_id,
            status=status,
            best_params=best_candidate,
            cv_results=cv_results,
            validation_metrics=val_metrics,
            test_metrics=test_metrics,
            comparator_metrics=comparator_metrics,
            shuffled_control_metrics=shuffled_control_metrics,
            duration_seconds=duration,
            model=best_model,
            preprocessor=preprocessor,
            config=self.config,
        )
