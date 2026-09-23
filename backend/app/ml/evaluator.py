"""Model Evaluation Subsystem for Multiclass Encrypted ESP Flow Classification."""

from __future__ import annotations

from typing import Any

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    confusion_matrix,
    f1_score,
    precision_recall_fscore_support,
)

from app.ml.dataset import CANONICAL_CLASSES


class MLEvaluator:
    """Evaluates multiclass classifier predictions scientifically and generates metrics reports."""

    def __init__(self, class_names: list[str] | None = None) -> None:
        self.class_names = class_names or CANONICAL_CLASSES

    def evaluate(
        self,
        y_true: np.ndarray,
        y_pred: np.ndarray,
        y_prob: np.ndarray | None = None,
        groups: np.ndarray | None = None,
    ) -> dict[str, Any]:
        """Compute flow-level and session-level classification metrics.

        Args:
            y_true: Ground truth integer labels.
            y_pred: Predicted integer labels.
            y_prob: Uncalibrated predicted class probabilities (N, num_classes).
            groups: Session ID strings for session-aware evaluation.

        Returns:
            Comprehensive evaluation metrics dictionary.
        """
        n_samples = len(y_true)
        if n_samples == 0:
            return {"error": "EMPTY_EVALUATION_SET", "num_samples": 0}

        # Determine all classes present in y_true or y_pred
        present_classes = sorted(set(y_true).union(set(y_pred)))

        # Overall aggregate metrics
        macro_f1 = float(f1_score(y_true, y_pred, average="macro", zero_division=0))
        weighted_f1 = float(f1_score(y_true, y_pred, average="weighted", zero_division=0))
        accuracy = float(accuracy_score(y_true, y_pred))
        bal_acc = float(balanced_accuracy_score(y_true, y_pred))

        # Per-class metrics
        p, r, f, s = precision_recall_fscore_support(
            y_true,
            y_pred,
            labels=list(range(len(self.class_names))),
            zero_division=0,
        )

        per_class: dict[str, dict[str, Any]] = {}
        for idx, cname in enumerate(self.class_names):
            per_class[cname] = {
                "class_id": idx,
                "precision": float(p[idx]),
                "recall": float(r[idx]),
                "f1_score": float(f[idx]),
                "support": int(s[idx]),
                "present_in_evaluation": int(idx in present_classes),
            }

        # Confusion Matrix (fixed canonical class order)
        labels_order = list(range(len(self.class_names)))
        cm_raw = confusion_matrix(y_true, y_pred, labels=labels_order)
        # Normalized by row (true class support)
        cm_norm = np.zeros_like(cm_raw, dtype=np.float64)
        for i in range(len(labels_order)):
            row_sum = np.sum(cm_raw[i, :])
            if row_sum > 0:
                cm_norm[i, :] = cm_raw[i, :] / float(row_sum)

        confusion_report = {
            "class_names": self.class_names,
            "raw_matrix": cm_raw.tolist(),
            "normalized_matrix": cm_norm.round(4).tolist(),
        }

        # Session-aware evaluation if groups are supplied
        session_metrics: dict[str, Any] = {}
        if groups is not None and len(groups) == n_samples:
            unique_sessions = np.unique(groups)
            sess_true = []
            sess_pred = []
            for s_id in unique_sessions:
                mask = groups == s_id
                # True class is consistent per session by construction
                t_label = y_true[mask][0]
                if y_prob is not None and len(y_prob) == n_samples:
                    # Session prediction via mean probability
                    mean_p = np.mean(y_prob[mask], axis=0)
                    p_label = int(np.argmax(mean_p))
                else:
                    # Majority vote prediction
                    vals, cnts = np.unique(y_pred[mask], return_counts=True)
                    p_label = int(vals[np.argmax(cnts)])
                sess_true.append(t_label)
                sess_pred.append(p_label)

            sess_true_arr = np.array(sess_true, dtype=np.int32)
            sess_pred_arr = np.array(sess_pred, dtype=np.int32)
            session_metrics = {
                "total_sessions": len(unique_sessions),
                "session_macro_f1": float(f1_score(sess_true_arr, sess_pred_arr, average="macro", zero_division=0)),
                "session_accuracy": float(accuracy_score(sess_true_arr, sess_pred_arr)),
            }

        return {
            "num_samples": n_samples,
            "macro_f1": macro_f1,
            "weighted_f1": weighted_f1,
            "accuracy": accuracy,
            "balanced_accuracy": bal_acc,
            "per_class": per_class,
            "confusion_matrix": confusion_report,
            "session_metrics": session_metrics,
        }

    def evaluate_slices(
        self,
        metadata_df: pd.DataFrame,
        y_true: np.ndarray,
        y_pred: np.ndarray,
    ) -> dict[str, Any]:
        """Evaluate performance stratified across IPsec configuration dimensions."""
        slices_report: dict[str, Any] = {}
        dimensions = ["mode", "ip_version", "is_nat_t", "network_impairment_profile"]

        for dim in dimensions:
            if dim not in metadata_df.columns:
                slices_report[dim] = {"status": "BLOCKED_DIMENSION_NOT_IN_METADATA"}
                continue

            unique_vals = metadata_df[dim].dropna().unique()
            if len(unique_vals) <= 1:
                slices_report[dim] = {
                    "status": "INSUFFICIENT_COVERAGE",
                    "values_observed": [str(v) for v in unique_vals],
                }
                continue

            slices_report[dim] = {"status": "EVALUATED", "categories": {}}
            for val in unique_vals:
                mask = (metadata_df[dim] == val).values
                if not np.any(mask):
                    continue
                sub_true = y_true[mask]
                sub_pred = y_pred[mask]
                slices_report[dim]["categories"][str(val)] = {
                    "count": int(np.sum(mask)),
                    "macro_f1": float(f1_score(sub_true, sub_pred, average="macro", zero_division=0)),
                    "accuracy": float(accuracy_score(sub_true, sub_pred)),
                }

        return slices_report
