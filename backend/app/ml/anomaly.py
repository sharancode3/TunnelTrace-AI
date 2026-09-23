"""Behavioral Anomaly Detection Subsystem using Safe JSON-Serialized Isolation Forest."""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from app.ml.auditor import LeakageAuditor


@dataclass(frozen=True)
class AnomalyFeatureSchema:
    """Versioned schema defining statistical behavioral features for anomaly detection.

    Uses leakage-safe flow dynamics only. Excludes all IP addresses, ports, SPIs,
    keys, scenario names, and security policy outcomes.
    """

    version: str = "1.0.0"
    features: list[str] = field(
        default_factory=lambda: [
            "f15_total_packets",
            "f16_total_bytes",
            "f17_flow_duration_ms",
            "f18_packet_rate_pps",
            "f19_byte_rate_bps",
            "f09_mean_iat",
            "f10_std_iat",
            "f01_mean_fwd_pkt_len",
            "f05_mean_bwd_pkt_len",
            "f13_fwd_bwd_pkt_ratio",
        ]
    )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, indent=2)

    def schema_hash(self) -> str:
        canonical_bytes = json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(canonical_bytes).hexdigest()

    @classmethod
    def canonical_schema(cls) -> AnomalyFeatureSchema:
        return cls()


@dataclass
class AnomalyDecision:
    """Structured decision output from the behavioral anomaly detector."""

    is_anomaly: bool
    status: str  # STATISTICAL_BEHAVIORAL_ANOMALY, NORMAL_BEHAVIOR
    anomaly_score: float  # Higher indicates more anomalous [0.0..1.0]
    operational_threshold: float
    feature_deviations: dict[str, float] = field(default_factory=dict)  # Normalized deviations from benign mean

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class IsolationForestAnomalyDetector:
    """Safe, non-pickle Isolation Forest for IPsec encrypted behavioral anomaly detection.

    CRITICAL RULES:
        - Independent of closed-set application classification.
        - Independent of OOD gating.
        - NEVER modifies application class label.
        - NEVER outputs 'attack', 'zero-day', 'intrusion', or 'malware'.
        - Serializes tree parameters safely to pure JSON (zero pickle vulnerabilities).
    """

    def __init__(
        self,
        schema: AnomalyFeatureSchema | None = None,
        operational_threshold: float = 0.60,
    ) -> None:
        self.schema = schema or AnomalyFeatureSchema.canonical_schema()
        self.operational_threshold = operational_threshold
        self.trees_data: list[dict[str, Any]] = []
        self.n_samples_fit: int = 256
        self.feature_means: dict[str, float] = {}
        self.feature_stds: dict[str, float] = {}

    def _c_factor(self, n: float) -> float:
        """Average path length of unsuccessful search in Binary Search Tree."""
        if n <= 1:
            return 0.0
        if n == 2:
            return 1.0
        euler_gamma = 0.57721566490153286060
        return float(2.0 * (math.log(n - 1.0) + euler_gamma) - (2.0 * (n - 1.0) / n))

    def fit(
        self,
        X_benign_train: pd.DataFrame | np.ndarray,
        n_estimators: int = 50,
        random_state: int = 42,
    ) -> None:
        """Fit Isolation Forest on benign TRAIN flows and serialize parameters to JSON-safe structures."""
        if isinstance(X_benign_train, pd.DataFrame):
            # Select and order approved features
            X_df = X_benign_train[self.schema.features].copy()
            X_mat = X_df.to_numpy(dtype=np.float64)
        else:
            X_mat = np.asarray(X_benign_train, dtype=np.float64)

        # Audit features
        LeakageAuditor.audit_forbidden_columns(self.schema.features)

        self.n_samples_fit = len(X_mat)

        # Compute baseline feature statistics for deviation diagnostics
        for idx, f in enumerate(self.schema.features):
            self.feature_means[f] = float(np.mean(X_mat[:, idx]))
            std = float(np.std(X_mat[:, idx]))
            self.feature_stds[f] = std if std > 1e-6 else 1.0

        # Fit scikit-learn IsolationForest
        clf = IsolationForest(
            n_estimators=n_estimators,
            max_samples="auto",
            contamination="auto",
            random_state=random_state,
        )
        clf.fit(X_mat)

        # Extract tree structures to pure JSON-serializable representation
        self.trees_data = []
        for estimator in clf.estimators_:
            t = estimator.tree_
            tree_dict = {
                "children_left": t.children_left.tolist(),
                "children_right": t.children_right.tolist(),
                "feature": t.feature.tolist(),
                "threshold": [float(val) for val in t.threshold],
                "n_node_samples": t.n_node_samples.tolist(),
            }
            self.trees_data.append(tree_dict)

    def tune_threshold(
        self,
        X_benign_val: pd.DataFrame | np.ndarray,
        target_fpr: float = 0.05,
    ) -> float:
        """Empirically calibrate operational anomaly score threshold on clean benign validation data."""
        scores = self.score_samples(X_benign_val)
        # Threshold at (100 - 100 * target_fpr) percentile to bound FPR
        threshold = float(np.percentile(scores, (1.0 - target_fpr) * 100.0))
        self.operational_threshold = float(round(threshold, 4))
        return self.operational_threshold

    def _path_length_single_tree(self, x: np.ndarray, tree: dict[str, Any]) -> float:
        """Traverse a single tree and compute path length h(x)."""
        node = 0
        depth = 0.0
        c_left = tree["children_left"]
        c_right = tree["children_right"]
        feat = tree["feature"]
        thresh = tree["threshold"]
        n_samples = tree["n_node_samples"]

        while c_left[node] != -1:  # Not a leaf
            f_idx = feat[node]
            val = x[f_idx]
            if val <= thresh[node]:
                node = c_left[node]
            else:
                node = c_right[node]
            depth += 1.0

        # Leaf node adjustment
        return depth + self._c_factor(float(n_samples[node]))

    def score_samples(self, X: pd.DataFrame | np.ndarray) -> np.ndarray:
        """Compute anomaly score s(x) for each sample. Higher score = more anomalous [0.0..1.0]."""
        if isinstance(X, pd.DataFrame):
            X_mat = X[self.schema.features].to_numpy(dtype=np.float64)
        else:
            X_mat = np.asarray(X, dtype=np.float64)

        if not self.trees_data:
            return np.full(len(X_mat), 0.5)

        c_n = self._c_factor(float(self.n_samples_fit))
        if c_n <= 0.0:
            c_n = 1.0

        scores = []
        for i in range(len(X_mat)):
            x = X_mat[i]
            lengths = [self._path_length_single_tree(x, t) for t in self.trees_data]
            avg_length = float(np.mean(lengths))
            score = 2.0 ** (-avg_length / c_n)
            scores.append(float(score))

        return np.array(scores, dtype=np.float64)

    def evaluate_flow(self, feature_row: pd.Series | dict[str, float] | np.ndarray) -> AnomalyDecision:
        """Evaluate a single flow for statistical behavioral anomaly."""
        if isinstance(feature_row, dict):
            vec = np.array([feature_row.get(f, 0.0) for f in self.schema.features], dtype=np.float64)
        elif isinstance(feature_row, pd.Series):
            vec = np.array([feature_row.get(f, 0.0) for f in self.schema.features], dtype=np.float64)
        else:
            vec = np.asarray(feature_row, dtype=np.float64)

        score = float(self.score_samples(vec.reshape(1, -1))[0])
        is_anomaly = score >= self.operational_threshold

        status = "STATISTICAL_BEHAVIORAL_ANOMALY" if is_anomaly else "NORMAL_BEHAVIOR"

        # Compute feature z-score deviations for diagnostic context
        deviations = {}
        for idx, f in enumerate(self.schema.features):
            m = self.feature_means.get(f, 0.0)
            s = self.feature_stds.get(f, 1.0)
            deviations[f] = float(round((vec[idx] - m) / s, 3))

        return AnomalyDecision(
            is_anomaly=is_anomaly,
            status=status,
            anomaly_score=float(round(score, 4)),
            operational_threshold=self.operational_threshold,
            feature_deviations=deviations,
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert fitted detector parameters to pure JSON dictionary."""
        return {
            "version": "1.0.0",
            "schema_hash": self.schema.schema_hash(),
            "operational_threshold": self.operational_threshold,
            "n_samples_fit": self.n_samples_fit,
            "feature_means": self.feature_means,
            "feature_stds": self.feature_stds,
            "num_trees": len(self.trees_data),
            "trees_data": self.trees_data,
        }

    def save_json(self, output_path: Path) -> Path:
        """Serialize fitted model to pure JSON file without using pickle."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)
        return output_path

    @classmethod
    def load_json(cls, input_path: Path, schema: AnomalyFeatureSchema | None = None) -> IsolationForestAnomalyDetector:
        """Load fitted detector from pure JSON file safely without pickle."""
        with open(input_path, encoding="utf-8") as f:
            data = json.load(f)

        det = cls(
            schema=schema,
            operational_threshold=float(data["operational_threshold"]),
        )
        det.n_samples_fit = int(data.get("n_samples_fit", 256))
        det.feature_means = {k: float(v) for k, v in data.get("feature_means", {}).items()}
        det.feature_stds = {k: float(v) for k, v in data.get("feature_stds", {}).items()}
        det.trees_data = data.get("trees_data", [])
        return det
