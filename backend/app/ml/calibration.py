"""Probability Calibration Subsystem for Statistically Defensible Confidence."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Any

import numpy as np
from scipy.optimize import minimize
from sklearn.metrics import log_loss

from app.ml.dataset import CANONICAL_CLASSES


@dataclass
class CalibrationMetrics:
    """Diagnostic evaluation metrics comparing pre- and post-calibration distributions."""

    nll_before: float
    nll_after: float
    brier_before: float
    brier_after: float
    ece_before: float
    ece_after: float
    num_bins: int
    reliability_diagram: dict[str, list[float]]  # bin_centers, acc_before, acc_after, conf_before, conf_after

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CalibrationConfig:
    """Persisted configuration and parameters for probability calibrator."""

    method: str = "TEMPERATURE_SCALING"  # TEMPERATURE_SCALING, IDENTITY
    temperature: float = 1.0  # Scalar T > 0
    num_classes: int = 7
    classes: list[str] = field(default_factory=lambda: list(CANONICAL_CLASSES))
    fit_metrics: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, indent=2)

    def config_hash(self) -> str:
        canonical_bytes = json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(canonical_bytes).hexdigest()

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CalibrationConfig:
        valid_keys = cls.__dataclass_fields__.keys()
        filtered = {k: v for k, v in data.items() if k in valid_keys}
        return cls(**filtered)


class ProbabilityCalibrator:
    """Calibrates multiclass predicted probability vectors to ensure honest confidence intervals.

    Supports:
        - Temperature Scaling: Optimizes scalar T > 0 minimizing NLL on calibration data.
        - Calibration Evaluation: Computes NLL, Brier score, ECE, and reliability diagrams.
    """

    def __init__(self, config: CalibrationConfig | None = None) -> None:
        self.config = config or CalibrationConfig()

    def calibrate(self, probs: np.ndarray) -> np.ndarray:
        """Apply temperature calibration to an (N, C) probability matrix.

        Computes:
            z = log(p + epsilon)
            p_calibrated = softmax(z / T)
        """
        if probs.ndim != 2 or probs.shape[1] != self.config.num_classes:
            raise ValueError(f"Expected shape (N, {self.config.num_classes}), got {probs.shape}")

        T = self.config.temperature
        if T <= 0.0:
            raise ValueError(f"Temperature T must be strictly positive, got {T}")

        if abs(T - 1.0) < 1e-6:
            return probs

        # Convert probabilities to pseudo-logits
        eps = 1e-12
        pseudo_logits = np.log(np.clip(probs, eps, 1.0))
        scaled_logits = pseudo_logits / T

        # Numerically stable softmax
        exp_scaled = np.exp(scaled_logits - np.max(scaled_logits, axis=1, keepdims=True))
        calibrated_probs = exp_scaled / np.sum(exp_scaled, axis=1, keepdims=True)
        return calibrated_probs

    def fit_temperature(
        self,
        probs_cal: np.ndarray,
        y_cal: np.ndarray,
        num_bins: int = 10,
    ) -> CalibrationMetrics:
        """Fit optimal scalar temperature T on calibration split (VAL_CAL).

        Minimizes cross-entropy (NLL) with respect to T > 0.
        """
        if len(probs_cal) != len(y_cal):
            raise ValueError("Lengths of probs_cal and y_cal must match.")

        eps = 1e-12
        pseudo_logits = np.log(np.clip(probs_cal, eps, 1.0))
        y_int = y_cal.astype(int)

        def loss_fn(T_arr: np.ndarray) -> float:
            T = T_arr[0]
            if T <= 0.01:
                return 1e6
            scaled = pseudo_logits / T
            # Log-sum-exp
            max_s = np.max(scaled, axis=1, keepdims=True)
            lse = max_s.squeeze(1) + np.log(np.sum(np.exp(scaled - max_s), axis=1))
            # Gather target logits
            target_logits = scaled[np.arange(len(y_int)), y_int]
            nll = np.mean(lse - target_logits)
            return float(nll)

        # Optimize T starting from 1.0
        res = minimize(
            loss_fn,
            x0=np.array([1.0]),
            method="L-BFGS-B",
            bounds=[(0.05, 10.0)],
        )

        best_T = float(res.x[0])
        self.config.temperature = best_T
        self.config.method = "TEMPERATURE_SCALING"

        # Evaluate metrics before vs after
        probs_before = probs_cal
        probs_after = self.calibrate(probs_cal)

        metrics = self.evaluate_calibration(probs_before, probs_after, y_cal, num_bins=num_bins)
        self.config.fit_metrics = metrics.to_dict()
        return metrics

    def compute_ece(
        self,
        probs: np.ndarray,
        y_true: np.ndarray,
        num_bins: int = 10,
    ) -> tuple[float, dict[str, list[float]]]:
        """Compute Expected Calibration Error (ECE) and reliability bin statistics."""
        confidences = np.max(probs, axis=1)
        predictions = np.argmax(probs, axis=1)
        accuracies = (predictions == y_true).astype(float)

        bin_edges = np.linspace(0.0, 1.0, num_bins + 1)
        bin_centers = []
        bin_accs = []
        bin_confs = []
        bin_counts = []
        ece = 0.0
        total_samples = len(y_true)

        for i in range(num_bins):
            lo, hi = bin_edges[i], bin_edges[i + 1]
            if i == num_bins - 1:
                in_bin = (confidences >= lo) & (confidences <= hi)
            else:
                in_bin = (confidences >= lo) & (confidences < hi)

            bin_size = np.sum(in_bin)
            bin_centers.append(float((lo + hi) / 2.0))
            if bin_size > 0:
                acc = float(np.mean(accuracies[in_bin]))
                conf = float(np.mean(confidences[in_bin]))
                ece += (bin_size / total_samples) * abs(acc - conf)
                bin_accs.append(acc)
                bin_confs.append(conf)
            else:
                bin_accs.append(0.0)
                bin_confs.append(float((lo + hi) / 2.0))
            bin_counts.append(int(bin_size))

        diagram_data = {
            "bin_centers": bin_centers,
            "accuracies": bin_accs,
            "confidences": bin_confs,
            "counts": bin_counts,
        }
        return float(ece), diagram_data

    def evaluate_calibration(
        self,
        probs_before: np.ndarray,
        probs_after: np.ndarray,
        y_true: np.ndarray,
        num_bins: int = 10,
    ) -> CalibrationMetrics:
        """Calculate comprehensive calibration metrics before and after calibration."""
        C = self.config.num_classes
        y_int = y_true.astype(int)

        # Multi-class Brier score = sum across classes of mean((p_c - y_c)^2)
        y_one_hot = np.zeros((len(y_int), C), dtype=float)
        y_one_hot[np.arange(len(y_int)), y_int] = 1.0

        brier_before = float(np.mean(np.sum((probs_before - y_one_hot) ** 2, axis=1)))
        brier_after = float(np.mean(np.sum((probs_after - y_one_hot) ** 2, axis=1)))

        # NLL
        eps = 1e-15
        p_b_clip = np.clip(probs_before, eps, 1.0 - eps)
        p_b_clip = p_b_clip / p_b_clip.sum(axis=1, keepdims=True)
        p_a_clip = np.clip(probs_after, eps, 1.0 - eps)
        p_a_clip = p_a_clip / p_a_clip.sum(axis=1, keepdims=True)

        try:
            nll_before = float(log_loss(y_int, p_b_clip, labels=list(range(C))))
        except Exception:
            nll_before = float("inf")

        try:
            nll_after = float(log_loss(y_int, p_a_clip, labels=list(range(C))))
        except Exception:
            nll_after = float("inf")

        ece_before, diag_before = self.compute_ece(probs_before, y_int, num_bins=num_bins)
        ece_after, diag_after = self.compute_ece(probs_after, y_int, num_bins=num_bins)

        reliability_diagram = {
            "bin_centers": diag_before["bin_centers"],
            "acc_before": diag_before["accuracies"],
            "acc_after": diag_after["accuracies"],
            "conf_before": diag_before["confidences"],
            "conf_after": diag_after["confidences"],
            "counts": diag_after["counts"],
        }

        return CalibrationMetrics(
            nll_before=nll_before,
            nll_after=nll_after,
            brier_before=brier_before,
            brier_after=brier_after,
            ece_before=ece_before,
            ece_after=ece_after,
            num_bins=num_bins,
            reliability_diagram=reliability_diagram,
        )
