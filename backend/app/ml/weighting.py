"""Sample Weight Computation Subsystem (Train-Only Fit)."""

from __future__ import annotations

from typing import Any

import numpy as np


class SampleWeightComputer:
    """Computes sample weights derived strictly from TRAIN partition labels and session groups.

    Never uses validation or test counts to prevent label distribution leakage.
    """

    SUPPORTED_PROFILES: list[str] = [
        "NONE",
        "CLASS_BALANCED",
        "SESSION_CLASS_BALANCED",
    ]

    def __init__(self, profile: str = "NONE") -> None:
        self.profile = profile.upper()
        if self.profile not in self.SUPPORTED_PROFILES:
            raise ValueError(f"Unsupported weighting profile '{profile}'. Choose from {self.SUPPORTED_PROFILES}")

    def compute_weights(
        self,
        y_train: np.ndarray,
        groups_train: np.ndarray | None = None,
    ) -> np.ndarray:
        """Compute sample weights for the training set.

        Args:
            y_train: Integer class labels of the training partition.
            groups_train: Session ID array corresponding to each training sample.

        Returns:
            np.ndarray of positive float sample weights with length len(y_train).
        """
        n = len(y_train)
        if n == 0 or self.profile == "NONE":
            return np.ones(n, dtype=np.float64)

        classes, class_counts = np.unique(y_train, return_counts=True)
        m = len(classes)
        if m <= 1:
            return np.ones(n, dtype=np.float64)

        # 1. Base class-balanced weight: w_c = N / (M * N_c)
        class_weight_map: dict[int, float] = {}
        for c, count in zip(classes, class_counts, strict=False):
            class_weight_map[int(c)] = float(n / (m * count))

        sample_weights = np.array([class_weight_map[int(y)] for y in y_train], dtype=np.float64)

        # 2. Session-class balanced: normalize contribution of high-flow sessions
        if self.profile == "SESSION_CLASS_BALANCED" and groups_train is not None and len(groups_train) == n:
            unique_sessions, session_flow_counts = np.unique(groups_train, return_counts=True)
            session_count_map = dict(zip(unique_sessions, session_flow_counts, strict=False))

            for i in range(n):
                sess_id = groups_train[i]
                cnt = session_count_map.get(sess_id, 1)
                # Dampen flow count weight so sessions with many flows contribute proportionally
                sample_weights[i] = sample_weights[i] / float(cnt)

            # Re-normalize so sum of weights equals n
            total_w = np.sum(sample_weights)
            if total_w > 0:
                sample_weights = (sample_weights / total_w) * n

        return sample_weights

    def get_summary(
        self,
        y_train: np.ndarray,
        weights: np.ndarray,
    ) -> dict[str, Any]:
        """Summarize weighting distribution by class."""
        summary = {"profile": self.profile, "class_weights": {}}
        for c in np.unique(y_train):
            mask = y_train == c
            summary["class_weights"][str(c)] = {
                "mean_weight": float(np.mean(weights[mask])) if np.any(mask) else 0.0,
                "count": int(np.sum(mask)),
            }
        return summary
