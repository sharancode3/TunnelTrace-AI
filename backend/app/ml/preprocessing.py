"""Train-Only Preprocessing Pipeline for Tabular Side-Channel Features."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd


class FeaturePreprocessor:
    """Preprocesses tabular feature matrices while strictly enforcing fit-transform isolation.

    All centering, scaling, and quantile parameters are fitted EXCLUSIVELY on the TRAIN partition,
    and applied unchanged to VALIDATION and TEST partitions to prevent data leakage.
    """

    HEAVY_TAIL_COLUMNS: list[str] = [
        "duration_ms",
        "total_bytes",
        "iat_mean_ms",
        "iat_std_ms",
        "iat_max_ms",
        "fwd_iat_mean_ms",
        "rev_iat_mean_ms",
        "bytes_per_second",
        "packets_per_second",
        "burst_mean_bytes",
    ]

    def __init__(
        self,
        apply_log1p: bool = True,
        scaling_strategy: str = "NONE",  # "NONE", "ROBUST_SCALER", "STANDARD_SCALER"
    ) -> None:
        self.apply_log1p = apply_log1p
        self.scaling_strategy = scaling_strategy.upper()
        self.is_fitted: bool = False
        self.fitted_columns: list[str] = []
        self.center_params: dict[str, float] = {}
        self.scale_params: dict[str, float] = {}

    def fit(
        self,
        X: pd.DataFrame | np.ndarray,
        feature_names: list[str] | None = None,
    ) -> FeaturePreprocessor:
        """Fit preprocessor parameters strictly on the training partition X_train."""
        if isinstance(X, np.ndarray):
            cols = feature_names or [f"f_{i}" for i in range(X.shape[1])]
            X_df = pd.DataFrame(X, columns=cols)
        else:
            X_df = X

        self.fitted_columns = list(X_df.columns)
        X_work = X_df.copy()

        # 1. Apply log1p on heavy-tailed features before fitting scalers
        if self.apply_log1p:
            for col in self.HEAVY_TAIL_COLUMNS:
                if col in X_work.columns:
                    X_work[col] = np.log1p(np.maximum(0.0, X_work[col].values))

        # 2. Fit scaling statistics
        self.center_params = {}
        self.scale_params = {}

        if self.scaling_strategy == "ROBUST_SCALER":
            for col in self.fitted_columns:
                vals = X_work[col].values
                med = float(np.median(vals))
                q25 = float(np.percentile(vals, 25))
                q75 = float(np.percentile(vals, 75))
                iqr = q75 - q25
                self.center_params[col] = med
                self.scale_params[col] = iqr if iqr > 1e-6 else 1.0

        elif self.scaling_strategy == "STANDARD_SCALER":
            for col in self.fitted_columns:
                vals = X_work[col].values
                mean = float(np.mean(vals))
                std = float(np.std(vals))
                self.center_params[col] = mean
                self.scale_params[col] = std if std > 1e-6 else 1.0

        self.is_fitted = True
        return self

    def transform(self, X: pd.DataFrame | np.ndarray) -> pd.DataFrame | np.ndarray:
        """Apply fitted transformations to a feature matrix (Train, Val, or Test)."""
        if not self.is_fitted:
            raise RuntimeError("Preprocessor must be fit on training data before calling transform().")

        is_numpy = isinstance(X, np.ndarray)
        if is_numpy:
            X_df = pd.DataFrame(X, columns=self.fitted_columns)
        else:
            X_df = X

        # Verify exact column order
        if list(X_df.columns) != self.fitted_columns:
            raise ValueError(
                f"FEATURE_SCHEMA_MISMATCH: Input columns {list(X_df.columns)} do not match fitted columns {self.fitted_columns}."
            )

        X_out = X_df.copy()

        # 1. Apply log1p
        if self.apply_log1p:
            for col in self.HEAVY_TAIL_COLUMNS:
                if col in X_out.columns:
                    X_out[col] = np.log1p(np.maximum(0.0, X_out[col].values))

        # 2. Apply scaling using parameters fitted on TRAIN
        if self.scaling_strategy in ("ROBUST_SCALER", "STANDARD_SCALER"):
            for col in self.fitted_columns:
                center = self.center_params[col]
                scale = self.scale_params[col]
                X_out[col] = (X_out[col].values - center) / scale

        return X_out.to_numpy(dtype=np.float32) if is_numpy else X_out

    def fit_transform(
        self,
        X: pd.DataFrame | np.ndarray,
        feature_names: list[str] | None = None,
    ) -> pd.DataFrame | np.ndarray:
        """Fit on TRAIN and immediately transform."""
        return self.fit(X, feature_names=feature_names).transform(X)

    def to_dict(self) -> dict[str, Any]:
        """Export fitted parameters in a safe non-pickle dictionary."""
        return {
            "apply_log1p": self.apply_log1p,
            "scaling_strategy": self.scaling_strategy,
            "is_fitted": self.is_fitted,
            "fitted_columns": self.fitted_columns,
            "center_params": self.center_params,
            "scale_params": self.scale_params,
        }

    def to_json(self) -> str:
        """Export parameters as JSON string."""
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FeaturePreprocessor:
        """Construct from dictionary."""
        obj = cls(
            apply_log1p=data.get("apply_log1p", True),
            scaling_strategy=data.get("scaling_strategy", "NONE"),
        )
        obj.is_fitted = data.get("is_fitted", False)
        obj.fitted_columns = data.get("fitted_columns", [])
        obj.center_params = data.get("center_params", {})
        obj.scale_params = data.get("scale_params", {})
        return obj

    def save_params(self, file_path: str | Path) -> None:
        """Export parameters to a JSON file."""
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(self.to_json())

    @classmethod
    def from_params_file(cls, file_path: str | Path) -> FeaturePreprocessor:
        """Construct from a JSON file."""
        with open(file_path, encoding="utf-8") as f:
            return cls.from_json(f.read())

    @classmethod
    def from_json(cls, json_str: str) -> FeaturePreprocessor:
        return cls.from_dict(json.loads(json_str))

