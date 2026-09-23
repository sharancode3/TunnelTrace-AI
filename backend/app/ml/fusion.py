"""Multimodal Fusion Subsystem combining Tabular XGBoost and Sequence 1D-CNN."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Any

import numpy as np
from scipy.spatial.distance import jensenshannon
from sklearn.metrics import f1_score, log_loss

from app.ml.dataset import CANONICAL_CLASSES


@dataclass
class FusionConfig:
    """Configuration and parameters for multimodal ensemble fusion."""

    method: str = "WEIGHTED_AVERAGE"  # WEIGHTED_AVERAGE
    alpha: float = 0.5  # Weight assigned to XGBoost (1.0 - alpha assigned to CNN)
    num_classes: int = 7
    classes: list[str] = field(default_factory=lambda: list(CANONICAL_CLASSES))
    search_metrics: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, indent=2)

    def config_hash(self) -> str:
        canonical_bytes = json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(canonical_bytes).hexdigest()

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FusionConfig:
        valid_keys = cls.__dataclass_fields__.keys()
        filtered = {k: v for k, v in data.items() if k in valid_keys}
        return cls(**filtered)


class MultimodalFusionEngine:
    """Combines predicted probability distributions from XGBoost and 1D-CNN branches."""

    def __init__(self, config: FusionConfig | None = None) -> None:
        self.config = config or FusionConfig()

    def fuse(
        self,
        P_xgb: np.ndarray,
        P_cnn: np.ndarray,
        alpha: float | None = None,
    ) -> np.ndarray:
        """Combine two (N, C) probability matrices via weighted averaging.

        P_fused = alpha * P_xgb + (1.0 - alpha) * P_cnn
        """
        if P_xgb.shape != P_cnn.shape:
            raise ValueError(
                f"Shape mismatch: P_xgb has shape {P_xgb.shape}, P_cnn has shape {P_cnn.shape}"
            )
        if P_xgb.shape[1] != self.config.num_classes:
            raise ValueError(
                f"Expected {self.config.num_classes} classes, got {P_xgb.shape[1]}"
            )

        w = alpha if alpha is not None else self.config.alpha
        if not (0.0 <= w <= 1.0):
            raise ValueError(f"Alpha must be in [0.0, 1.0], got {w}")

        P_fused = w * P_xgb + (1.0 - w) * P_cnn

        # Re-normalize to guarantee exact sum = 1.0
        sums = P_fused.sum(axis=1, keepdims=True)
        sums = np.where(sums > 0, sums, 1.0)
        return P_fused / sums

    def compute_disagreement(
        self,
        P_xgb: np.ndarray,
        P_cnn: np.ndarray,
    ) -> dict[str, Any]:
        """Compute branch agreement diagnostic metrics between XGBoost and CNN."""
        pred_xgb = np.argmax(P_xgb, axis=1)
        pred_cnn = np.argmax(P_cnn, axis=1)
        agreement_mask = (pred_xgb == pred_cnn)
        agreement_rate = float(np.mean(agreement_mask))

        # Mean Jensen-Shannon divergence across samples
        js_divs = []
        for i in range(len(P_xgb)):
            # jensenshannon returns square root of JS divergence; we square to get true divergence
            js = jensenshannon(P_xgb[i], P_cnn[i], base=2.0)
            js_divs.append(float(js ** 2) if not np.isnan(js) else 0.0)

        mean_js_div = float(np.mean(js_divs)) if js_divs else 0.0

        return {
            "agreement_rate": agreement_rate,
            "mean_js_divergence": mean_js_div,
            "sample_agreements": agreement_mask.tolist(),
            "sample_js_divergences": js_divs,
            "xgb_predictions": pred_xgb.tolist(),
            "cnn_predictions": pred_cnn.tolist(),
        }

    def search_optimal_alpha(
        self,
        P_xgb_val: np.ndarray,
        P_cnn_val: np.ndarray,
        y_val: np.ndarray,
        grid_steps: int = 21,
    ) -> dict[str, Any]:
        """Search alpha in [0.0, 1.0] on validation data to maximize Macro-F1.

        Never runs on TEST. Returns complete evaluation grid and best configuration.
        """
        alphas = np.linspace(0.0, 1.0, grid_steps)
        candidates = []
        best_alpha = 0.5
        best_macro_f1 = -1.0
        best_nll = float("inf")

        for a in alphas:
            P_fused = self.fuse(P_xgb_val, P_cnn_val, alpha=a)
            preds = np.argmax(P_fused, axis=1)
            macro_f1 = float(f1_score(y_val, preds, average="macro", zero_division=0))

            # Compute NLL with epsilon clipping
            P_clipped = np.clip(P_fused, 1e-15, 1.0 - 1e-15)
            # Normalize clipped
            P_clipped = P_clipped / P_clipped.sum(axis=1, keepdims=True)
            try:
                nll = float(log_loss(y_val, P_clipped, labels=list(range(self.config.num_classes))))
            except Exception:
                nll = float("inf")

            cand = {
                "alpha": float(round(a, 4)),
                "macro_f1": macro_f1,
                "nll": nll,
            }
            candidates.append(cand)

            if (macro_f1 > best_macro_f1) or (abs(macro_f1 - best_macro_f1) < 1e-4 and nll < best_nll):
                best_macro_f1 = macro_f1
                best_nll = nll
                best_alpha = float(round(a, 4))

        # Baseline comparisons
        xgb_only_f1 = next(c["macro_f1"] for c in candidates if c["alpha"] == 1.0)
        cnn_only_f1 = next(c["macro_f1"] for c in candidates if c["alpha"] == 0.0)
        equal_f1 = next(c["macro_f1"] for c in candidates if abs(c["alpha"] - 0.5) < 1e-3)

        self.config.alpha = best_alpha
        self.config.search_metrics = {
            "best_alpha": best_alpha,
            "best_macro_f1": best_macro_f1,
            "best_nll": best_nll,
            "xgb_only_macro_f1": xgb_only_f1,
            "cnn_only_macro_f1": cnn_only_f1,
            "equal_average_macro_f1": equal_f1,
            "grid_results": candidates,
        }

        return self.config.search_metrics
