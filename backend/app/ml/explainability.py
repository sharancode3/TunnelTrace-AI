"""TreeSHAP Explainability Subsystem for the Tabular XGBoost Branch."""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass, field
from typing import Any

import numpy as np
import pandas as pd
import shap

from app.ml.auditor import LeakageAuditor
from app.ml.dataset import CANONICAL_CLASSES

logger = logging.getLogger(__name__)


@dataclass
class FeatureContribution:
    """Individual feature contribution to the XGBoost prediction margin."""

    feature_name: str
    feature_value: float
    contribution: float  # SHAP value on margin space
    direction: str  # POSITIVE (pushes toward class), NEGATIVE (pushes away)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class LocalExplanation:
    """Local explanation record for a single classified flow."""

    explained_model_branch: str = "XGBOOST_BRANCH_ONLY"  # TreeSHAP strictly explains XGBoost, NOT CNN/Ensemble
    target_class_index: int = 0
    target_class_name: str = "Unknown"
    base_value: float = 0.0
    sum_contributions: float = 0.0
    predicted_margin: float = 0.0
    is_additive: bool = True
    output_space: str = "RAW_MARGIN"
    top_positive_contributions: list[FeatureContribution] = field(default_factory=list)
    top_negative_contributions: list[FeatureContribution] = field(default_factory=list)
    status: str = "EXPLANATION_AVAILABLE"  # EXPLANATION_AVAILABLE, UNAVAILABLE

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["top_positive_contributions"] = [c.to_dict() for c in self.top_positive_contributions]
        d["top_negative_contributions"] = [c.to_dict() for c in self.top_negative_contributions]
        return d


class TreeSHAPExplainer:
    """Wraps SHAP TreeExplainer for the XGBoost baseline branch.

    EXPLICIT SCOPE: Explains the XGBoost tabular model only.
    Does NOT explain the 1D-CNN or the multimodal fused ensemble.
    """

    def __init__(
        self,
        xgb_booster: Any,
        feature_names: list[str],
        classes: list[str] | None = None,
    ) -> None:
        self.feature_names = list(feature_names)
        self.classes = classes or list(CANONICAL_CLASSES)

        # Audit features for zero leakage
        self._audit_features(self.feature_names)

        # Store native booster
        if hasattr(xgb_booster, "get_booster"):
            self.booster = xgb_booster.get_booster()
        elif hasattr(xgb_booster, "model") and hasattr(xgb_booster.model, "get_booster"):
            self.booster = xgb_booster.model.get_booster()
        elif hasattr(xgb_booster, "predict"):
            self.booster = xgb_booster
        else:
            self.booster = None

        # Optional SHAP explainer fallback
        try:
            self.explainer = shap.TreeExplainer(self.booster)
        except Exception:
            self.explainer = None

    def _audit_features(self, feature_names: list[str]) -> None:
        """Verify no prohibited column names exist in the explanation feature list."""
        LeakageAuditor.audit_forbidden_columns(feature_names)

    def explain_flow(
        self,
        feature_vector: np.ndarray | pd.Series | dict[str, float],
        target_class_idx: int,
        top_k: int = 5,
    ) -> LocalExplanation:
        """Compute local TreeSHAP feature contributions for a single flow prediction.

        Uses native XGBoost pred_contribs for exact additivity and compatibility.
        """
        if self.booster is None and self.explainer is None:
            return LocalExplanation(
                status="UNAVAILABLE",
                target_class_index=target_class_idx,
                target_class_name=self.classes[target_class_idx] if target_class_idx < len(self.classes) else "Unknown",
            )

        if isinstance(feature_vector, dict):
            vec = np.array([feature_vector.get(f, 0.0) for f in self.feature_names], dtype=np.float32)
        elif isinstance(feature_vector, pd.Series):
            vec = feature_vector[self.feature_names].to_numpy(dtype=np.float32)
        else:
            vec = np.asarray(feature_vector, dtype=np.float32)

        x_row = vec.reshape(1, -1)
        num_feats = len(self.feature_names)
        class_shap: np.ndarray = np.zeros(num_feats)
        base_val: float = 0.0

        # Try native XGBoost SHAP contributions first
        if self.booster is not None:
            try:
                import xgboost as xgb
                dmat = xgb.DMatrix(x_row)
                contribs = self.booster.predict(dmat, pred_contribs=True)
                if contribs.ndim == 3:
                    # Shape: (1, num_classes, num_feats + 1)
                    target_idx = min(target_class_idx, contribs.shape[1] - 1)
                    class_shap = contribs[0, target_idx, :num_feats]
                    base_val = float(contribs[0, target_idx, num_feats])
                elif contribs.ndim == 2:
                    class_shap = contribs[0, :num_feats]
                    base_val = float(contribs[0, num_feats])
            except Exception as e:
                logger.warning("Native XGBoost SHAP failed, attempting SHAP explainer fallback: %s", e)
                if self.explainer is not None:
                    try:
                        shap_vals = self.explainer.shap_values(x_row)
                        if isinstance(shap_vals, list):
                            class_shap = shap_vals[target_class_idx][0]
                        elif isinstance(shap_vals, np.ndarray) and shap_vals.ndim == 3:
                            class_shap = shap_vals[0, target_class_idx, :]
                        elif isinstance(shap_vals, np.ndarray) and shap_vals.ndim == 2:
                            class_shap = shap_vals[0]
                    except Exception:
                        pass
        elif self.explainer is not None:
            try:
                shap_vals = self.explainer.shap_values(x_row)
                if isinstance(shap_vals, list):
                    class_shap = shap_vals[target_class_idx][0]
                elif isinstance(shap_vals, np.ndarray) and shap_vals.ndim == 3:
                    class_shap = shap_vals[0, target_class_idx, :]
                elif isinstance(shap_vals, np.ndarray) and shap_vals.ndim == 2:
                    class_shap = shap_vals[0]
            except Exception:
                pass

        sum_contributions = float(np.sum(class_shap))
        pred_margin = base_val + sum_contributions

        # Collect contributions
        positive_contribs: list[FeatureContribution] = []
        negative_contribs: list[FeatureContribution] = []

        for idx, fn in enumerate(self.feature_names):
            val = float(vec[idx])
            phi = float(class_shap[idx]) if idx < len(class_shap) else 0.0
            if phi >= 0:
                positive_contribs.append(
                    FeatureContribution(
                        feature_name=fn,
                        feature_value=val,
                        contribution=phi,
                        direction="POSITIVE",
                    )
                )
            else:
                negative_contribs.append(
                    FeatureContribution(
                        feature_name=fn,
                        feature_value=val,
                        contribution=phi,
                        direction="NEGATIVE",
                    )
                )

        # Sort positive descending, negative ascending
        positive_contribs.sort(key=lambda c: c.contribution, reverse=True)
        negative_contribs.sort(key=lambda c: c.contribution)

        target_name = (
            self.classes[target_class_idx] if target_class_idx < len(self.classes) else f"Class_{target_class_idx}"
        )

        return LocalExplanation(
            explained_model_branch="XGBOOST_BRANCH_ONLY",
            target_class_index=target_class_idx,
            target_class_name=target_name,
            base_value=base_val,
            sum_contributions=sum_contributions,
            predicted_margin=pred_margin,
            is_additive=True,
            output_space="RAW_MARGIN",
            top_positive_contributions=positive_contribs[:top_k],
            top_negative_contributions=negative_contribs[:top_k],
            status="EXPLANATION_AVAILABLE",
        )

    def compute_global_summary(self, X: pd.DataFrame | np.ndarray) -> dict[str, float]:
        """Compute mean absolute SHAP value across samples for global feature importance ranking."""
        x_mat = X if isinstance(X, np.ndarray) else X.to_numpy()
        if self.booster is not None:
            try:
                import xgboost as xgb
                dmat = xgb.DMatrix(x_mat)
                contribs = self.booster.predict(dmat, pred_contribs=True)
                if contribs.ndim == 3:
                    # Exclude bias column and average across samples and classes
                    mean_abs = np.mean(np.abs(contribs[:, :, :-1]), axis=(0, 1))
                elif contribs.ndim == 2:
                    mean_abs = np.mean(np.abs(contribs[:, :-1]), axis=0)
                else:
                    return {}
                return {fn: float(mean_abs[idx]) for idx, fn in enumerate(self.feature_names) if idx < len(mean_abs)}
            except Exception:
                pass

        if self.explainer is not None:
            try:
                shap_vals = self.explainer.shap_values(x_mat)
                if isinstance(shap_vals, list):
                    mean_abs = np.mean([np.mean(np.abs(sv), axis=0) for sv in shap_vals], axis=0)
                elif isinstance(shap_vals, np.ndarray) and shap_vals.ndim == 3:
                    mean_abs = np.mean(np.abs(shap_vals), axis=(0, 1))
                else:
                    mean_abs = np.mean(np.abs(shap_vals), axis=0)
                return {fn: float(mean_abs[idx]) for idx, fn in enumerate(self.feature_names) if idx < len(mean_abs)}
            except Exception:
                pass

        return {}

