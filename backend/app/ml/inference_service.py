"""Stage 7 Unified Multimodal Inference Service for Encrypted ESP Flows."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

import numpy as np
import torch

from app.ml.bundle import ModelBundle
from app.ml.dataset import CANONICAL_CLASSES
from app.ml.explainability import LocalExplanation
from app.ml.extractor import TabularFeatureExtractor
from app.ml.sequence_extractor import SequenceExtractor


@dataclass
class Stage7InferenceResult:
    """Comprehensive, audit-grade transparency record for a single flow classification."""

    flow_id: str | None
    known_class_prediction: str  # Supervised prediction among 7 classes
    final_class: str  # Known class or UNKNOWN_UNSEEN if OOD-rejected
    calibrated_confidence: float  # max(P_calibrated) under tested distribution
    entropy: float  # Shannon entropy in bits
    normalized_entropy: float  # Shannon entropy / log2(7)
    ood_status: str  # KNOWN_ACCEPTED, UNKNOWN_UNSEEN, OUT_OF_DISTRIBUTION
    rejection_reason: str | None  # HIGH_ENTROPY, LOW_CONFIDENCE, DUAL_TRIGGER, or None
    is_degraded: bool  # True if short flow fallback triggered
    degraded_reason: str | None
    calibrated_probabilities: dict[str, float]  # Class name -> calibrated probability
    xgboost_probabilities: dict[str, float]
    cnn_probabilities: dict[str, float] | None
    branch_agreement: bool | None
    js_divergence: float | None
    behavioral_anomaly_status: str  # STATISTICAL_BEHAVIORAL_ANOMALY, NORMAL_BEHAVIOR
    anomaly_score: float
    anomaly_threshold: float
    xgboost_explanation: dict[str, Any] | None  # Local TreeSHAP explanation for XGBoost branch
    model_bundle_version: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class Stage7InferenceService:
    """Executes the complete Stage 7 multimodal encrypted traffic classification pipeline."""

    def __init__(self, bundle: ModelBundle) -> None:
        self.bundle = bundle
        self.tabular_extractor = TabularFeatureExtractor(schema=bundle.feature_schema)
        self.sequence_extractor = SequenceExtractor(schema=bundle.sequence_schema)

    def classify_flow(
        self,
        packets: list[dict[str, Any]],
        flow_metadata: dict[str, Any] | None = None,
        explain: bool = True,
    ) -> Stage7InferenceResult:
        """Classify an encrypted ESP flow with multimodal fusion, calibration, OOD, SHAP, and anomaly detection.

        Args:
            packets: List of packet dicts belonging to the flow (packet_time, packet_length, direction/spi).
            flow_metadata: Optional dictionary with flow metadata (e.g. 'flow_id', 'spi').
            explain: Whether to compute local TreeSHAP explanations for the XGBoost branch.

        Returns:
            Comprehensive Stage7InferenceResult transparency record.
        """
        flow_id = str(flow_metadata.get("flow_id", "")) if flow_metadata else None

        # ----------------------------------------------------------------------
        # 1. Tabular Feature Extraction & XGBoost Branch
        # ----------------------------------------------------------------------
        feat_dict, _ = self.tabular_extractor.extract_features(packets, flow_metadata=flow_metadata)
        feat_names = [f.name for f in self.bundle.feature_schema.features]
        x_raw = np.array([[feat_dict[f] for f in feat_names]], dtype=np.float32)

        x_scaled = self.bundle.preprocessor.transform(x_raw)
        p_xgb = self.bundle.xgb_model.predict_proba(x_scaled)  # (1, 7)

        # ----------------------------------------------------------------------
        # 2. Sequence Feature Extraction & 1D-CNN Branch (with Graceful Fallback)
        # ----------------------------------------------------------------------
        min_packets = self.bundle.sequence_schema.min_cnn_packets
        is_eligible = len(packets) >= min_packets

        p_cnn: np.ndarray | None = None
        branch_agreement: bool | None = None
        js_div: float | None = None
        is_degraded = False
        degraded_reason = None

        if is_eligible:
            try:
                seq_tensor, mask, _ = self.sequence_extractor.extract_sequence(
                    packets,
                    flow_metadata=flow_metadata,
                    N=self.bundle.sequence_schema.default_horizon,
                )
                t_in = torch.tensor(seq_tensor[np.newaxis, :, :], dtype=torch.float32)
                m_in = torch.tensor(mask[np.newaxis, :], dtype=torch.bool)

                with torch.no_grad():
                    p_cnn = self.bundle.cnn_model.predict_proba(t_in, m_in).cpu().numpy()

                p_fused = self.bundle.fusion_engine.fuse(p_xgb, p_cnn)
                diag = self.bundle.fusion_engine.compute_disagreement(p_xgb, p_cnn)
                branch_agreement = bool(diag["sample_agreements"][0])
                js_div = float(diag["sample_js_divergences"][0])
            except Exception as e:
                # Graceful degradation on CNN failure
                p_fused = p_xgb
                is_degraded = True
                degraded_reason = f"CNN_INFERENCE_ERROR: {e}"
        else:
            # Flow too short for sequence CNN
            p_fused = p_xgb
            is_degraded = True
            degraded_reason = f"FLOW_TOO_SHORT_FOR_CNN (packets={len(packets)} < min={min_packets})"

        # ----------------------------------------------------------------------
        # 3. Probability Calibration
        # ----------------------------------------------------------------------
        p_calibrated = self.bundle.calibrator.calibrate(p_fused)  # (1, 7)
        calibrated_vec = p_calibrated[0]
        max_conf = float(np.max(calibrated_vec))
        pred_idx = int(np.argmax(calibrated_vec))
        known_pred_class = CANONICAL_CLASSES[pred_idx]

        # ----------------------------------------------------------------------
        # 4. Open-Set / Out-of-Distribution (OOD) Gating
        # ----------------------------------------------------------------------
        ood_decision = self.bundle.ood_detector.evaluate_flow(calibrated_vec)
        if ood_decision.is_ood:
            final_class = ood_decision.status  # UNKNOWN_UNSEEN
        else:
            final_class = known_pred_class

        # ----------------------------------------------------------------------
        # 5. TreeSHAP Explainability (XGBoost Branch Only)
        # ----------------------------------------------------------------------
        shap_explanation: LocalExplanation | None = None
        if explain:
            try:
                shap_explanation = self.bundle.explainer.explain_flow(
                    feature_vector=feat_dict,
                    target_class_idx=pred_idx,
                    top_k=5,
                )
            except Exception:
                shap_explanation = None

        # ----------------------------------------------------------------------
        # 6. Behavioral Anomaly Detection (Isolation Forest)
        # ----------------------------------------------------------------------
        anom_decision = self.bundle.anomaly_detector.evaluate_flow(feat_dict)

        # ----------------------------------------------------------------------
        # 7. Transparency Record Assembly
        # ----------------------------------------------------------------------
        p_cal_dict = {cls_name: float(calibrated_vec[i]) for i, cls_name in enumerate(CANONICAL_CLASSES)}
        p_xgb_dict = {cls_name: float(p_xgb[0, i]) for i, cls_name in enumerate(CANONICAL_CLASSES)}
        p_cnn_dict = (
            {cls_name: float(p_cnn[0, i]) for i, cls_name in enumerate(CANONICAL_CLASSES)}
            if p_cnn is not None
            else None
        )

        return Stage7InferenceResult(
            flow_id=flow_id,
            known_class_prediction=known_pred_class,
            final_class=final_class,
            calibrated_confidence=float(round(max_conf, 4)),
            entropy=float(round(ood_decision.entropy, 4)),
            normalized_entropy=float(round(ood_decision.normalized_entropy, 4)),
            ood_status=ood_decision.status,
            rejection_reason=ood_decision.rejection_reason,
            is_degraded=is_degraded,
            degraded_reason=degraded_reason,
            calibrated_probabilities=p_cal_dict,
            xgboost_probabilities=p_xgb_dict,
            cnn_probabilities=p_cnn_dict,
            branch_agreement=branch_agreement,
            js_divergence=float(round(js_div, 4)) if js_div is not None else None,
            behavioral_anomaly_status=anom_decision.status,
            anomaly_score=anom_decision.anomaly_score,
            anomaly_threshold=anom_decision.operational_threshold,
            xgboost_explanation=shap_explanation.to_dict() if shap_explanation else None,
            model_bundle_version=self.bundle.bundle_version,
        )
