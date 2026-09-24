"""Metadata Fingerprintability Engine.

Orchestrates side-channel distinguishability assessment across encrypted ESP flows.
Transparently evaluates both empirical ML distinguishability and deterministic
metadata distribution regularity.
"""

from __future__ import annotations

import logging
from typing import Any

from app.security.fingerprintability.components import (
    compute_burst_distinguishability,
    compute_classifier_distinguishability,
    compute_directional_asymmetry,
    compute_packet_size_regularity,
    compute_predictive_entropy_complement,
    compute_timing_regularity,
)
from app.security.fingerprintability.models import (
    CalibrationStatus,
    FingerprintabilityComponent,
    FingerprintabilityStatus,
    MetadataFingerprintabilityAssessment,
)

logger = logging.getLogger(__name__)


class MetadataFingerprintabilityEngine:
    """Engine computing behavioral metadata side-channel distinguishability."""

    METHODOLOGY_VERSION = "MFI-v1.0-EXPERIMENTAL"

    DEFAULT_WEIGHTS = {
        "classifier_distinguishability": 0.25,
        "predictive_entropy_complement": 0.15,
        "packet_size_regularity": 0.20,
        "timing_regularity": 0.15,
        "directional_asymmetry": 0.15,
        "burst_distinguishability": 0.10,
    }

    def __init__(
        self,
        weights: dict[str, float] | None = None,
        methodology_version: str | None = None,
    ) -> None:
        self.weights = weights or self.DEFAULT_WEIGHTS.copy()
        self.methodology_version = methodology_version or self.METHODOLOGY_VERSION
        self.methodology_hash = MetadataFingerprintabilityAssessment.compute_methodology_hash(
            self.methodology_version, self.weights
        )

    def assess_flow(
        self,
        analysis_id: str,
        flow_id: str | None,
        flow_features: dict[str, Any],
        ml_prediction: dict[str, Any] | None = None,
        model_bundle_id: str | None = None,
    ) -> MetadataFingerprintabilityAssessment:
        """Compute fingerprintability for an individual encrypted flow."""
        # 1. Extract ML signals if available and verified calibrated
        is_calibrated = False
        calibrated_conf: float | None = None
        norm_entropy: float | None = None
        calib_status = CalibrationStatus.UNAVAILABLE

        if ml_prediction:
            calib_val = ml_prediction.get("is_calibrated")
            # Also check if calibrated_confidence is present and non-zero
            if calib_val or ml_prediction.get("calibrated_confidence") is not None:
                is_calibrated = True
                calib_status = CalibrationStatus.CALIBRATED
                calibrated_conf = float(ml_prediction.get("calibrated_confidence", 0.0))
                norm_entropy = float(ml_prediction.get("normalized_entropy", 0.5))
            else:
                calib_status = CalibrationStatus.RAW_UNACCEPTED

        # 2. Compute individual components
        c_clf = compute_classifier_distinguishability(
            calibrated_confidence=calibrated_conf,
            is_calibrated=is_calibrated,
            weight=self.weights.get("classifier_distinguishability", 0.25),
        )
        c_ent = compute_predictive_entropy_complement(
            normalized_entropy=norm_entropy,
            is_calibrated=is_calibrated,
            weight=self.weights.get("predictive_entropy_complement", 0.15),
        )
        c_size = compute_packet_size_regularity(
            pkt_len_mean=float(flow_features.get("pkt_len_mean", 0.0)),
            pkt_len_std=float(flow_features.get("pkt_len_std", 0.0)),
            total_packets=int(flow_features.get("total_packets", 1)),
            weight=self.weights.get("packet_size_regularity", 0.20),
        )
        c_timing = compute_timing_regularity(
            iat_mean=float(flow_features.get("iat_mean", 0.0)),
            iat_std=float(flow_features.get("iat_std", 0.0)),
            total_packets=int(flow_features.get("total_packets", 1)),
            weight=self.weights.get("timing_regularity", 0.15),
        )
        c_asym = compute_directional_asymmetry(
            fwd_pkt_ratio=float(flow_features.get("fwd_pkt_ratio", 0.5)),
            byte_direction_ratio=flow_features.get("byte_direction_ratio"),
            weight=self.weights.get("directional_asymmetry", 0.15),
        )
        c_burst = compute_burst_distinguishability(
            burst_count=int(flow_features.get("burst_count", 0)),
            total_packets=int(flow_features.get("total_packets", 1)),
            duration_ms=float(flow_features.get("duration_ms", 0.0)),
            weight=self.weights.get("burst_distinguishability", 0.10),
        )

        components = {
            c_clf.name: c_clf,
            c_ent.name: c_ent,
            c_size.name: c_size,
            c_timing.name: c_timing,
            c_asym.name: c_asym,
            c_burst.name: c_burst,
        }

        # 3. Calculate composite index over available components only
        available_comps = [c for c in components.values() if c.is_available]
        if not available_comps:
            return MetadataFingerprintabilityAssessment(
                analysis_id=analysis_id,
                flow_id=flow_id,
                overall_index=None,
                status=FingerprintabilityStatus.UNAVAILABLE,
                methodology_version=self.methodology_version,
                methodology_hash=self.methodology_hash,
                components=components,
                flow_count=1,
                ml_model_bundle_id=model_bundle_id,
                calibration_status=calib_status,
            )

        total_avail_weight = sum(c.weight for c in available_comps)
        if total_avail_weight > 0.0:
            weighted_sum = sum(c.score * c.weight for c in available_comps)
            overall_index = max(0.0, min(100.0, weighted_sum / total_avail_weight))
        else:
            overall_index = 0.0

        return MetadataFingerprintabilityAssessment(
            analysis_id=analysis_id,
            flow_id=flow_id,
            overall_index=round(overall_index, 2),
            status=FingerprintabilityStatus.EXPERIMENTAL,
            methodology_version=self.methodology_version,
            methodology_hash=self.methodology_hash,
            components=components,
            flow_count=1,
            ml_model_bundle_id=model_bundle_id,
            calibration_status=calib_status,
        )

    def assess_analysis(
        self,
        analysis_id: str,
        flows_features: list[dict[str, Any]],
        ml_predictions: list[dict[str, Any]] | None = None,
        model_bundle_id: str | None = None,
    ) -> MetadataFingerprintabilityAssessment:
        """Compute aggregate fingerprintability across all flows in an analysis."""
        if not flows_features:
            # Zero flows observed in analysis
            empty_comp = {
                name: FingerprintabilityComponent(
                    name=name, score=0.0, weight=w, is_available=False, rationale="No ESP flows observed."
                )
                for name, w in self.weights.items()
            }
            return MetadataFingerprintabilityAssessment(
                analysis_id=analysis_id,
                flow_id=None,
                overall_index=None,
                status=FingerprintabilityStatus.UNAVAILABLE,
                methodology_version=self.methodology_version,
                methodology_hash=self.methodology_hash,
                components=empty_comp,
                flow_count=0,
                ml_model_bundle_id=model_bundle_id,
                calibration_status=CalibrationStatus.UNAVAILABLE,
            )

        ml_pred_list = ml_predictions or []
        flow_assessments: list[MetadataFingerprintabilityAssessment] = []

        for i, flow_feat in enumerate(flows_features):
            flow_ml = ml_pred_list[i] if i < len(ml_pred_list) else None
            flow_id = str(flow_feat.get("flow_id", f"flow-{i}"))
            ass = self.assess_flow(
                analysis_id=analysis_id,
                flow_id=flow_id,
                flow_features=flow_feat,
                ml_prediction=flow_ml,
                model_bundle_id=model_bundle_id,
            )
            flow_assessments.append(ass)

        # Aggregate components across flows
        agg_components: dict[str, FingerprintabilityComponent] = {}
        for name, weight in self.weights.items():
            comp_list = [a.components[name] for a in flow_assessments if name in a.components]
            avail_comps = [c for c in comp_list if c.is_available]
            if avail_comps:
                avg_score = sum(c.score for c in avail_comps) / len(avail_comps)
                agg_components[name] = FingerprintabilityComponent(
                    name=name,
                    score=round(avg_score, 2),
                    weight=weight,
                    is_available=True,
                    rationale=f"Averaged across {len(avail_comps)} flows: {avg_score:.1f}%.",
                )
            else:
                agg_components[name] = FingerprintabilityComponent(
                    name=name,
                    score=0.0,
                    weight=weight,
                    is_available=False,
                    rationale="Unavailable across all analyzed flows.",
                )

        available_agg = [c for c in agg_components.values() if c.is_available]
        if available_agg:
            tot_w = sum(c.weight for c in available_agg)
            w_sum = sum(c.score * c.weight for c in available_agg)
            agg_overall = round(w_sum / tot_w, 2) if tot_w > 0 else 0.0
            status = FingerprintabilityStatus.EXPERIMENTAL
        else:
            agg_overall = None
            status = FingerprintabilityStatus.UNAVAILABLE

        # Check calibration status across assessments
        calib_statuses = [a.calibration_status for a in flow_assessments]
        if any(s == CalibrationStatus.CALIBRATED for s in calib_statuses):
            overall_calib = CalibrationStatus.CALIBRATED
        elif any(s == CalibrationStatus.RAW_UNACCEPTED for s in calib_statuses):
            overall_calib = CalibrationStatus.RAW_UNACCEPTED
        else:
            overall_calib = CalibrationStatus.UNAVAILABLE

        return MetadataFingerprintabilityAssessment(
            analysis_id=analysis_id,
            flow_id=None,
            overall_index=agg_overall,
            status=status,
            methodology_version=self.methodology_version,
            methodology_hash=self.methodology_hash,
            components=agg_components,
            flow_count=len(flows_features),
            ml_model_bundle_id=model_bundle_id,
            calibration_status=overall_calib,
        )
