"""Stage 7 & Stage 9 ML Inference Pipeline Execution Service.

Coordinates loading the active model bundle, extracting flow packet sequences,
executing multimodal inference on CPU, and persisting FlowClassification records.
"""

from __future__ import annotations

import logging
import uuid
from pathlib import Path
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.capture import ProtocolObservation
from app.db.models.ml import FlowClassification
from app.db.models.reconstruction import ESPFlow
from app.ml.bundle import ModelBundle, ModelBundleLoader
from app.ml.inference_service import Stage7InferenceResult, Stage7InferenceService

logger = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
DEFAULT_MODEL_DIR = REPO_ROOT / "models" / "active"


def extract_flow_packets(
    observations: list[ProtocolObservation],
    flow: ESPFlow,
) -> list[dict[str, Any]]:
    """Extract and orient packet sequence for a specific ESPFlow from protocol observations."""
    packets_by_frame: dict[int, dict[str, Any]] = {}

    for obs in observations:
        if obs.protocol not in ("ESP", "NAT-T"):
            continue

        fn = obs.frame_number
        if fn not in packets_by_frame:
            packets_by_frame[fn] = {
                "frame_number": fn,
                "packet_time": obs.packet_time,
                "spi": None,
                "packet_length": 0,
            }

        p = packets_by_frame[fn]
        if obs.field_name == "esp.spi":
            p["spi"] = obs.normalized_value.lower()
        elif obs.field_name in ("esp.packet_length", "esp.length", "frame.len"):
            try:
                p["packet_length"] = int(obs.normalized_value or obs.raw_value or 0)
            except (ValueError, TypeError):
                pass
        elif obs.extra_attributes and isinstance(obs.extra_attributes, dict):
            len_val = obs.extra_attributes.get("packet_len_bytes") or obs.extra_attributes.get("length")
            if len_val is not None:
                try:
                    p["packet_length"] = int(len_val)
                except (ValueError, TypeError):
                    pass

    # Orient packets with direction: 1 for forward SPI, -1 for reverse SPI
    flow_packets = []
    forward_spi = flow.spi.lower() if flow.spi else ""
    reverse_spi = flow.reverse_spi.lower() if flow.reverse_spi else None

    for p in packets_by_frame.values():
        if not p["spi"]:
            continue
        pkt_spi = p["spi"]
        if pkt_spi == forward_spi:
            flow_packets.append({
                "packet_time": p["packet_time"],
                "packet_length": max(p["packet_length"], 64),
                "direction": 1,
                "spi": pkt_spi,
            })
        elif reverse_spi and pkt_spi == reverse_spi:
            flow_packets.append({
                "packet_time": p["packet_time"],
                "packet_length": max(p["packet_length"], 64),
                "direction": -1,
                "spi": pkt_spi,
            })

    # Sort chronologically
    flow_packets.sort(key=lambda x: x["packet_time"])

    # Fallback if no frame-level length was parsed: synthesize from flow summary bounds
    if not flow_packets:
        count = max(flow.packet_count, 1)
        step = (flow.duration_seconds / count) if count > 1 else 0.01
        avg_len = (flow.byte_count // count) if count > 0 and flow.byte_count > 0 else 128
        for i in range(min(count, 32)):
            flow_packets.append({
                "packet_time": flow.start_time + (i * step),
                "packet_length": avg_len,
                "direction": 1,
                "spi": forward_spi,
            })

    return flow_packets


async def execute_flow_classification(
    analysis_id: uuid.UUID,
    db: AsyncSession,
    model_dir: Path | None = None,
) -> int:
    """Execute ML inference for all reconstructed ESPFlows of an analysis.

    Returns the number of flows successfully classified.
    """
    resolved_model_dir = model_dir or DEFAULT_MODEL_DIR
    manifest_path = resolved_model_dir / "model_manifest.json"

    if not manifest_path.exists():
        logger.info(
            "Model manifest not found at %s. ML inference bypassed (STATUS: UNAVAILABLE).",
            manifest_path,
        )
        return 0

    try:
        bundle: ModelBundle = ModelBundleLoader.load_bundle(resolved_model_dir)
        service = Stage7InferenceService(bundle=bundle)
    except Exception as exc:
        logger.warning(
            "Failed to load Stage 7 model bundle from %s: %s. ML inference bypassed.",
            resolved_model_dir,
            exc,
        )
        return 0

    # Fetch reconstructed flows
    flows_res = await db.execute(
        select(ESPFlow).where(ESPFlow.analysis_id == analysis_id)
    )
    flows = list(flows_res.scalars().all())
    if not flows:
        logger.info("No ESPFlow records found for analysis %s. Skipping ML inference.", analysis_id)
        return 0

    # Fetch observations to extract flow packet sequences
    obs_res = await db.execute(
        select(ProtocolObservation)
        .where(ProtocolObservation.analysis_id == analysis_id)
        .order_by(ProtocolObservation.packet_time, ProtocolObservation.frame_number)
    )
    observations = list(obs_res.scalars().all())

    # Clear prior classifications for idempotency
    flow_ids = [f.id for f in flows]
    await db.execute(
        delete(FlowClassification).where(FlowClassification.flow_id.in_(flow_ids))
    )
    await db.flush()

    classified_count = 0
    for flow in flows:
        packets = extract_flow_packets(observations, flow)
        flow_metadata = {"flow_id": str(flow.id), "spi": flow.spi}

        try:
            result: Stage7InferenceResult = service.classify_flow(
                packets=packets,
                flow_metadata=flow_metadata,
                explain=True,
            )

            shap_data = None
            if result.xgboost_explanation and isinstance(result.xgboost_explanation, dict):
                shap_data = result.xgboost_explanation.get("contributions")

            classification = FlowClassification(
                id=uuid.uuid4(),
                flow_id=flow.id,
                known_class=result.known_class_prediction,
                final_class=result.final_class,
                calibrated_confidence=float(result.calibrated_confidence),
                entropy=float(result.entropy),
                normalized_entropy=float(result.normalized_entropy),
                ood_status=result.ood_status,
                rejection_reason=result.rejection_reason,
                is_degraded=result.is_degraded,
                degraded_reason=result.degraded_reason,
                behavioral_anomaly_status=result.behavioral_anomaly_status,
                anomaly_score=float(result.anomaly_score),
                transparency_data={
                    "calibrated_probabilities": result.calibrated_probabilities,
                    "xgboost_probabilities": result.xgboost_probabilities,
                    "cnn_probabilities": result.cnn_probabilities,
                    "branch_agreement": result.branch_agreement,
                    "js_divergence": result.js_divergence,
                    "shap_values": shap_data,
                    "model_bundle_version": result.model_bundle_version,
                },
            )
            db.add(classification)
            classified_count += 1
        except Exception as flow_err:
            logger.error(
                "Classification failed for flow %s: %s", flow.id, flow_err
            )

    await db.commit()
    logger.info(
        "Successfully classified %d/%d flows for analysis %s.",
        classified_count,
        len(flows),
        analysis_id,
    )
    return classified_count
