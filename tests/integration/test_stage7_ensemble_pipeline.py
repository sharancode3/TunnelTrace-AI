"""Integration test for Stage 7 Multimodal Ensemble, Calibration, OOD, TreeSHAP, and Anomaly Detection."""

from __future__ import annotations

import uuid
from pathlib import Path

import numpy as np
import pytest
import torch
from app.db.base import Base
from app.db.models.ml import FlowClassification
from app.ml.anomaly import AnomalyFeatureSchema, IsolationForestAnomalyDetector
from app.ml.auditor import LeakageAuditor
from app.ml.bundle import ArtifactIntegrityError, ModelBundleBuilder, ModelBundleLoader
from app.ml.calibration import ProbabilityCalibrator
from app.ml.cnn.model import Lightweight1DCNN
from app.ml.cnn.trainer import CNNTrainer
from app.ml.constants import CANONICAL_CLASSES
from app.ml.explainability import TreeSHAPExplainer
from app.ml.fusion import MultimodalFusionEngine
from app.ml.inference_service import Stage7InferenceService
from app.ml.ood import OODDetector
from app.ml.preprocessing import FeaturePreprocessor
from app.ml.schema import FeatureSchema
from app.ml.sequence_extractor import SequenceExtractor
from app.ml.sequence_schema import SequenceSchema
from app.ml.trainer import XGBoostBaselineModel
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
STAGE2_RUN01_WAN = REPO_ROOT / "storage" / "lab" / "runs" / "tt-1790185654-25c4bc" / "captures" / "wan_encrypted.pcap"


@pytest.fixture
async def async_db():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    session_factory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with session_factory() as session:
        yield session

    await engine.dispose()


@pytest.mark.asyncio
async def test_stage7_multimodal_pipeline_end_to_end(
    async_db: AsyncSession,
    tmp_path: Path,
):
    """End-to-End Stage 7 Integration Test:
    1. Schemas: FeatureSchema, SequenceSchema, AnomalyFeatureSchema.
    2. Extract: Tabular features (24 dims) and sequence tensors (3, N) for synthetic / lab flows.
    3. Train & Evaluate CNN Candidate Horizons: N in {32, 64, 128}.
    4. Train & Export TorchScript 1D-CNN.
    5. Train XGBoost Baseline Model.
    6. Multimodal Fusion Grid Search across alpha in [0, 1].
    7. Probability Calibration via Temperature Scaling (evaluate pre/post ECE, NLL, Brier).
    8. Open-Set OOD Gating: Tune thresholds, verify UNKNOWN_UNSEEN rejection on OOD.
    9. TreeSHAP Explainability: Exact additivity check and zero-leakage check on XGBoost branch.
    10. Behavioral Anomaly Detection: Train non-pickle Isolation Forest on benign flows.
    11. Model Bundle Export & SHA-256 Checksum Tamper Verification.
    12. Stage 7 Inference Service: Full inference + degraded short-flow fallback.
    13. Database Persistence: FlowClassification ORM insert & query.
    """
    np.random.seed(42)
    torch.manual_seed(42)

    # -------------------------------------------------------------------------
    # 1. Schemas & Leakage Audits
    # -------------------------------------------------------------------------
    feat_schema = FeatureSchema()
    seq_schema = SequenceSchema(default_horizon=32, min_cnn_packets=3)
    anom_schema = AnomalyFeatureSchema(features=[f.name for f in feat_schema.features[:8]])

    # Leakage audits
    LeakageAuditor.audit_forbidden_columns(feat_schema.feature_names)
    LeakageAuditor.audit_forbidden_columns(seq_schema.channels)
    LeakageAuditor.audit_forbidden_columns(anom_schema.features)

    # -------------------------------------------------------------------------
    # 2. Synthetic Multimodal Flow Data (Representing Reconstructed Native IPsec)
    # -------------------------------------------------------------------------
    n_flows = 70
    num_feats = len(feat_schema.features)
    y_all = np.array([i % 7 for i in range(n_flows)], dtype=np.int32)

    # Tabular feature vectors
    X_raw = np.random.randn(n_flows, num_feats).astype(np.float32)
    # Give some class signal
    for i in range(n_flows):
        c = y_all[i]
        X_raw[i, c % num_feats] += 2.5

    preprocessor = FeaturePreprocessor(apply_log1p=True, scaling_strategy="STANDARD_SCALER")
    preprocessor.fit(X_raw, feature_names=feat_schema.feature_names)
    X_scaled = preprocessor.transform(X_raw)

    # Split train / val
    X_train, X_val = X_scaled[:42], X_scaled[42:]
    y_train, y_val = y_all[:42], y_all[42:]

    # Sequence tensors for validation (N_val, 3, 32)
    T_val = np.random.randn(28, 3, 32).astype(np.float32)
    M_val = np.ones((28, 32), dtype=bool)

    # -------------------------------------------------------------------------
    # 3. Candidate Horizons Evaluation (N in {32, 64, 128})
    # -------------------------------------------------------------------------
    seq_extractor = SequenceExtractor(schema=seq_schema)
    raw_train_packets = [
        [
            {
                "packet_time": 0.01 * j,
                "packet_length": 200 + (j % 5) * 50,
                "direction": 1 if j % 2 == 0 else -1,
                "spi": "0x12345678",
            }
            for j in range(15)
        ]
        for _ in range(20)
    ]
    raw_val_packets = [
        [
            {
                "packet_time": 0.01 * j,
                "packet_length": 200 + (j % 5) * 50,
                "direction": 1 if j % 2 == 0 else -1,
                "spi": "0x12345678",
            }
            for j in range(15)
        ]
        for _ in range(10)
    ]
    y_train_sub = y_train[:20]
    y_val_sub = y_val[:10]

    trainer = CNNTrainer(schema=seq_schema)
    trainer.config.max_epochs = 2
    trainer.config.patience = 2
    horizons_eval = trainer.evaluate_candidate_horizons(
        raw_train_packets_by_flow=raw_train_packets,
        train_labels=y_train_sub,
        raw_val_packets_by_flow=raw_val_packets,
        val_labels=y_val_sub,
        extractor=seq_extractor,
        horizons=[32, 64, 128],
    )
    assert len(horizons_eval["candidates"]) == 3
    assert horizons_eval["selected_horizon"] in [32, 64, 128]
    assert horizons_eval["selected_model"] is not None

    # -------------------------------------------------------------------------
    # 4. Train 1D-CNN & Export TorchScript
    # -------------------------------------------------------------------------
    cnn_model = Lightweight1DCNN(
        in_channels=3,
        num_classes=7,
        conv1_channels=16,
        conv2_channels=32,
        fc_hidden=32,
        dropout_rate=0.1,
    )
    cnn_model.eval()
    cnn_pt_path = tmp_path / "cnn_model.pt"
    trainer.export_torchscript(cnn_model, cnn_pt_path)
    assert cnn_pt_path.exists()

    # -------------------------------------------------------------------------
    # 5. Train XGBoost Baseline Model
    # -------------------------------------------------------------------------
    xgb_model = XGBoostBaselineModel()
    xgb_model.fit(X_train, y_train)
    P_xgb_val = xgb_model.predict_proba(X_val)

    # CNN validation predictions
    t_val_tensor = torch.tensor(T_val, dtype=torch.float32)
    m_val_tensor = torch.tensor(M_val, dtype=torch.bool)
    with torch.no_grad():
        P_cnn_val = cnn_model.predict_proba(t_val_tensor, m_val_tensor).cpu().numpy()

    # -------------------------------------------------------------------------
    # 6. Multimodal Fusion Search (Alpha in [0, 1])
    # -------------------------------------------------------------------------
    fusion_engine = MultimodalFusionEngine()
    fusion_metrics = fusion_engine.search_optimal_alpha(
        P_xgb_val=P_xgb_val,
        P_cnn_val=P_cnn_val,
        y_val=y_val,
        grid_steps=11,
    )
    assert "best_alpha" in fusion_metrics
    assert "grid_results" in fusion_metrics
    assert 0.0 <= fusion_engine.config.alpha <= 1.0

    P_fused_val = fusion_engine.fuse(P_xgb_val, P_cnn_val)
    disagree_diag = fusion_engine.compute_disagreement(P_xgb_val, P_cnn_val)
    assert 0.0 <= disagree_diag["agreement_rate"] <= 1.0

    # -------------------------------------------------------------------------
    # 7. Probability Calibration (Temperature Scaling)
    # -------------------------------------------------------------------------
    calibrator = ProbabilityCalibrator()
    calib_metrics = calibrator.fit_temperature(probs_cal=P_fused_val, y_cal=y_val, num_bins=10)
    assert calibrator.config.temperature > 0.0
    assert calib_metrics.nll_after <= calib_metrics.nll_before + 1e-4

    P_calibrated_val = calibrator.calibrate(P_fused_val)
    np.testing.assert_allclose(P_calibrated_val.sum(axis=1), 1.0, rtol=1e-5)

    # -------------------------------------------------------------------------
    # 8. Open-Set OOD Gating
    # -------------------------------------------------------------------------
    # Synthetic OOD: high-entropy uniform distribution
    P_ood_val = np.random.dirichlet(np.ones(7), size=20)
    ood_detector = OODDetector()
    ood_metrics = ood_detector.tune_thresholds(
        probs_known_val=P_calibrated_val,
        probs_ood_val=P_ood_val,
        target_frr=0.10,
    )
    assert "auroc" in ood_metrics
    assert ood_detector.config.entropy_threshold > 0.0

    # Verify OOD flow returns UNKNOWN_UNSEEN
    ood_sample = np.ones(7) / 7.0
    ood_dec = ood_detector.evaluate_flow(ood_sample)
    assert ood_dec.is_ood is True
    assert ood_dec.status == "UNKNOWN_UNSEEN"

    # -------------------------------------------------------------------------
    # 9. TreeSHAP Explainability (XGBoost Branch)
    # -------------------------------------------------------------------------
    explainer = TreeSHAPExplainer(
        xgb_booster=xgb_model.model,
        feature_names=feat_schema.feature_names,
        classes=CANONICAL_CLASSES,
    )
    local_exp = explainer.explain_flow(X_val[0], target_class_idx=int(y_val[0]), top_k=3)
    assert local_exp.explained_model_branch == "XGBOOST_BRANCH_ONLY"
    assert local_exp.is_additive is True

    # -------------------------------------------------------------------------
    # 10. Behavioral Anomaly Detection (Non-Pickle Isolation Forest)
    # -------------------------------------------------------------------------
    anomaly_detector = IsolationForestAnomalyDetector(schema=anom_schema)
    anom_train_mat = X_train[:, :8]
    anom_val_mat = X_val[:, :8]
    anomaly_detector.fit(anom_train_mat, n_estimators=15)
    anom_thresh = anomaly_detector.tune_threshold(anom_val_mat, target_fpr=0.05)
    assert 0.0 < anom_thresh < 1.0

    # Normal sample
    benign_dec = anomaly_detector.evaluate_flow({f: 0.0 for f in anom_schema.features})
    assert benign_dec.status == "NORMAL_BEHAVIOR"

    # Extreme outlier
    outlier_dec = anomaly_detector.evaluate_flow({f: 100.0 for f in anom_schema.features})
    assert outlier_dec.status == "STATISTICAL_BEHAVIORAL_ANOMALY"
    assert "attack" not in outlier_dec.status.lower()

    # -------------------------------------------------------------------------
    # 11. Bundle Build, Export & Tamper Verification
    # -------------------------------------------------------------------------
    bundle_dir = tmp_path / "stage7_bundle_e2e"
    builder = ModelBundleBuilder()
    builder.build_and_export(
        output_dir=bundle_dir,
        xgb_model=xgb_model,
        cnn_model=cnn_model,
        preprocessor=preprocessor,
        feature_schema=feat_schema,
        sequence_schema=seq_schema,
        anomaly_schema=anom_schema,
        fusion_config=fusion_engine.config,
        calibration_config=calibrator.config,
        ood_config=ood_detector.config,
        anomaly_detector=anomaly_detector,
        bundle_id="stage7_e2e_bundle",
        bundle_version="v1.0.0-e2e",
    )

    manifest_file = bundle_dir / "model_manifest.json"
    assert manifest_file.exists()
    bundle = ModelBundleLoader.load_bundle(bundle_dir)
    assert bundle.bundle_id == "stage7_e2e_bundle"

    # Tamper check
    (bundle_dir / "fusion_config.json").write_text("{}", encoding="utf-8")
    with pytest.raises(ArtifactIntegrityError):
        ModelBundleLoader.load_bundle(bundle_dir)

    # Restore bundle for inference service test
    builder.build_and_export(
        output_dir=bundle_dir,
        xgb_model=xgb_model,
        cnn_model=cnn_model,
        preprocessor=preprocessor,
        feature_schema=feat_schema,
        sequence_schema=seq_schema,
        anomaly_schema=anom_schema,
        fusion_config=fusion_engine.config,
        calibration_config=calibrator.config,
        ood_config=ood_detector.config,
        anomaly_detector=anomaly_detector,
        bundle_id="stage7_e2e_bundle",
        bundle_version="v1.0.0-e2e",
    )
    restored_bundle = ModelBundleLoader.load_bundle(bundle_dir)

    # -------------------------------------------------------------------------
    # 12. Stage 7 Unified Inference Service
    # -------------------------------------------------------------------------
    service = Stage7InferenceService(bundle=restored_bundle)

    # Full packet flow (12 packets)
    full_flow_packets = [
        {
            "packet_time": 0.02 * i,
            "packet_length": 300 + (i % 5) * 50,
            "direction": 1 if i % 2 == 0 else -1,
            "spi": "0x11223344",
        }
        for i in range(12)
    ]
    res_full = service.classify_flow(
        packets=full_flow_packets,
        flow_metadata={"flow_id": "flow-full-001", "spi": "0x11223344"},
        explain=True,
    )
    assert res_full.flow_id == "flow-full-001"
    assert res_full.is_degraded is False
    assert res_full.cnn_probabilities is not None
    assert res_full.xgboost_explanation is not None

    # Degraded short flow (2 packets < min_cnn_packets=3)
    short_flow_packets = [
        {"packet_time": 0.0, "packet_length": 150, "direction": 1, "spi": "0x55667788"},
        {"packet_time": 0.05, "packet_length": 150, "direction": -1, "spi": "0x55667788"},
    ]
    res_short = service.classify_flow(
        packets=short_flow_packets,
        flow_metadata={"flow_id": "flow-short-002", "spi": "0x55667788"},
        explain=False,
    )
    assert res_short.is_degraded is True
    assert "short" in res_short.degraded_reason.lower()
    assert res_short.cnn_probabilities is None

    # -------------------------------------------------------------------------
    # 13. Database Lineage & FlowClassification Persistence
    # -------------------------------------------------------------------------
    flow_uuid = uuid.uuid4()
    db_flow_classification = FlowClassification(
        id=uuid.uuid4(),
        flow_id=flow_uuid,
        known_class=res_full.known_class_prediction,
        final_class=res_full.final_class,
        calibrated_confidence=res_full.calibrated_confidence,
        entropy=res_full.entropy,
        normalized_entropy=res_full.normalized_entropy,
        ood_status=res_full.ood_status,
        rejection_reason=res_full.rejection_reason,
        is_degraded=res_full.is_degraded,
        degraded_reason=res_full.degraded_reason,
        behavioral_anomaly_status=res_full.behavioral_anomaly_status,
        anomaly_score=res_full.anomaly_score,
        transparency_data={
            "model_bundle_id": "stage7_e2e_bundle",
            "model_bundle_version": "v1.0.0-e2e",
            "calibrated_probabilities": res_full.calibrated_probabilities,
            "xgboost_probabilities": res_full.xgboost_probabilities,
            "cnn_probabilities": res_full.cnn_probabilities,
            "branch_agreement": res_full.branch_agreement,
            "js_divergence": res_full.js_divergence,
        },
    )
    async_db.add(db_flow_classification)
    await async_db.commit()

    # Query back
    queried = await async_db.get(FlowClassification, db_flow_classification.id)
    assert queried is not None
    assert queried.transparency_data["model_bundle_id"] == "stage7_e2e_bundle"
    assert queried.final_class in list(CANONICAL_CLASSES) + ["UNKNOWN_UNSEEN"]
    assert queried.calibrated_confidence == res_full.calibrated_confidence
