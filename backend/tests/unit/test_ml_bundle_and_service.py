"""
Unit tests for Stage 7 Model Bundle packaging, SHA-256 tamper verification,
and Stage 7 Inference Service (including degraded short-flow fallback).
"""

from pathlib import Path

import numpy as np
import pytest

from app.ml.anomaly import AnomalyFeatureSchema, IsolationForestAnomalyDetector
from app.ml.bundle import ArtifactIntegrityError, ModelBundleBuilder, ModelBundleLoader
from app.ml.calibration import CalibrationConfig
from app.ml.cnn.model import Lightweight1DCNN
from app.ml.constants import CANONICAL_CLASSES
from app.ml.fusion import FusionConfig
from app.ml.inference_service import Stage7InferenceResult, Stage7InferenceService
from app.ml.ood import OODConfig
from app.ml.preprocessing import FeaturePreprocessor
from app.ml.schema import FeatureSchema
from app.ml.sequence_schema import SequenceSchema
from app.ml.trainer import XGBoostBaselineModel


@pytest.fixture
def trained_bundle_dir(tmp_path: Path) -> Path:
    bundle_dir = tmp_path / "stage7_bundle"

    # 1. Schemas
    feat_schema = FeatureSchema()
    seq_schema = SequenceSchema(default_horizon=32, min_cnn_packets=3)
    num_feats = len(feat_schema.features)
    anom_schema = AnomalyFeatureSchema(features=[f.name for f in feat_schema.features[:6]])

    # 2. Preprocessor
    preprocessor = FeaturePreprocessor(apply_log1p=True, scaling_strategy="NONE")
    # Fit dummy preprocessor
    np.random.seed(42)
    dummy_x = np.random.randn(20, num_feats).astype(np.float32)
    preprocessor.fit(dummy_x, feature_names=feat_schema.feature_names)

    # 3. XGBoost Model
    xgb_model = XGBoostBaselineModel()
    dummy_y = np.array([i % 7 for i in range(20)])
    x_trans = preprocessor.transform(dummy_x)
    xgb_model.fit(x_trans, dummy_y)

    # 4. CNN Model
    cnn_model = Lightweight1DCNN(
        num_classes=7,
        in_channels=3,
        conv1_channels=16,
        conv2_channels=32,
        dropout_rate=0.1,
    )
    cnn_model.eval()

    # 5. Configurations
    fusion_cfg = FusionConfig(alpha=0.6)
    calib_cfg = CalibrationConfig(method="TEMPERATURE_SCALING", temperature=1.1)
    ood_cfg = OODConfig(entropy_threshold=1.5, min_confidence_threshold=0.4)

    # 6. Anomaly Detector
    anomaly_detector = IsolationForestAnomalyDetector(schema=anom_schema)
    anom_x = dummy_x[:, :6]
    anomaly_detector.fit(anom_x, n_estimators=10)
    anomaly_detector.tune_threshold(anom_x, target_fpr=0.05)

    # 7. Build and Export
    builder = ModelBundleBuilder()
    builder.build_and_export(
        output_dir=bundle_dir,
        xgb_model=xgb_model,
        cnn_model=cnn_model,
        preprocessor=preprocessor,
        feature_schema=feat_schema,
        sequence_schema=seq_schema,
        anomaly_schema=anom_schema,
        fusion_config=fusion_cfg,
        calibration_config=calib_cfg,
        ood_config=ood_cfg,
        anomaly_detector=anomaly_detector,
        bundle_id="stage7_test_bundle",
        bundle_version="v1.0.0-test",
    )
    return bundle_dir


class TestModelBundlePackagingAndLoading:
    def test_bundle_creation_and_loading(self, trained_bundle_dir: Path) -> None:
        assert (trained_bundle_dir / "model_manifest.json").exists()

        # Load bundle successfully
        bundle = ModelBundleLoader.load_bundle(trained_bundle_dir)
        assert bundle.bundle_id == "stage7_test_bundle"
        assert bundle.bundle_version == "v1.0.0-test"
        assert bundle.cnn_model is not None
        assert bundle.xgb_model is not None
        assert bundle.preprocessor is not None

    def test_tamper_detection_triggers_error(self, trained_bundle_dir: Path) -> None:
        # Tamper with fusion_config.json
        cfg_file = trained_bundle_dir / "fusion_config.json"
        content = cfg_file.read_text(encoding="utf-8")
        cfg_file.write_text(content + "  ", encoding="utf-8")

        # Loading must raise ArtifactIntegrityError
        with pytest.raises(ArtifactIntegrityError, match="Checksum mismatch"):
            ModelBundleLoader.load_bundle(trained_bundle_dir)

    def test_missing_file_triggers_error(self, trained_bundle_dir: Path) -> None:
        # Delete calibration_config.json
        (trained_bundle_dir / "calibration_config.json").unlink()

        with pytest.raises(ArtifactIntegrityError, match="Missing bundle artifact file"):
            ModelBundleLoader.load_bundle(trained_bundle_dir)


class TestStage7InferenceService:
    def test_inference_service_full_flow(self, trained_bundle_dir: Path) -> None:
        bundle = ModelBundleLoader.load_bundle(trained_bundle_dir)
        service = Stage7InferenceService(bundle=bundle)

        # 10 valid encrypted ESP packets
        packets = [
            {
                "packet_time": 0.05 * i,
                "packet_length": 100 + i * 50,
                "direction": 1 if i % 2 == 0 else -1,
                "spi": "0x12345678",
            }
            for i in range(10)
        ]
        flow_metadata = {"flow_id": "test_flow_01", "spi": "0x12345678"}

        result: Stage7InferenceResult = service.classify_flow(
            packets=packets,
            flow_metadata=flow_metadata,
            explain=True,
        )

        assert result.flow_id == "test_flow_01"
        assert result.is_degraded is False
        assert result.degraded_reason is None
        assert result.known_class_prediction in CANONICAL_CLASSES
        assert result.final_class in list(CANONICAL_CLASSES) + ["UNKNOWN_UNSEEN"]
        assert 0.0 <= result.calibrated_confidence <= 1.0
        assert len(result.calibrated_probabilities) == 7
        assert len(result.xgboost_probabilities) == 7
        assert result.cnn_probabilities is not None and len(result.cnn_probabilities) == 7
        assert result.entropy >= 0.0
        assert result.behavioral_anomaly_status in [
            "STATISTICAL_BEHAVIORAL_ANOMALY",
            "NORMAL_BEHAVIOR",
        ]
        assert result.xgboost_explanation is not None

    def test_inference_service_short_flow_degraded_fallback(
        self, trained_bundle_dir: Path
    ) -> None:
        bundle = ModelBundleLoader.load_bundle(trained_bundle_dir)
        service = Stage7InferenceService(bundle=bundle)

        # Only 2 packets (< min_cnn_packets=3)
        packets = [
            {
                "packet_time": 0.0,
                "packet_length": 250,
                "direction": 1,
                "spi": "0x99999999",
            },
            {
                "packet_time": 0.1,
                "packet_length": 250,
                "direction": -1,
                "spi": "0x99999999",
            },
        ]
        flow_metadata = {"flow_id": "short_flow_02", "spi": "0x99999999"}

        result: Stage7InferenceResult = service.classify_flow(
            packets=packets,
            flow_metadata=flow_metadata,
            explain=False,
        )

        # Must fall back gracefully to XGBoost degraded mode
        assert result.is_degraded is True
        assert result.degraded_reason is not None
        assert "short" in result.degraded_reason.lower()
        assert result.cnn_probabilities is None
        assert len(result.xgboost_probabilities) == 7
        assert result.known_class_prediction in CANONICAL_CLASSES
