"""Model Bundle Packaging, Cryptographic Integrity Verification, and Loading."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
import torch

from app.ml.anomaly import AnomalyFeatureSchema, IsolationForestAnomalyDetector
from app.ml.calibration import CalibrationConfig, ProbabilityCalibrator
from app.ml.cnn.model import Lightweight1DCNN
from app.ml.cnn.trainer import CNNTrainer
from app.ml.dataset import CANONICAL_CLASSES, INT_TO_LABEL, LABEL_TO_INT
from app.ml.explainability import TreeSHAPExplainer
from app.ml.fusion import FusionConfig, MultimodalFusionEngine
from app.ml.ood import OODConfig, OODDetector
from app.ml.preprocessing import FeaturePreprocessor
from app.ml.schema import FeatureSchema
from app.ml.sequence_schema import SequenceSchema
from app.ml.trainer import XGBoostBaselineModel


class ArtifactIntegrityError(Exception):
    """Raised when an artifact checksum does not match its manifest or is corrupted."""


@dataclass
class ModelBundle:
    """Encapsulates the complete, loaded Stage 7 multimodal inference bundle."""

    bundle_id: str
    bundle_version: str
    feature_schema: FeatureSchema
    sequence_schema: SequenceSchema
    anomaly_schema: AnomalyFeatureSchema
    label_mapping: dict[str, Any]
    preprocessor: FeaturePreprocessor
    xgb_model: XGBoostBaselineModel
    cnn_model: Any  # TorchScript module or Lightweight1DCNN
    fusion_engine: MultimodalFusionEngine
    calibrator: ProbabilityCalibrator
    ood_detector: OODDetector
    explainer: TreeSHAPExplainer
    anomaly_detector: IsolationForestAnomalyDetector
    manifest: dict[str, Any]


class ModelBundleBuilder:
    """Constructs and exports the unified Stage 7 model bundle with SHA-256 manifests."""

    @staticmethod
    def _sha256_file(path: Path) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest()

    def build_and_export(
        self,
        output_dir: Path,
        xgb_model: XGBoostBaselineModel,
        cnn_model: Lightweight1DCNN,
        preprocessor: FeaturePreprocessor,
        feature_schema: FeatureSchema,
        sequence_schema: SequenceSchema,
        anomaly_schema: AnomalyFeatureSchema,
        fusion_config: FusionConfig,
        calibration_config: CalibrationConfig,
        ood_config: OODConfig,
        anomaly_detector: IsolationForestAnomalyDetector,
        dataset_manifest_hash: str = "STAGE7_DATASET_HASH",
        split_manifest_hash: str = "STAGE7_SPLIT_HASH",
        bundle_id: str = "stage7_ensemble_v1",
        bundle_version: str = "v1.0.0-ensemble",
        artifact_state: str = "EXPERIMENTAL",
    ) -> dict[str, Any]:
        """Export all bundle components to disk and write the authoritative model_manifest.json."""
        output_dir.mkdir(parents=True, exist_ok=True)

        # 1. Feature Schema
        feat_schema_path = output_dir / "feature_schema.json"
        with open(feat_schema_path, "w", encoding="utf-8") as f:
            f.write(feature_schema.to_json())

        # 2. Sequence Schema
        seq_schema_path = output_dir / "sequence_schema.json"
        with open(seq_schema_path, "w", encoding="utf-8") as f:
            f.write(sequence_schema.to_json())

        # 3. Anomaly Schema
        anom_schema_path = output_dir / "anomaly_schema.json"
        with open(anom_schema_path, "w", encoding="utf-8") as f:
            f.write(anomaly_schema.to_json())

        # 4. Label Mapping
        label_map_path = output_dir / "label_mapping.json"
        label_data = {
            "version": "1.0",
            "num_classes": len(CANONICAL_CLASSES),
            "classes": CANONICAL_CLASSES,
            "label_to_int": LABEL_TO_INT,
            "int_to_label": {str(k): v for k, v in INT_TO_LABEL.items()},
        }
        with open(label_map_path, "w", encoding="utf-8") as f:
            json.dump(label_data, f, indent=2)

        # 5. Preprocessor
        prep_path = output_dir / "preprocessor.json"
        preprocessor.save_params(prep_path)

        # 6. XGBoost Baseline Model
        xgb_dir = output_dir / "xgboost"
        xgb_dir.mkdir(parents=True, exist_ok=True)
        xgb_path = xgb_dir / "model.json"
        xgb_model.save_model(xgb_path)

        # 7. CNN TorchScript Model
        cnn_dir = output_dir / "cnn"
        cnn_dir.mkdir(parents=True, exist_ok=True)
        cnn_path = cnn_dir / "model.pt"
        trainer = CNNTrainer(schema=sequence_schema)
        trainer.export_torchscript(cnn_model, cnn_path)

        # 8. Fusion Config
        fusion_path = output_dir / "fusion_config.json"
        with open(fusion_path, "w", encoding="utf-8") as f:
            f.write(fusion_config.to_json())

        # 9. Calibration Config
        calib_path = output_dir / "calibration_config.json"
        with open(calib_path, "w", encoding="utf-8") as f:
            f.write(calibration_config.to_json())

        # 10. OOD Config
        ood_path = output_dir / "ood_config.json"
        with open(ood_path, "w", encoding="utf-8") as f:
            f.write(ood_config.to_json())

        # 11. Anomaly Detector
        anom_path = output_dir / "anomaly_model.json"
        anomaly_detector.save_json(anom_path)

        # Compute SHA-256 for all exported files
        files_manifest = {
            "feature_schema.json": self._sha256_file(feat_schema_path),
            "sequence_schema.json": self._sha256_file(seq_schema_path),
            "anomaly_schema.json": self._sha256_file(anom_schema_path),
            "label_mapping.json": self._sha256_file(label_map_path),
            "preprocessor.json": self._sha256_file(prep_path),
            "xgboost/model.json": self._sha256_file(xgb_path),
            "cnn/model.pt": self._sha256_file(cnn_path),
            "fusion_config.json": self._sha256_file(fusion_path),
            "calibration_config.json": self._sha256_file(calib_path),
            "ood_config.json": self._sha256_file(ood_path),
            "anomaly_model.json": self._sha256_file(anom_path),
        }

        manifest = {
            "bundle_id": bundle_id,
            "bundle_version": bundle_version,
            "artifact_state": artifact_state,
            "is_active": False,  # Strict Non-Negotiable: Never automatically active
            "created_at": datetime.now(timezone.utc).isoformat(),
            "target_device": "cpu",
            "frameworks": {
                "torch": str(torch.__version__),
                "xgboost": "3.2.0",
                "scikit_learn": "1.7.2",
            },
            "dataset_manifest_hash": dataset_manifest_hash,
            "split_manifest_hash": split_manifest_hash,
            "feature_schema_hash": feature_schema.schema_hash(),
            "sequence_schema_hash": sequence_schema.schema_hash(),
            "anomaly_schema_hash": anomaly_schema.schema_hash(),
            "fusion_config_hash": fusion_config.config_hash(),
            "calibration_config_hash": calibration_config.config_hash(),
            "ood_config_hash": ood_config.config_hash(),
            "files": files_manifest,
        }

        manifest_path = output_dir / "model_manifest.json"
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2, sort_keys=True)

        return manifest


class ModelBundleLoader:
    """Canonical loader for Stage 7 Model Bundle with strict SHA-256 integrity verification."""

    @staticmethod
    def _sha256_file(path: Path) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest()

    @classmethod
    def load_bundle(cls, bundle_dir: Path, verify_hashes: bool = True) -> ModelBundle:
        """Load and verify a complete Stage 7 model bundle from disk."""
        manifest_path = bundle_dir / "model_manifest.json"
        if not manifest_path.exists():
            raise FileNotFoundError(f"Model manifest not found: {manifest_path}")

        with open(manifest_path, encoding="utf-8") as f:
            manifest = json.load(f)

        # 1. Verify SHA-256 hashes of all component files
        if verify_hashes:
            files_dict = manifest.get("files", {})
            for rel_path, expected_hash in files_dict.items():
                p = bundle_dir / rel_path
                if not p.exists():
                    raise ArtifactIntegrityError(f"Missing bundle artifact file: {rel_path}")
                actual_hash = cls._sha256_file(p)
                if actual_hash != expected_hash:
                    raise ArtifactIntegrityError(
                        f"Checksum mismatch for {rel_path}: expected {expected_hash}, got {actual_hash}"
                    )

        # 2. Load Schemas & Labels
        with open(bundle_dir / "feature_schema.json", encoding="utf-8") as f:
            feat_schema = FeatureSchema.from_dict(json.load(f))

        with open(bundle_dir / "sequence_schema.json", encoding="utf-8") as f:
            seq_schema = SequenceSchema.from_dict(json.load(f))

        with open(bundle_dir / "anomaly_schema.json", encoding="utf-8") as f:
            anom_schema = AnomalyFeatureSchema(**json.load(f))

        with open(bundle_dir / "label_mapping.json", encoding="utf-8") as f:
            label_mapping = json.load(f)

        # 3. Load Preprocessor
        preprocessor = FeaturePreprocessor.from_params_file(bundle_dir / "preprocessor.json")

        # 4. Load Models
        xgb_model = XGBoostBaselineModel()
        xgb_model.load_model(bundle_dir / "xgboost" / "model.json")

        cnn_path = bundle_dir / "cnn" / "model.pt"
        cnn_model = torch.jit.load(str(cnn_path), map_location=torch.device("cpu"))
        cnn_model.eval()

        # 5. Load Configurations & Subsystems
        with open(bundle_dir / "fusion_config.json", encoding="utf-8") as f:
            fusion_config = FusionConfig.from_dict(json.load(f))
        fusion_engine = MultimodalFusionEngine(config=fusion_config)

        with open(bundle_dir / "calibration_config.json", encoding="utf-8") as f:
            calib_config = CalibrationConfig.from_dict(json.load(f))
        calibrator = ProbabilityCalibrator(config=calib_config)

        with open(bundle_dir / "ood_config.json", encoding="utf-8") as f:
            ood_config = OODConfig.from_dict(json.load(f))
        ood_detector = OODDetector(config=ood_config)

        explainer = TreeSHAPExplainer(
            xgb_booster=getattr(xgb_model, "inner_model", xgb_model) or xgb_model,
            feature_names=[f.name for f in feat_schema.features],
            classes=CANONICAL_CLASSES,
        )

        anomaly_detector = IsolationForestAnomalyDetector.load_json(
            bundle_dir / "anomaly_model.json",
            schema=anom_schema,
        )

        bundle = ModelBundle(
            bundle_id=manifest.get("bundle_id", "stage7_ensemble"),
            bundle_version=manifest.get("bundle_version", "v1.0.0"),
            feature_schema=feat_schema,
            sequence_schema=seq_schema,
            anomaly_schema=anom_schema,
            label_mapping=label_mapping,
            preprocessor=preprocessor,
            xgb_model=xgb_model,
            cnn_model=cnn_model,
            fusion_engine=fusion_engine,
            calibrator=calibrator,
            ood_detector=ood_detector,
            explainer=explainer,
            anomaly_detector=anomaly_detector,
            manifest=manifest,
        )

        # Smoke Test
        cls._run_smoke_test(bundle)
        return bundle

    @staticmethod
    def _run_smoke_test(bundle: ModelBundle) -> None:
        """Run synthetic smoke test ensuring all components function together cleanly."""
        num_feats = len(bundle.feature_schema.features)
        x_dummy = np.ones((1, num_feats), dtype=np.float32)
        x_trans = bundle.preprocessor.transform(x_dummy)
        p_xgb = bundle.xgb_model.predict_proba(x_trans)

        seq_horizon = bundle.sequence_schema.default_horizon
        t_dummy = torch.zeros((1, 3, seq_horizon), dtype=torch.float32)
        m_dummy = torch.ones((1, seq_horizon), dtype=torch.bool)
        with torch.no_grad():
            p_cnn = bundle.cnn_model.predict_proba(t_dummy, m_dummy).cpu().numpy()

        p_fused = bundle.fusion_engine.fuse(p_xgb, p_cnn)
        p_cal = bundle.calibrator.calibrate(p_fused)

        ood_dec = bundle.ood_detector.evaluate_flow(p_cal[0])
        anom_dec = bundle.anomaly_detector.evaluate_flow(dict.fromkeys(bundle.anomaly_schema.features, 1.0))

        assert p_cal.shape == (1, 7), f"Expected shape (1, 7), got {p_cal.shape}"
        assert abs(float(np.sum(p_cal[0])) - 1.0) < 1e-4, "Calibrated probabilities must sum to 1.0"
        assert ood_dec.status in ("KNOWN_ACCEPTED", "UNKNOWN_UNSEEN", "OUT_OF_DISTRIBUTION")
        assert anom_dec.status in ("STATISTICAL_BEHAVIORAL_ANOMALY", "NORMAL_BEHAVIOR")
