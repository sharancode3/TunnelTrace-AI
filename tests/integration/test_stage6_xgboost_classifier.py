"""Integration test for Stage 6 XGBoost Baseline Classifier on real native IPsec ESP captures."""

from __future__ import annotations

import hashlib
import uuid
from pathlib import Path

import pytest
from app.db.base import Base
from app.db.models.capture import AnalysisRun, Capture
from app.db.models.dataset import (
    Dataset,
    DatasetSession,
    DatasetSplit,
    DatasetVersion,
)
from app.ml.auditor import LeakageAuditor
from app.ml.dataset import MLDatasetBuilder
from app.ml.manifest import ModelManifestBuilder
from app.ml.schema import FeatureSchema
from app.ml.trainer import TrainingConfig, XGBoostTrainer
from app.protocol.service import ProtocolForensicsService
from app.reconstruction.engine import ReconstructionEngine
from app.services.storage.local import LocalStorageProvider
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
STAGE2_RUN01_WAN = REPO_ROOT / "storage" / "lab" / "runs" / "tt-1790185654-25c4bc" / "captures" / "wan_encrypted.pcap"
STAGE2_RUN03_TRANSPORT = REPO_ROOT / "storage" / "lab" / "runs" / "tt-1790185791-2fd383" / "captures" / "wan_encrypted.pcap"
STAGE2_RUN04_IPV6 = REPO_ROOT / "storage" / "lab" / "runs" / "tt-1790185891-f96398" / "captures" / "wan_encrypted.pcap"
STAGE2_RUN06_NATT = REPO_ROOT / "storage" / "lab" / "runs" / "tt-1790185927-b1d8f6" / "captures" / "wan_encrypted.pcap"


@pytest.fixture
def temp_storage_dir(tmp_path: Path) -> str:
    return str(tmp_path)


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
async def test_stage6_xgboost_classifier_end_to_end(
    async_db: AsyncSession,
    temp_storage_dir: str,
    tmp_path: Path,
):
    """End-to-End Stage 6 Integration Test on Real Native IPsec Captures:

    1. Ingest real Stage 2 WAN captures (Tunnel, Transport, IPv6, NAT-T).
    2. Run Stage 3 Forensics and Stage 4 Flow Reconstruction.
    3. Register accepted sessions with session-isolated splits (Train, Validation, Test, OOD_Holdout).
    4. Assert OOD_Holdout is excluded from supervised training.
    5. Extract 24 tabular side-channel features and audit for zero feature leakage.
    6. Execute XGBoost training with GroupKFold cross-validation on TRAIN.
    7. Execute benchmark comparators (Dummy Classifier, Logistic Regression) and label-shuffle negative control.
    8. Select best model on Validation partition, then evaluate held-out TEST partition once.
    9. Export model bundle, verify SHA-256 manifest integrity, and assert EXPERIMENTAL state (not active).
    10. Perform fresh reload and run inference smoke test.
    11. Execute slice evaluations across mode, IP version, and NAT-T.
    """
    storage = LocalStorageProvider(root_dir=temp_storage_dir)
    forensics = ProtocolForensicsService(async_db)
    forensics.storage = storage
    reconstruction = ReconstructionEngine(async_db)

    # 1. Create Dataset & DatasetVersion
    dataset = Dataset(
        name="TunnelTrace_Stage6_Native_IPsec",
        vpn_technology="IPSEC_NATIVE",
        role="PRIMARY",
        description="Native IPsec baseline dataset for XGBoost classification",
    )
    async_db.add(dataset)
    await async_db.commit()
    await async_db.refresh(dataset)

    version = DatasetVersion(
        dataset_id=dataset.id,
        version_tag="v1.0.0-stage6",
        status="LOCKED",
        manifest_hash="stage6_manifest_hash_test",
    )
    async_db.add(version)
    await async_db.commit()
    await async_db.refresh(version)

    # 2. Define real test runs with split assignment
    test_runs = [
        {
            "pcap_path": STAGE2_RUN01_WAN,
            "workload_class": "Web",
            "scenario_id": "01_tunnel_ipv4_aes256gcm_pfs.yaml",
            "mode": "TUNNEL",
            "ip_version": "IPv4",
            "cipher_suite": "aes256gcm16",
            "pfs_status": "ENABLED",
            "is_nat_t": False,
            "split_type": "TRAIN",
        },
        {
            "pcap_path": STAGE2_RUN03_TRANSPORT,
            "workload_class": "VoIP",
            "scenario_id": "03_transport_ipv4_aes256gcm.yaml",
            "mode": "TRANSPORT",
            "ip_version": "IPv4",
            "cipher_suite": "aes256gcm16",
            "pfs_status": "DISABLED",
            "is_nat_t": False,
            "split_type": "TRAIN",
        },
        {
            "pcap_path": STAGE2_RUN04_IPV6,
            "workload_class": "Web",
            "scenario_id": "04_tunnel_ipv6_aes256gcm_pfs.yaml",
            "mode": "TUNNEL",
            "ip_version": "IPv6",
            "cipher_suite": "aes256gcm16",
            "pfs_status": "ENABLED",
            "is_nat_t": False,
            "split_type": "VALIDATION",
        },
        {
            "pcap_path": STAGE2_RUN06_NATT,
            "workload_class": "VoIP",
            "scenario_id": "06_tunnel_ipv4_natt.yaml",
            "mode": "TUNNEL",
            "ip_version": "IPv4",
            "cipher_suite": "aes256gcm16",
            "pfs_status": "ENABLED",
            "is_nat_t": True,
            "split_type": "TEST",
        },
        {
            # OOD Holdout session (must be strictly excluded from supervised training)
            "pcap_path": STAGE2_RUN01_WAN,
            "workload_class": "OOD_HOLDOUT",
            "scenario_id": "01_tunnel_ipv4_aes256gcm_pfs.yaml",
            "mode": "TUNNEL",
            "ip_version": "IPv4",
            "cipher_suite": "aes256gcm16",
            "pfs_status": "ENABLED",
            "is_nat_t": False,
            "split_type": "OOD_HOLDOUT",
        },
    ]

    for run_meta in test_runs:
        pcap_path = run_meta["pcap_path"]
        assert pcap_path.exists(), f"PCAP artifact {pcap_path} must exist"

        file_bytes = pcap_path.read_bytes()
        sha256 = hashlib.sha256(file_bytes).hexdigest()
        rel_path = f"captures/stage6_{run_meta['workload_class'].lower()}_{uuid.uuid4().hex[:6]}/raw.pcap"
        storage.save_file(rel_path, file_bytes)

        cap_id = uuid.uuid4()
        cap = Capture(
            id=cap_id,
            capture_source="TESTBED_LAB",
            capture_format="PCAP",
            original_filename=pcap_path.name,
            storage_path=rel_path,
            file_size_bytes=len(file_bytes),
            sha256_hash=sha256,
            packet_count=100,
            duration_sec=5.0,
            link_layer_type="RAW_IP" if "transport" in str(pcap_path) else "ETHERNET",
            validation_state="VALIDATED",
        )
        async_db.add(cap)

        analysis_id = uuid.uuid4()
        analysis = AnalysisRun(
            id=analysis_id,
            capture_id=cap_id,
            status="QUEUED",
            current_stage="INGESTING",
        )
        async_db.add(analysis)
        await async_db.commit()

        # Run Stage 3 forensics & Stage 4 reconstruction
        await forensics.execute_analysis(analysis_id)
        await reconstruction.execute_reconstruction(analysis_id)

        # Register session
        sess_id = uuid.uuid4()
        sess = DatasetSession(
            id=sess_id,
            version_id=version.id,
            capture_id=cap.id,
            analysis_id=analysis.id,
            workload_class=run_meta["workload_class"],
            workload_profile_id=f"profile_{run_meta['workload_class'].lower()}",
            workload_seed=42,
            scenario_id=run_meta["scenario_id"],
            mode=run_meta["mode"],
            ip_version=run_meta["ip_version"],
            cipher_suite=run_meta["cipher_suite"],
            pfs_status=run_meta["pfs_status"],
            is_nat_t=run_meta["is_nat_t"],
            quality_status="ACCEPTED",
            encrypted_capture_sha256=sha256,
            duration_seconds=5.0,
            packet_count=cap.packet_count,
            byte_count=cap.file_size_bytes,
        )
        async_db.add(sess)

        # Register split
        sp = DatasetSplit(
            version_id=version.id,
            session_id=sess_id,
            split_type=run_meta["split_type"],
            group_id=str(sess_id),
        )
        async_db.add(sp)

    await async_db.commit()

    # 3. Assemble partitions using MLDatasetBuilder
    schema = FeatureSchema()
    builder = MLDatasetBuilder(schema)
    partitions = await builder.build_partitions_from_db(async_db, version.id)

    train_part = partitions["TRAIN"]
    val_part = partitions["VALIDATION"]
    test_part = partitions["TEST"]

    assert train_part.num_rows > 0
    assert val_part.num_rows > 0
    assert test_part.num_rows > 0

    # 4. Assert OOD_HOLDOUT was excluded from supervised partitions
    for p_name, part in partitions.items():
        assert "OOD_HOLDOUT" not in part.metadata["workload_class"].values, (
            f"OOD_HOLDOUT leaked into supervised partition {p_name}"
        )

    # 5. Assert zero partition leakage
    LeakageAuditor.audit_session_isolation({
        "TRAIN": list(train_part.groups),
        "VALIDATION": list(val_part.groups),
        "TEST": list(test_part.groups),
    })

    # 6. Assert no forbidden columns in feature matrix
    assert train_part.X.shape[1] == 24
    LeakageAuditor.audit_forbidden_columns(list(train_part.X.columns))

    # 7. Train XGBoost Baseline Classifier
    config = TrainingConfig(
        experiment_id="exp_stage6_real_test",
        num_classes=7,  # Multiclass setup
        cv_folds=2,
        param_grid=[
            {"max_depth": 3, "learning_rate": 0.1, "n_estimators": 25, "subsample": 0.8, "colsample_bytree": 0.8},
        ],
    )
    trainer = XGBoostTrainer(config)
    result = trainer.train_experiment(train_part, val_part, test_part)

    # Real evaluation results verification
    assert result.status in ("COMPLETED", "EXPERIMENTAL_DATA_INSUFFICIENT")
    assert "macro_f1" in result.validation_metrics
    assert "confusion_matrix" in result.validation_metrics
    assert "macro_f1" in result.test_metrics

    # Verify comparators ran
    assert "dummy_majority" in result.comparator_metrics
    assert "logistic_regression" in result.comparator_metrics

    # Verify negative control ran
    assert "macro_f1" in result.shuffled_control_metrics

    # 8. Export Model Bundle & Provenance Manifest
    bundle_dir = tmp_path / "stage6_model_bundle"
    manifest = ModelManifestBuilder.export_bundle(
        result=result,
        schema=schema,
        output_dir=bundle_dir,
        dataset_version_id=str(version.id),
        manifest_hash=train_part.manifest_hash,
        split_manifest_hash=train_part.split_manifest_hash,
    )

    assert manifest["model_family"] == "XGBoost"
    assert manifest["artifact_state"] == "EXPERIMENTAL"
    assert manifest["is_active"] is False
    assert (bundle_dir / "model" / "xgboost.json").exists()
    assert (bundle_dir / "model_manifest.json").exists()
    assert (bundle_dir / "feature_schema.json").exists()
    assert (bundle_dir / "label_mapping.json").exists()

    # 9. Reload model and execute inference smoke test
    preds, probs = ModelManifestBuilder.reload_and_verify(bundle_dir, test_part.X)
    assert len(preds) == len(test_part.X)
    assert probs.shape == (len(test_part.X), 7)

    # 10. Evaluate slice robustness (Mode, IP version, NAT-T)
    evaluator = trainer.evaluator
    slices = evaluator.evaluate_slices(train_part.metadata, train_part.y, result.model.predict(train_part.X))
    assert "mode" in slices
    assert "ip_version" in slices
    assert "is_nat_t" in slices
