"""Typed Command-Line Interface for Stage 6 ML Workflows."""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import get_settings
from app.db.models.dataset import DatasetSession, DatasetSplit, DatasetVersion
from app.ml.auditor import LeakageAuditor
from app.ml.dataset import MLDatasetBuilder
from app.ml.manifest import ModelManifestBuilder
from app.ml.schema import FeatureSchema
from app.ml.trainer import TrainingConfig, XGBoostTrainer


def get_async_session_factory():
    settings = get_settings()
    engine = create_async_engine(settings.DATABASE_URL, echo=False)
    return async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)


async def inspect_dataset(version_id: str) -> dict[str, Any]:
    """Inspect dataset records, classes, and split integrity."""
    session_factory = get_async_session_factory()
    async with session_factory() as session:
        # Check version
        v_res = await session.execute(select(DatasetVersion).where(DatasetVersion.id == version_id))
        version = v_res.scalar_one_or_none()
        if not version:
            print(f"[!] DatasetVersion '{version_id}' not found.")
            return {"error": "VERSION_NOT_FOUND"}

        # Sessions count by class
        s_res = await session.execute(
            select(DatasetSession).where(
                DatasetSession.version_id == version_id,
                DatasetSession.quality_status == "ACCEPTED",
            )
        )
        sessions = s_res.scalars().all()
        class_counts = {}
        for s in sessions:
            class_counts[s.workload_class] = class_counts.get(s.workload_class, 0) + 1

        # Splits
        sp_res = await session.execute(select(DatasetSplit).where(DatasetSplit.version_id == version_id))
        splits = sp_res.scalars().all()
        split_counts = {}
        split_map: dict[str, list[str]] = {}
        for sp in splits:
            stype = sp.split_type.upper()
            split_counts[stype] = split_counts.get(stype, 0) + 1
            split_map.setdefault(stype, []).append(str(sp.session_id))

        # Check leakage
        leakage_status = "SAFE"
        try:
            LeakageAuditor.audit_session_isolation(split_map)
        except Exception as e:
            leakage_status = f"LEAKAGE_DETECTED: {e}"

        report = {
            "dataset_version_id": str(version.id),
            "version_tag": version.version_tag,
            "manifest_hash": version.manifest_hash,
            "total_accepted_sessions": len(sessions),
            "class_distribution": class_counts,
            "splits": split_counts,
            "session_isolation_status": leakage_status,
        }
        print(json.dumps(report, indent=2))
        return report


async def train_baseline_cli(
    version_id: str,
    output_dir: Path,
    seed: int = 42,
    cv_folds: int = 3,
) -> None:
    """Train XGBoost baseline from database dataset partitions."""
    print(f"[*] Starting XGBoost Baseline Training for DatasetVersion: {version_id}")
    session_factory = get_async_session_factory()
    schema = FeatureSchema()
    builder = MLDatasetBuilder(schema)

    async with session_factory() as session:
        print("[*] Extracting features and assembling session-isolated partitions...")
        partitions = await builder.build_partitions_from_db(session, version_id)

    train_part = partitions.get("TRAIN")
    val_part = partitions.get("VALIDATION")
    test_part = partitions.get("TEST")

    if not train_part or train_part.num_rows == 0:
        print("[!] Aborting: TRAIN partition has 0 samples.")
        return

    print(f"[*] TRAIN rows: {train_part.num_rows}, groups: {train_part.session_counts}")
    print(f"[*] VALIDATION rows: {val_part.num_rows if val_part else 0}")
    print(f"[*] TEST rows: {test_part.num_rows if test_part else 0}")

    config = TrainingConfig(
        random_seed=seed,
        cv_folds=cv_folds,
    )
    trainer = XGBoostTrainer(config)

    print("[*] Training XGBoost classifier with GroupKFold cross-validation...")
    result = trainer.train_experiment(train_part, val_part, test_part)

    print(f"[*] Experiment complete: status={result.status}, duration={result.duration_seconds:.2f}s")
    print(f"[*] Best Candidate Params: {result.best_params}")
    print(f"[*] Validation Macro-F1: {result.validation_metrics.get('macro_f1', 0.0):.4f}")
    if result.test_metrics:
        print(f"[*] Held-out TEST Macro-F1: {result.test_metrics.get('macro_f1', 0.0):.4f}")

    print(f"[*] Packaging artifact bundle to: {output_dir}")
    manifest = ModelManifestBuilder.export_bundle(
        result=result,
        schema=schema,
        output_dir=output_dir,
        dataset_version_id=version_id,
        manifest_hash=train_part.manifest_hash,
        split_manifest_hash=train_part.split_manifest_hash,
    )
    print(f"[*] Bundle exported successfully. Manifest SHA-256: {manifest.get('manifest_sha256')}")


def main() -> None:
    parser = argparse.ArgumentParser(description="TunnelTrace AI ML CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # inspect-dataset
    inspect_parser = subparsers.add_parser("inspect-dataset", help="Inspect dataset sessions and splits")
    inspect_parser.add_argument("--version-id", required=True, help="DatasetVersion UUID")

    # train-baseline
    train_parser = subparsers.add_parser("train-baseline", help="Train XGBoost baseline classifier")
    train_parser.add_argument("--version-id", required=True, help="DatasetVersion UUID")
    train_parser.add_argument("--output-dir", default="storage/models/experimental/xgboost_baseline", help="Output path")
    train_parser.add_argument("--seed", type=int, default=42, help="Random seed")
    train_parser.add_argument("--cv-folds", type=int, default=3, help="GroupKFold folds")

    args = parser.parse_args()

    if args.command == "inspect-dataset":
        asyncio.run(inspect_dataset(args.version_id))
    elif args.command == "train-baseline":
        asyncio.run(
            train_baseline_cli(
                version_id=args.version_id,
                output_dir=Path(args.output_dir),
                seed=args.seed,
                cv_folds=args.cv_folds,
            )
        )


if __name__ == "__main__":
    main()
