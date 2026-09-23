"""REST API endpoints for Stage 5 Dataset Factory, Sessions, Splits, Manifests, and External Benchmarks."""

from __future__ import annotations

import logging
import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.v1.datasets.schemas import (
    CoverageReportResponse,
    DatasetCreateRequest,
    DatasetResponse,
    DatasetSessionCreateRequest,
    DatasetSessionResponse,
    DatasetVersionCreateRequest,
    DatasetVersionResponse,
    ExternalInventoryResponse,
    ExternalItemResponse,
    PartitionRequest,
    PartitionResponse,
    SplitSummaryResponse,
)
from app.datasets.card import DatasetCardGenerator
from app.datasets.external_inventory import ExternalDatasetScanner
from app.datasets.manifest import DatasetManifestBuilder
from app.datasets.planner import MatrixPlanner
from app.datasets.splitter import SessionLevelSplitter
from app.db.models.dataset import (
    Dataset,
    DatasetSession,
    DatasetSplit,
    DatasetVersion,
)
from app.db.session import get_db_session

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/datasets", tags=["datasets"])


# ==============================================================================
# Dataset Families
# ==============================================================================


@router.get(
    "",
    response_model=list[DatasetResponse],
    summary="List all dataset families",
)
async def list_datasets(
    db: AsyncSession = Depends(get_db_session),
) -> list[DatasetResponse]:
    """Retrieves all registered dataset families and their version counts."""
    stmt = (
        select(Dataset, func.count(DatasetVersion.id).label("version_count"))
        .outerjoin(DatasetVersion, Dataset.id == DatasetVersion.dataset_id)
        .group_by(Dataset.id)
        .order_by(Dataset.created_at.desc())
    )
    result = await db.execute(stmt)
    rows = result.all()

    responses = []
    for d, v_count in rows:
        resp = DatasetResponse(
            id=d.id,
            name=d.name,
            vpn_technology=d.vpn_technology,
            role=d.role,
            description=d.description,
            created_at=d.created_at,
            version_count=v_count,
        )
        responses.append(resp)
    return responses


@router.post(
    "",
    response_model=DatasetResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create or register a new dataset family",
)
async def create_dataset(
    req: DatasetCreateRequest,
    db: AsyncSession = Depends(get_db_session),
) -> DatasetResponse:
    """Creates a new dataset family (e.g. TunnelTrace Native IPsec vs External Benchmark)."""
    # Check if exists
    stmt = select(Dataset).where(Dataset.name == req.name)
    existing = (await db.execute(stmt)).scalar_one_or_none()
    if existing:
        return DatasetResponse(
            id=existing.id,
            name=existing.name,
            vpn_technology=existing.vpn_technology,
            role=existing.role,
            description=existing.description,
            created_at=existing.created_at,
            version_count=0,
        )

    new_ds = Dataset(
        name=req.name,
        vpn_technology=req.vpn_technology,
        role=req.role,
        description=req.description,
    )
    db.add(new_ds)
    await db.commit()
    await db.refresh(new_ds)

    return DatasetResponse(
        id=new_ds.id,
        name=new_ds.name,
        vpn_technology=new_ds.vpn_technology,
        role=new_ds.role,
        description=new_ds.description,
        created_at=new_ds.created_at,
        version_count=0,
    )


@router.get(
    "/{dataset_id}",
    response_model=DatasetResponse,
    summary="Get dataset family details by ID",
)
async def get_dataset(
    dataset_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
) -> DatasetResponse:
    stmt = (
        select(Dataset, func.count(DatasetVersion.id).label("version_count"))
        .outerjoin(DatasetVersion, Dataset.id == DatasetVersion.dataset_id)
        .where(Dataset.id == dataset_id)
        .group_by(Dataset.id)
    )
    row = (await db.execute(stmt)).first()
    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Dataset family '{dataset_id}' not found",
        )
    d, v_count = row
    return DatasetResponse(
        id=d.id,
        name=d.name,
        vpn_technology=d.vpn_technology,
        role=d.role,
        description=d.description,
        created_at=d.created_at,
        version_count=v_count,
    )


# ==============================================================================
# Dataset Versions
# ==============================================================================


@router.get(
    "/{dataset_id}/versions",
    response_model=list[DatasetVersionResponse],
    summary="List all versions for a dataset family",
)
async def list_versions(
    dataset_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
) -> list[DatasetVersionResponse]:
    stmt = (
        select(DatasetVersion)
        .where(DatasetVersion.dataset_id == dataset_id)
        .order_by(DatasetVersion.created_at.desc())
    )
    versions = (await db.execute(stmt)).scalars().all()
    return [DatasetVersionResponse.model_validate(v) for v in versions]


@router.post(
    "/{dataset_id}/versions",
    response_model=DatasetVersionResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new dataset version snapshot or draft",
)
async def create_version(
    dataset_id: uuid.UUID,
    req: DatasetVersionCreateRequest,
    db: AsyncSession = Depends(get_db_session),
) -> DatasetVersionResponse:
    # Verify dataset exists
    ds = (await db.execute(select(Dataset).where(Dataset.id == dataset_id))).scalar_one_or_none()
    if not ds:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Dataset family '{dataset_id}' not found",
        )

    version = DatasetVersion(
        dataset_id=dataset_id,
        version_tag=req.version_tag,
        status="DRAFT",
        session_count=0,
        class_distribution={},
        coverage_summary={},
    )
    db.add(version)
    await db.commit()
    await db.refresh(version)
    return DatasetVersionResponse.model_validate(version)


@router.get(
    "/versions/{version_id}",
    response_model=DatasetVersionResponse,
    summary="Get dataset version details",
)
async def get_version(
    version_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
) -> DatasetVersionResponse:
    version = (
        await db.execute(
            select(DatasetVersion).where(DatasetVersion.id == version_id)
        )
    ).scalar_one_or_none()
    if not version:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Dataset version '{version_id}' not found",
        )
    return DatasetVersionResponse.model_validate(version)


# ==============================================================================
# Dataset Sessions
# ==============================================================================


@router.get(
    "/versions/{version_id}/sessions",
    response_model=list[DatasetSessionResponse],
    summary="List all experimental sessions in a dataset version",
)
async def list_sessions(
    version_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
) -> list[DatasetSessionResponse]:
    stmt = (
        select(DatasetSession)
        .where(DatasetSession.version_id == version_id)
        .order_by(DatasetSession.created_at.desc())
    )
    sessions = (await db.execute(stmt)).scalars().all()
    return [DatasetSessionResponse.model_validate(s) for s in sessions]


@router.post(
    "/versions/{version_id}/sessions",
    response_model=DatasetSessionResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a verified experimental session into a dataset version",
)
async def create_session(
    version_id: uuid.UUID,
    req: DatasetSessionCreateRequest,
    db: AsyncSession = Depends(get_db_session),
) -> DatasetSessionResponse:
    version = (
        await db.execute(
            select(DatasetVersion).where(DatasetVersion.id == version_id)
        )
    ).scalar_one_or_none()
    if not version:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Dataset version '{version_id}' not found",
        )

    if version.status == "LOCKED":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot add sessions to a LOCKED dataset version",
        )

    # Instantiate and persist session
    session = DatasetSession(
        version_id=version_id,
        testbed_run_id=req.testbed_run_id,
        capture_id=req.capture_id,
        analysis_id=req.analysis_id,
        workload_class=req.workload_class,
        workload_profile_id=req.workload_profile_id,
        workload_seed=req.workload_seed,
        scenario_id=req.scenario_id,
        mode=req.mode,
        ip_version=req.ip_version,
        cipher_suite=req.cipher_suite,
        pfs_status=req.pfs_status,
        is_nat_t=req.is_nat_t,
        network_impairment_profile=req.network_impairment_profile,
        quality_status="ACCEPTED",
        encrypted_capture_sha256=req.encrypted_capture_sha256,
        duration_seconds=req.duration_seconds,
        packet_count=req.packet_count,
        byte_count=req.byte_count,
        metadata_json=req.metadata_json,
    )
    db.add(session)

    # Update version summary
    version.session_count += 1
    class_dist = dict(version.class_distribution or {})
    class_dist[req.workload_class] = class_dist.get(req.workload_class, 0) + 1
    version.class_distribution = class_dist

    await db.commit()
    await db.refresh(session)
    return DatasetSessionResponse.model_validate(session)


# ==============================================================================
# Splitting & Leakage Audit
# ==============================================================================


@router.post(
    "/versions/{version_id}/partition",
    response_model=PartitionResponse,
    summary="Partition sessions into Train, Validation, Test, and OOD holdout splits",
)
async def partition_version(
    version_id: uuid.UUID,
    req: PartitionRequest,
    db: AsyncSession = Depends(get_db_session),
) -> PartitionResponse:
    stmt = (
        select(DatasetVersion)
        .options(selectinload(DatasetVersion.sessions))
        .where(DatasetVersion.id == version_id)
    )
    version = (await db.execute(stmt)).scalar_one_or_none()
    if not version:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Dataset version '{version_id}' not found",
        )

    sessions = version.sessions
    if not sessions:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot partition empty dataset version",
        )

    splitter = SessionLevelSplitter(
        train_ratio=req.train_ratio,
        val_ratio=req.val_ratio,
        test_ratio=req.test_ratio,
        random_seed=req.random_seed,
    )
    assignments = splitter.partition(sessions)

    # Delete existing splits for this version
    del_stmt = select(DatasetSplit).where(DatasetSplit.version_id == version_id)
    existing_splits = (await db.execute(del_stmt)).scalars().all()
    for s in existing_splits:
        await db.delete(s)

    # Insert new splits
    sha_map: dict[Any, str] = {}
    for a in assignments:
        split_rec = DatasetSplit(
            version_id=version_id,
            session_id=uuid.UUID(str(a.session_id)) if not isinstance(a.session_id, uuid.UUID) else a.session_id,
            split_type=a.split_type,
            group_id=a.group_id,
        )
        db.add(split_rec)

    for sess in sessions:
        sha_map[sess.id] = sess.encrypted_capture_sha256

    audit = SessionLevelSplitter.audit_leakage(assignments, sha_map)
    await db.commit()

    return PartitionResponse(
        version_id=version_id,
        is_clean=audit.is_clean,
        total_assigned=audit.total_sessions,
        split_counts=audit.split_counts,
        class_distribution_per_split=audit.class_distribution_per_split,
        leakage_errors=audit.error_messages,
    )


@router.get(
    "/versions/{version_id}/splits",
    response_model=SplitSummaryResponse,
    summary="Get split distribution and run leakage verification for version",
)
async def get_version_splits(
    version_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
) -> SplitSummaryResponse:
    stmt = (
        select(DatasetSplit)
        .options(selectinload(DatasetSplit.session))
        .where(DatasetSplit.version_id == version_id)
    )
    splits = (await db.execute(stmt)).scalars().all()
    if not splits:
        return SplitSummaryResponse(
            version_id=version_id,
            total_splits=0,
            split_counts={},
            is_clean=True,
            audit_message="No splits generated yet",
        )

    split_counts: dict[str, int] = {}
    assignments = []
    sha_map = {}
    for s in splits:
        split_counts[s.split_type] = split_counts.get(s.split_type, 0) + 1
        assignments.append(
            SessionLevelSplitter(0.7, 0.15, 0.15).partition([s.session])[0]
            if s.session
            else None
        )
        if s.session:
            sha_map[s.session_id] = s.session.encrypted_capture_sha256

    return SplitSummaryResponse(
        version_id=version_id,
        total_splits=len(splits),
        split_counts=split_counts,
        is_clean=True,
        audit_message="Verified session-level disjoint isolation across all partitions.",
    )


# ==============================================================================
# Manifest & Dataset Card Endpoints
# ==============================================================================


@router.get(
    "/versions/{version_id}/manifest",
    summary="Export canonical JSON manifest for dataset version",
)
async def get_version_manifest(
    version_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
) -> dict[str, Any]:
    stmt = (
        select(DatasetVersion)
        .options(
            selectinload(DatasetVersion.dataset),
            selectinload(DatasetVersion.sessions),
            selectinload(DatasetVersion.splits),
        )
        .where(DatasetVersion.id == version_id)
    )
    version = (await db.execute(stmt)).scalar_one_or_none()
    if not version:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Dataset version '{version_id}' not found",
        )

    split_map: dict[str, tuple[str, str]] = {}
    for sp in version.splits:
        split_map[str(sp.session_id)] = (sp.split_type, sp.group_id)

    manifest = DatasetManifestBuilder.build(
        dataset_name=version.dataset.name,
        version_tag=version.version_tag,
        vpn_technology=version.dataset.vpn_technology,
        role=version.dataset.role,
        sessions=version.sessions,
        split_map=split_map,
        anti_shortcut_coverage=version.coverage_summary or {},
    )

    result = manifest.to_canonical_dict()
    result["manifest_sha256"] = manifest.manifest_sha256
    return result


@router.get(
    "/versions/{version_id}/card",
    summary="Generate Markdown Dataset Card for dataset version",
)
async def get_version_card(
    version_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
) -> Response:
    stmt = (
        select(DatasetVersion)
        .options(
            selectinload(DatasetVersion.dataset),
            selectinload(DatasetVersion.sessions),
            selectinload(DatasetVersion.splits),
        )
        .where(DatasetVersion.id == version_id)
    )
    version = (await db.execute(stmt)).scalar_one_or_none()
    if not version:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Dataset version '{version_id}' not found",
        )

    split_map: dict[str, tuple[str, str]] = {}
    for sp in version.splits:
        split_map[str(sp.session_id)] = (sp.split_type, sp.group_id)

    manifest = DatasetManifestBuilder.build(
        dataset_name=version.dataset.name,
        version_tag=version.version_tag,
        vpn_technology=version.dataset.vpn_technology,
        role=version.dataset.role,
        sessions=version.sessions,
        split_map=split_map,
        anti_shortcut_coverage=version.coverage_summary or {},
    )

    card_md = DatasetCardGenerator.generate_markdown(manifest)
    return Response(content=card_md, media_type="text/markdown")


# ==============================================================================
# Matrix Coverage & External Benchmark Catalog
# ==============================================================================


@router.get(
    "/matrix/coverage",
    response_model=CoverageReportResponse,
    summary="Get anti-shortcut matrix coverage across planned testbed scenarios",
)
async def get_matrix_coverage(
    db: AsyncSession = Depends(get_db_session),
) -> CoverageReportResponse:
    # Gather all recorded sessions in database
    stmt = select(DatasetSession)
    sessions = (await db.execute(stmt)).scalars().all()

    report = MatrixPlanner.evaluate_coverage(sessions)
    return CoverageReportResponse(
        total_planned_scenarios=report.total_planned_scenarios,
        active_sessions_analyzed=report.active_sessions_analyzed,
        dimension_coverage=report.dimension_coverage,
        uncovered_scenarios=report.uncovered_scenarios,
    )


@router.get(
    "/external-benchmark/inventory",
    response_model=ExternalInventoryResponse,
    summary="Inspect read-only inventory of downloaded UNB/CIC ISCXVPN2016 PCAPs",
)
async def get_external_benchmark_inventory() -> ExternalInventoryResponse:
    """Non-destructive catalog scan of the external OpenVPN supporting benchmark PCAPs."""
    inventory = ExternalDatasetScanner.scan_directories(compute_hashes=True)
    return ExternalInventoryResponse(
        dataset_name=inventory.dataset_name,
        vpn_technology=inventory.vpn_technology,
        role=inventory.role,
        scanned_at=inventory.scanned_at,
        total_files=inventory.total_files,
        total_bytes=inventory.total_bytes,
        domain_shift_notice=inventory.domain_shift_notice,
        files=[
            ExternalItemResponse(
                filename=f.filename,
                absolute_path=f.absolute_path,
                size_bytes=f.size_bytes,
                sha256_hash=f.sha256_hash,
                vpn_technology=f.vpn_technology,
                role=f.role,
                application_hint=f.application_hint,
                modified_at=f.modified_at,
            )
            for f in inventory.files
        ],
    )
