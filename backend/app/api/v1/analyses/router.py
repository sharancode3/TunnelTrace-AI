"""REST API endpoints for asynchronous protocol analysis execution and summary inspection."""

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, Depends, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.schemas import AnalysisRunResponseDTO, CreateAnalysisRequestDTO
from app.core.errors import AnalysisNotFoundError, CaptureNotFoundError
from app.db.models.capture import AnalysisRun, Capture
from app.db.session import get_db_session
from app.protocol.normalization.models import ProtocolSummaryDTO
from app.protocol.service import ProtocolForensicsService

router = APIRouter(prefix="/analyses", tags=["analyses"])


@router.post(
    "",
    response_model=AnalysisRunResponseDTO,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Enqueue protocol analysis for an ingested capture",
)
async def create_analysis(
    req: CreateAnalysisRequestDTO,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db_session),
) -> AnalysisRunResponseDTO:
    """Register an asynchronous protocol forensics run targeting an immutable capture."""
    res_cap = await db.execute(select(Capture).where(Capture.id == req.capture_id))
    capture = res_cap.scalar_one_or_none()
    if not capture:
        raise CaptureNotFoundError(str(req.capture_id))

    analysis_id = uuid.uuid4()
    analysis = AnalysisRun(
        id=analysis_id,
        capture_id=capture.id,
        status="QUEUED",
        current_stage="INGESTING",
        parser_engine="tshark",
        parser_version="unknown",
        schema_version="1.0.0",
        created_at=datetime.now(timezone.utc),
    )
    db.add(analysis)
    await db.commit()
    await db.refresh(analysis)

    # Execute deterministic analysis
    service = ProtocolForensicsService(db)
    await service.execute_analysis(analysis.id)

    # Reload fresh state
    res_updated = await db.execute(select(AnalysisRun).where(AnalysisRun.id == analysis.id))
    analysis = res_updated.scalar_one()

    return AnalysisRunResponseDTO(
        analysis_id=analysis.id,
        capture_id=analysis.capture_id,
        status=analysis.status,
        current_stage=analysis.current_stage,
        parser_engine=analysis.parser_engine,
        parser_version=analysis.parser_version,
        schema_version=analysis.schema_version,
        started_at=analysis.started_at,
        completed_at=analysis.completed_at,
        error_code=analysis.error_code,
        error_message=analysis.error_message,
        created_at=analysis.created_at,
    )


@router.get(
    "/{analysis_id}",
    response_model=AnalysisRunResponseDTO,
    summary="Retrieve analysis execution status and counters",
)
async def get_analysis(
    analysis_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
) -> AnalysisRunResponseDTO:
    """Retrieve operational state and parser version of an analysis run."""
    res = await db.execute(select(AnalysisRun).where(AnalysisRun.id == analysis_id))
    analysis = res.scalar_one_or_none()
    if not analysis:
        raise AnalysisNotFoundError(str(analysis_id))

    return AnalysisRunResponseDTO(
        analysis_id=analysis.id,
        capture_id=analysis.capture_id,
        status=analysis.status,
        current_stage=analysis.current_stage,
        parser_engine=analysis.parser_engine,
        parser_version=analysis.parser_version,
        schema_version=analysis.schema_version,
        started_at=analysis.started_at,
        completed_at=analysis.completed_at,
        error_code=analysis.error_code,
        error_message=analysis.error_message,
        created_at=analysis.created_at,
    )


@router.get(
    "/{analysis_id}/protocol",
    response_model=ProtocolSummaryDTO,
    summary="Retrieve normalized IPsec protocol observations summary",
)
async def get_protocol_summary(
    analysis_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
) -> ProtocolSummaryDTO:
    """Retrieve verified protocol facts, observed transforms, SPIs, and exchange types."""
    service = ProtocolForensicsService(db)
    return await service.get_protocol_summary(analysis_id)
