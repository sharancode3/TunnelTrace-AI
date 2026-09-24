"""FastAPI router for IKE/IPsec Negotiation Assessment (IKE-scan & Concordance)."""

from __future__ import annotations

import uuid
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.protocol.ike_schemas import (
    IkeAssessmentJobCreateRequest,
    IkeAssessmentJobResponse,
    IkeAssessmentStatusResponse,
    IkeConcordanceResponse,
)
from app.core.config import settings
from app.db.models.ike_assessment import IkeConcordanceRecord
from app.db.session import get_db_session
from app.discovery.validator import AuthorizationError, ScopeValidationError
from app.protocol.ike_scan.profiles import SCAN_PROFILES
from app.protocol.ike_scan.runner import detect_ike_scan_binary
from app.protocol.ike_scan.service import IkeAssessmentService

router = APIRouter(prefix="/ike-assessment", tags=["IKE Negotiation Assessment"])


@router.get(
    "/status",
    response_model=IkeAssessmentStatusResponse,
    summary="Check IKE assessment subsystem status, limits, and tool availability",
)
async def get_ike_assessment_status() -> IkeAssessmentStatusResponse:
    """Retrieve operational status, tool availability, and allowlisted profiles for IKE assessment."""
    bin_info = detect_ike_scan_binary()
    profiles_meta = [
        {
            "name": p.profile.value,
            "description": p.description,
            "ike_version": p.ike_version,
            "is_experimental": p.is_experimental,
            "default_port": p.default_port,
            "permitted_ports": list(p.permitted_ports),
            "retries": p.retries,
            "timeout_ms": p.timeout_ms,
        }
        for p in SCAN_PROFILES.values()
    ]

    return IkeAssessmentStatusResponse(
        enabled=settings.IKE_ASSESSMENT_ENABLED,
        ike_scan_available=bin_info.is_available,
        ike_scan_version=bin_info.version,
        ike_scan_path=bin_info.path,
        timeout_sec=settings.IKE_SCAN_TIMEOUT_SEC,
        allow_experimental_v2=settings.IKE_SCAN_ALLOW_EXPERIMENTAL_V2,
        available_profiles=profiles_meta,
    )


@router.post(
    "/jobs",
    response_model=IkeAssessmentJobResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create and execute an authorized IKE negotiation probe job",
)
async def create_ike_assessment_job(
    request: IkeAssessmentJobCreateRequest,
    db: AsyncSession = Depends(get_db_session),
) -> IkeAssessmentJobResponse:
    """Submit an authorized, strictly bounded IKE probe against an exact IP target."""
    service = IkeAssessmentService(db)
    try:
        job = await service.create_and_execute_job(
            job_name=request.job_name,
            operator_id=request.operator_id,
            authorization_reference=request.authorization_reference,
            authorization_attestation=request.authorization_attestation,
            profile_name=request.profile_name,
            target=request.target,
            port=request.port,
            analysis_id=request.analysis_id,
        )
        return IkeAssessmentJobResponse.model_validate(job)
    except AuthorizationError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Authorization rejected: {e}",
        )
    except ScopeValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Scope validation failed: {e}",
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@router.get(
    "/jobs",
    response_model=list[IkeAssessmentJobResponse],
    summary="List IKE assessment jobs",
)
async def list_ike_assessment_jobs(
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db_session),
) -> list[IkeAssessmentJobResponse]:
    """Retrieve history of audited IKE probe jobs."""
    service = IkeAssessmentService(db)
    jobs = await service.list_jobs(limit=limit, offset=offset)
    return [IkeAssessmentJobResponse.model_validate(j) for j in jobs]


@router.get(
    "/jobs/{job_id}",
    response_model=IkeAssessmentJobResponse,
    summary="Get IKE assessment job details and results",
)
async def get_ike_assessment_job(
    job_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
) -> IkeAssessmentJobResponse:
    """Retrieve job execution record and normalized probe results."""
    service = IkeAssessmentService(db)
    job = await service.get_job(job_id)
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Job not found")
    return IkeAssessmentJobResponse.model_validate(job)


@router.get(
    "/analyses/{analysis_id}/concordance",
    response_model=list[IkeConcordanceResponse],
    summary="Get IKE evidence concordance records for an analysis run",
)
async def get_analysis_concordance(
    analysis_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
) -> list[IkeConcordanceResponse]:
    """Retrieve multi-source concordance (passive TShark vs active IKE-scan) for an analysis run."""
    stmt = (
        select(IkeConcordanceRecord)
        .where(IkeConcordanceRecord.analysis_id == analysis_id)
        .order_by(IkeConcordanceRecord.evaluated_at.desc())
    )
    res = await db.execute(stmt)
    records = list(res.scalars().all())
    return [IkeConcordanceResponse.model_validate(r) for r in records]
