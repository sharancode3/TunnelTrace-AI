"""FastAPI router for External Vulnerability Assessment Reports (Greenbone/OpenVAS)."""

from __future__ import annotations

import json
import logging
import uuid
from typing import Annotated

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    Query,
    UploadFile,
    status,
)
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.vulnerabilities.schemas import (
    VulnerabilityFindingDTO,
    VulnerabilityFindingListResponse,
    VulnerabilityReportDTO,
    VulnerabilityReportListResponse,
    VulnerabilityReportPreviewResponse,
)
from app.db.session import get_db_session
from app.services.storage import get_storage_provider
from app.services.storage.base import StorageProvider
from app.vulnerabilities.parser import GreenboneParseError
from app.vulnerabilities.service import (
    AuthorizationValidationError,
    VulnerabilityFindingNotFoundError,
    VulnerabilityReportNotFoundError,
    VulnerabilityReportService,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/vulnerabilities", tags=["Vulnerability Assessment"])


def _parse_target_list(raw_targets: str | None) -> list[str]:
    if not raw_targets:
        return []
    cleaned = raw_targets.strip()
    if cleaned.startswith("[") and cleaned.endswith("]"):
        try:
            parsed = json.loads(cleaned)
            if isinstance(parsed, list):
                return [str(item).strip() for item in parsed if str(item).strip()]
        except Exception:
            pass
    return [t.strip() for t in cleaned.split(",") if t.strip()]


@router.post(
    "/reports/preview",
    response_model=VulnerabilityReportPreviewResponse,
    summary="Preview Greenbone XML Report",
    description="Preflight parsing of an uploaded Greenbone XML report artifact to inspect metadata, feed status, and asset mapping before importing.",
)
async def preview_vulnerability_report(
    file: UploadFile = File(..., description="Greenbone XML report artifact"),
    authorized_targets: str | None = Form(None, description="Comma-separated or JSON list of authorized target IPs/CIDRs"),
    db: AsyncSession = Depends(get_db_session),
) -> VulnerabilityReportPreviewResponse:
    try:
        raw_bytes = await file.read()
        target_list = _parse_target_list(authorized_targets)
        preview_data = await VulnerabilityReportService.preview_report(
            raw_bytes,
            authorized_targets=target_list,
            db=db,
        )
        return VulnerabilityReportPreviewResponse.model_validate(preview_data)
    except GreenboneParseError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Report XML parsing failed: {exc}",
        ) from exc
    except Exception as exc:
        logger.error(f"Unexpected error previewing vulnerability report: {exc}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to preview report due to an internal server error.",
        ) from exc


@router.post(
    "/reports/import",
    response_model=VulnerabilityReportDTO,
    status_code=status.HTTP_201_CREATED,
    summary="Import Greenbone XML Report",
    description="Validate operator attestation, store original artifact immutably, parse results, map assets, and persist supplemental vulnerability evidence.",
)
async def import_vulnerability_report(
    file: UploadFile = File(..., description="Greenbone XML report artifact"),
    operator_id: str = Form(..., description="Operator identifier attesting authorized import"),
    authorization_reference: str = Form(..., description="Change request or engagement authorization reference"),
    operator_attestation: str = Form(..., description="Explicit written attestation of authorized scope"),
    engagement_scope: str = Form(..., description="Designated engagement or asset scope"),
    authorized_targets: str | None = Form(None, description="Comma-separated or JSON list of authorized targets"),
    db: AsyncSession = Depends(get_db_session),
    storage: StorageProvider = Depends(get_storage_provider),
) -> VulnerabilityReportDTO:
    try:
        raw_bytes = await file.read()
        target_list = _parse_target_list(authorized_targets)
        report = await VulnerabilityReportService.import_report(
            raw_bytes,
            operator_id=operator_id,
            authorization_reference=authorization_reference,
            operator_attestation=operator_attestation,
            engagement_scope=engagement_scope,
            authorized_targets=target_list,
            db=db,
            storage=storage,
        )
        return VulnerabilityReportDTO.model_validate(report)
    except AuthorizationValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Operator authorization validation failed: {exc}",
        ) from exc
    except GreenboneParseError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Report XML parsing failed: {exc}",
        ) from exc
    except Exception as exc:
        logger.error(f"Unexpected error importing vulnerability report: {exc}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to import report due to an internal server error.",
        ) from exc


@router.get(
    "/reports",
    response_model=VulnerabilityReportListResponse,
    summary="List Imported Vulnerability Reports",
)
async def list_vulnerability_reports(
    skip: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    status: str | None = Query(None, description="Filter by report status"),
    operator_id: str | None = Query(None, description="Filter by importing operator ID"),
    db: AsyncSession = Depends(get_db_session),
) -> VulnerabilityReportListResponse:
    reports, total = await VulnerabilityReportService.list_reports(
        db=db,
        skip=skip,
        limit=limit,
        status=status,
        operator_id=operator_id,
    )
    dtos = [VulnerabilityReportDTO.model_validate(r) for r in reports]
    return VulnerabilityReportListResponse(
        reports=dtos,
        total=total,
        skip=skip,
        limit=limit,
    )


@router.get(
    "/reports/{report_id}",
    response_model=VulnerabilityReportDTO,
    summary="Get Vulnerability Report Details",
)
async def get_vulnerability_report(
    report_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
) -> VulnerabilityReportDTO:
    try:
        report = await VulnerabilityReportService.get_report(db, report_id)
        return VulnerabilityReportDTO.model_validate(report)
    except VulnerabilityReportNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc


@router.get(
    "/reports/{report_id}/findings",
    response_model=VulnerabilityFindingListResponse,
    summary="List Findings for Report",
)
async def list_findings_for_report(
    report_id: uuid.UUID,
    skip: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    host_ip: str | None = Query(None, description="Filter by host IP address"),
    severity: str | None = Query(None, description="Filter by source reported severity"),
    correlation_status: str | None = Query(None, description="Filter by correlation status"),
    asset_link_state: str | None = Query(None, description="Filter by asset link state"),
    db: AsyncSession = Depends(get_db_session),
) -> VulnerabilityFindingListResponse:
    try:
        # Check report exists
        await VulnerabilityReportService.get_report(db, report_id)
        findings, total = await VulnerabilityReportService.list_findings(
            db=db,
            report_id=report_id,
            host_ip=host_ip,
            severity=severity,
            correlation_status=correlation_status,
            asset_link_state=asset_link_state,
            skip=skip,
            limit=limit,
        )
        dtos = [VulnerabilityFindingDTO.model_validate(f) for f in findings]
        return VulnerabilityFindingListResponse(
            findings=dtos,
            total=total,
            skip=skip,
            limit=limit,
        )
    except VulnerabilityReportNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc


@router.get(
    "/findings",
    response_model=VulnerabilityFindingListResponse,
    summary="List Findings Across All Reports",
)
async def list_all_vulnerability_findings(
    skip: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    host_ip: str | None = Query(None, description="Filter by host IP address"),
    severity: str | None = Query(None, description="Filter by source reported severity"),
    correlation_status: str | None = Query(None, description="Filter by correlation status"),
    asset_link_state: str | None = Query(None, description="Filter by asset link state"),
    db: AsyncSession = Depends(get_db_session),
) -> VulnerabilityFindingListResponse:
    findings, total = await VulnerabilityReportService.list_findings(
        db=db,
        report_id=None,
        host_ip=host_ip,
        severity=severity,
        correlation_status=correlation_status,
        asset_link_state=asset_link_state,
        skip=skip,
        limit=limit,
    )
    dtos = [VulnerabilityFindingDTO.model_validate(f) for f in findings]
    return VulnerabilityFindingListResponse(
        findings=dtos,
        total=total,
        skip=skip,
        limit=limit,
    )


@router.get(
    "/reports/{report_id}/findings/{finding_id}",
    response_model=VulnerabilityFindingDTO,
    summary="Get Finding Detail",
)
async def get_vulnerability_finding(
    report_id: uuid.UUID,
    finding_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
) -> VulnerabilityFindingDTO:
    try:
        finding = await VulnerabilityReportService.get_finding(db, finding_id)
        if finding.report_id != report_id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Finding {finding_id} does not belong to report {report_id}",
            )
        return VulnerabilityFindingDTO.model_validate(finding)
    except VulnerabilityFindingNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc
