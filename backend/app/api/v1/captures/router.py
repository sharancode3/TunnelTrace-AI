"""REST API endpoints for offline packet capture upload and metadata inspection."""

import uuid

from fastapi import APIRouter, Depends, File, UploadFile, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.schemas import CaptureResponseDTO
from app.capture.ingestion import CaptureIngestionService
from app.core.errors import CaptureNotFoundError
from app.db.models.capture import Capture
from app.db.session import get_db_session

router = APIRouter(prefix="/captures", tags=["captures"])


@router.post(
    "",
    response_model=CaptureResponseDTO,
    status_code=status.HTTP_201_CREATED,
    summary="Upload and ingest a packet capture file (PCAP/PCAPNG)",
)
async def upload_capture(
    file: UploadFile = File(..., description="Binary packet capture file (PCAP or PCAPNG)"),
    db: AsyncSession = Depends(get_db_session),
) -> CaptureResponseDTO:
    """Safely stream, validate, hash, and persist an offline packet capture file."""
    service = CaptureIngestionService(db)
    capture = await service.ingest_upload(file, capture_source="OFFLINE_UPLOAD")

    return CaptureResponseDTO(
        capture_id=capture.id,
        capture_source=capture.capture_source,
        capture_format=capture.capture_format,
        original_filename=capture.original_filename,
        file_size_bytes=capture.file_size_bytes,
        sha256=capture.sha256_hash,
        packet_count=capture.packet_count,
        duration_sec=capture.duration_sec,
        first_packet_at=capture.first_packet_at,
        last_packet_at=capture.last_packet_at,
        link_layer_type=capture.link_layer_type,
        validation_state=capture.validation_state,
        created_at=capture.created_at,
    )


@router.get(
    "/{capture_id}",
    response_model=CaptureResponseDTO,
    summary="Retrieve capture metadata by UUID",
)
async def get_capture(
    capture_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
) -> CaptureResponseDTO:
    """Retrieve verified metadata and provenance for an ingested capture."""
    res = await db.execute(select(Capture).where(Capture.id == capture_id))
    capture = res.scalar_one_or_none()
    if not capture:
        raise CaptureNotFoundError(str(capture_id))

    return CaptureResponseDTO(
        capture_id=capture.id,
        capture_source=capture.capture_source,
        capture_format=capture.capture_format,
        original_filename=capture.original_filename,
        file_size_bytes=capture.file_size_bytes,
        sha256=capture.sha256_hash,
        packet_count=capture.packet_count,
        duration_sec=capture.duration_sec,
        first_packet_at=capture.first_packet_at,
        last_packet_at=capture.last_packet_at,
        link_layer_type=capture.link_layer_type,
        validation_state=capture.validation_state,
        created_at=capture.created_at,
    )
