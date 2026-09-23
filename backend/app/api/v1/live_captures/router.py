"""REST API endpoints for authorized Class B live packet capture management."""

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.schemas import (
    InterfaceMetadataDTO,
    LiveCaptureSessionResponseDTO,
    StartLiveCaptureRequestDTO,
    StopLiveCaptureResponseDTO,
)
from app.core.errors import LiveCaptureError, NotFoundError
from app.db.models.capture import AnalysisRun, Capture, LiveCaptureSession
from app.db.session import get_db_session
from app.integrations.privileged_agent import get_privileged_agent_client
from app.protocol.service import ProtocolForensicsService
from app.services.storage import get_storage_provider

router = APIRouter(prefix="/live-captures", tags=["live-captures"])


@router.get(
    "/interfaces",
    response_model=list[InterfaceMetadataDTO],
    summary="List allowlisted capture interfaces from Class B Privileged Agent",
)
async def list_authorized_interfaces() -> list[InterfaceMetadataDTO]:
    """Query Class B Privileged Agent for authorized network capture interfaces."""
    agent = get_privileged_agent_client()
    try:
        res = await agent.execute_action("LIST_INTERFACES", {})
        ifaces = res.get("interfaces", [])
        return [InterfaceMetadataDTO(**i) for i in ifaces]
    except Exception as exc:
        raise LiveCaptureError(
            f"Failed to query authorized capture interfaces: {exc}",
            code="LIVE_CAPTURE_FAILED",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        ) from exc


@router.post(
    "/start",
    response_model=LiveCaptureSessionResponseDTO,
    status_code=status.HTTP_201_CREATED,
    summary="Initiate an authorized live packet capture on an allowlisted interface",
)
async def start_live_capture(
    req: StartLiveCaptureRequestDTO,
    db: AsyncSession = Depends(get_db_session),
) -> LiveCaptureSessionResponseDTO:
    """Dispatches a bounded capture request to the Class B privileged agent."""
    agent = get_privileged_agent_client()
    storage = get_storage_provider()

    session_id = uuid.uuid4()
    pcap_rel = f"live/{session_id}/live.pcap"
    full_pcap_path = storage.resolve_safe_path(pcap_rel)
    full_pcap_path.parent.mkdir(parents=True, exist_ok=True)

    bpf_filter = req.bpf_filter or "udp port 500 or udp port 4500 or esp or ah"

    try:
        await agent.execute_action(
            "START_LIVE_CAPTURE",
            {
                "session_id": str(session_id),
                "interface": req.interface_id,
                "output_pcap": str(full_pcap_path),
                "bpf_filter": bpf_filter,
            },
        )
    except PermissionError as exc:
        raise LiveCaptureError(
            str(exc),
            code="LIVE_INTERFACE_NOT_ALLOWED",
            status_code=status.HTTP_403_FORBIDDEN,
        ) from exc
    except ValueError as exc:
        raise LiveCaptureError(
            str(exc),
            code="LIVE_INTERFACE_NOT_ALLOWED",
            status_code=status.HTTP_400_BAD_REQUEST,
        ) from exc
    except Exception as exc:
        raise LiveCaptureError(
            f"Failed to start live capture: {exc}",
            code="LIVE_CAPTURE_START_FAILED",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        ) from exc

    session_record = LiveCaptureSession(
        id=session_id,
        interface_name=req.interface_id,
        status="CAPTURING",
        capture_profile=req.capture_profile,
        bpf_filter=bpf_filter,
        max_duration_sec=req.duration_sec,
        storage_path=pcap_rel,
        started_at=datetime.now(timezone.utc),
        created_at=datetime.now(timezone.utc),
    )
    db.add(session_record)
    await db.commit()
    await db.refresh(session_record)

    return LiveCaptureSessionResponseDTO(
        session_id=session_record.id,
        interface_name=session_record.interface_name,
        status=session_record.status,
        capture_profile=session_record.capture_profile,
        packet_count=session_record.packet_count,
        byte_count=session_record.byte_count,
        duration_sec=0.0,
        capture_id=None,
        started_at=session_record.started_at,
        created_at=session_record.created_at,
    )


@router.get(
    "/{session_id}",
    response_model=LiveCaptureSessionResponseDTO,
    summary="Query live capture session status and packet counters",
)
async def get_live_capture_status(
    session_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
) -> LiveCaptureSessionResponseDTO:
    """Retrieve status and live duration of an active or completed capture session."""
    res = await db.execute(
        select(LiveCaptureSession).where(LiveCaptureSession.id == session_id)
    )
    session = res.scalar_one_or_none()
    if not session:
        raise NotFoundError(f"Live capture session '{session_id}' not found.")

    agent = get_privileged_agent_client()
    live_info = {}
    try:
        live_info = await agent.execute_action(
            "GET_LIVE_CAPTURE_STATUS", {"session_id": str(session_id)}
        )
    except Exception:
        pass

    duration_sec = live_info.get("duration_sec")
    if duration_sec is None and session.started_at and session.stopped_at:
        duration_sec = (session.stopped_at - session.started_at).total_seconds()

    return LiveCaptureSessionResponseDTO(
        session_id=session.id,
        interface_name=session.interface_name,
        status=live_info.get("status", session.status),
        capture_profile=session.capture_profile,
        packet_count=session.packet_count,
        byte_count=session.byte_count,
        duration_sec=duration_sec,
        capture_id=session.capture_id,
        started_at=session.started_at,
        stopped_at=session.stopped_at,
        created_at=session.created_at,
    )


@router.post(
    "/{session_id}/stop",
    response_model=StopLiveCaptureResponseDTO,
    summary="Stop live capture, flush buffers, calculate SHA-256, and register Capture",
)
async def stop_live_capture(
    session_id: uuid.UUID,
    db: AsyncSession = Depends(get_db_session),
) -> StopLiveCaptureResponseDTO:
    """Gracefully terminates live capture, hashes final bytes, and registers a durable Capture."""
    res = await db.execute(
        select(LiveCaptureSession).where(LiveCaptureSession.id == session_id)
    )
    session = res.scalar_one_or_none()
    if not session:
        raise NotFoundError(f"Live capture session '{session_id}' not found.")

    agent = get_privileged_agent_client()
    try:
        stop_res = await agent.execute_action(
            "STOP_LIVE_CAPTURE", {"session_id": str(session_id)}
        )
    except Exception as exc:
        raise LiveCaptureError(
            f"Failed to stop live capture: {exc}",
            code="LIVE_CAPTURE_STOP_FAILED",
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        ) from exc

    file_size = stop_res.get("file_size_bytes", 0)
    packet_count = stop_res.get("packet_count", 0)
    sha256 = stop_res.get("sha256", "")
    duration_sec = stop_res.get("duration_sec", 0.0)

    # Register as durable Capture record
    capture_id = uuid.uuid4()
    storage = get_storage_provider()
    # Move from live/<session_id>/live.pcap to captures/<capture_id>/raw.pcap
    live_pcap = storage.resolve_safe_path(session.storage_path or f"live/{session_id}/live.pcap")
    final_rel = f"captures/{capture_id}/raw.pcap"
    final_pcap = storage.resolve_safe_path(final_rel)
    final_pcap.parent.mkdir(parents=True, exist_ok=True)

    import os
    if live_pcap.exists():
        os.replace(live_pcap, final_pcap)

    capture_record = Capture(
        id=capture_id,
        capture_source="LIVE_CAPTURE",
        capture_format="PCAP",
        original_filename=f"live_{session.interface_name}_{session_id.hex[:8]}.pcap",
        storage_path=final_rel,
        file_size_bytes=file_size,
        sha256_hash=sha256 or "unknown",
        packet_count=packet_count,
        duration_sec=duration_sec,
        link_layer_type="ether",
        interface_metadata={"interface": session.interface_name},
        validation_state="VALIDATED",
        created_at=datetime.now(timezone.utc),
    )
    db.add(capture_record)

    session.status = "COMPLETED"
    session.stopped_at = datetime.now(timezone.utc)
    session.packet_count = packet_count
    session.byte_count = file_size
    session.capture_id = capture_id
    await db.commit()
    await db.refresh(session)

    # Trigger authoritative analysis run
    analysis_id = uuid.uuid4()
    analysis = AnalysisRun(
        id=analysis_id,
        capture_id=capture_id,
        status="QUEUED",
        current_stage="INGESTING",
        parser_engine="tshark",
        parser_version="unknown",
        schema_version="1.0.0",
        created_at=datetime.now(timezone.utc),
    )
    db.add(analysis)
    await db.commit()

    # Execute deterministic analysis
    service = ProtocolForensicsService(db)
    await service.execute_analysis(analysis_id)

    return StopLiveCaptureResponseDTO(
        session_id=session.id,
        capture_id=capture_id,
        analysis_id=analysis_id,
        status="COMPLETED",
        file_size_bytes=file_size,
        packet_count=packet_count,
        sha256=sha256,
    )
