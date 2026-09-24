"""Orchestration service for authorized IKE negotiation assessment and concordance."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.db.models.capture import ProtocolObservation
from app.db.models.ike_assessment import (
    IkeAssessmentJob,
    IkeConcordanceRecord,
    IkeProbeResult,
)
from app.db.models.reconstruction import IKESecurityAssociation
from app.protocol.ike_scan.concordance import (
    ConcordanceEvaluation,
    evaluate_ike_concordance,
)
from app.protocol.ike_scan.parser import parse_ike_scan_output
from app.protocol.ike_scan.runner import run_ike_scan
from app.protocol.ike_scan.validator import ValidatedIkeScope, validate_ike_scope

logger = logging.getLogger(__name__)


class IkeAssessmentService:
    """Coordinates validation, execution, persistence, and concordance evaluation for IKE scans."""

    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def create_and_execute_job(
        self,
        *,
        job_name: str,
        operator_id: str,
        authorization_reference: str,
        authorization_attestation: str,
        profile_name: str,
        target: str,
        port: int = 500,
        analysis_id: uuid.UUID | None = None,
    ) -> IkeAssessmentJob:
        """Validate request scope, run bounded probe, persist evidence and evaluate concordance."""
        # 1. Scope and authorization validation
        scope: ValidatedIkeScope = validate_ike_scope(
            operator_id=operator_id,
            authorization_reference=authorization_reference,
            authorization_attestation=authorization_attestation,
            profile_name=profile_name,
            target=target,
            port=port,
        )

        # 2. Instantiate and persist Job entity
        job = IkeAssessmentJob(
            job_name=job_name.strip() or f"IKE Probe {scope.target_ip}",
            operator_id=scope.operator_id,
            authorization_reference=scope.authorization_reference,
            authorization_attestation=scope.authorization_attestation,
            authorized_at=scope.authorized_at,
            target_ip=scope.target_ip,
            target_port=scope.target_port,
            profile=scope.profile.value,
            ike_version_requested=scope.ike_version,
            status="VALIDATING",
            started_at=datetime.now(timezone.utc),
        )
        self.db.add(job)
        await self.db.flush()

        # 3. Subprocess execution
        job.status = "RUNNING"
        await self.db.flush()

        exec_res = run_ike_scan(scope)

        now = datetime.now(timezone.utc)
        job.completed_at = now
        job.raw_output_sha256 = exec_res.output_sha256
        job.output_bytes_count = exec_res.output_bytes_count
        job.tool_version = exec_res.tool_version

        if exec_res.status == "TOOL_UNAVAILABLE":
            job.status = "TOOL_UNAVAILABLE"
            job.failure_reason = exec_res.diagnostic_message
            probe_res = IkeProbeResult(
                job_id=job.id,
                target_ip=scope.target_ip,
                target_port=scope.target_port,
                response_category="TOOL_UNAVAILABLE",
                ike_version=f"IKEv{scope.ike_version}",
                is_experimental=scope.is_experimental,
                raw_response_text=exec_res.diagnostic_message,
            )
            self.db.add(probe_res)

        elif exec_res.status == "CANCELLED":
            job.status = "CANCELLED"
            job.failure_reason = exec_res.diagnostic_message
            probe_res = IkeProbeResult(
                job_id=job.id,
                target_ip=scope.target_ip,
                target_port=scope.target_port,
                response_category="TOOL_ERROR",
                ike_version=f"IKEv{scope.ike_version}",
                is_experimental=scope.is_experimental,
                raw_response_text=exec_res.diagnostic_message,
            )
            self.db.add(probe_res)

        elif exec_res.status == "FAILED":
            job.status = "FAILED"
            job.failure_reason = exec_res.diagnostic_message
            probe_res = IkeProbeResult(
                job_id=job.id,
                target_ip=scope.target_ip,
                target_port=scope.target_port,
                response_category="TOOL_ERROR",
                ike_version=f"IKEv{scope.ike_version}",
                is_experimental=scope.is_experimental,
                raw_response_text=exec_res.diagnostic_message,
            )
            self.db.add(probe_res)

        else:
            # COMPLETED
            job.status = "COMPLETED"
            parsed = parse_ike_scan_output(
                raw_output=exec_res.raw_stdout or "",
                target_ip=scope.target_ip,
                target_port=scope.target_port,
                is_experimental=scope.is_experimental,
            )
            probe_res = IkeProbeResult(
                job_id=job.id,
                target_ip=parsed.target_ip,
                target_port=parsed.target_port,
                response_category=parsed.response_category,
                ike_version=parsed.ike_version,
                handshake_type=parsed.handshake_type,
                notify_code=parsed.notify_code,
                notify_message=parsed.notify_message,
                vendor_ids=parsed.vendor_ids,
                transforms_returned=parsed.transforms_returned,
                rtt_ms=parsed.rtt_ms,
                raw_response_text=parsed.raw_response_text,
                is_experimental=parsed.is_experimental,
            )
            self.db.add(probe_res)

        await self.db.flush()

        # 4. If analysis_id provided, automatically evaluate concordance
        if analysis_id is not None:
            await self.evaluate_and_persist_concordance(
                analysis_id=analysis_id,
                target_ip=scope.target_ip,
                job_id=job.id,
            )

        await self.db.commit()
        refreshed = await self.get_job(job.id)
        return refreshed or job

    async def get_job(self, job_id: uuid.UUID) -> IkeAssessmentJob | None:
        """Fetch a job by ID with results loaded."""
        stmt = (
            select(IkeAssessmentJob)
            .where(IkeAssessmentJob.id == job_id)
            .options(selectinload(IkeAssessmentJob.results))
        )
        res = await self.db.execute(stmt)
        return res.scalar_one_or_none()

    async def list_jobs(self, limit: int = 50, offset: int = 0) -> list[IkeAssessmentJob]:
        """List jobs ordered by creation time descending."""
        stmt = (
            select(IkeAssessmentJob)
            .order_by(IkeAssessmentJob.created_at.desc())
            .limit(limit)
            .offset(offset)
            .options(selectinload(IkeAssessmentJob.results))
        )
        res = await self.db.execute(stmt)
        return list(res.scalars().all())

    async def evaluate_and_persist_concordance(
        self,
        *,
        analysis_id: uuid.UUID,
        target_ip: str,
        job_id: uuid.UUID | None = None,
        lab_ground_truth: dict[str, Any] | None = None,
    ) -> IkeConcordanceRecord:
        """Triangulate passive TShark observations with active probe results and record concordance."""
        # 1. Fetch passive SAs for analysis
        sa_stmt = select(IKESecurityAssociation).where(
            IKESecurityAssociation.analysis_id == analysis_id
        )
        sa_res = await self.db.execute(sa_stmt)
        passive_sa_models = list(sa_res.scalars().all())
        passive_sas = [
            {
                "version": sa.version,
                "encryption_algorithm": sa.encryption_algorithm,
                "integrity_algorithm": sa.integrity_algorithm,
                "dh_group": sa.dh_group,
                "initiator_spi": sa.initiator_spi,
                "responder_spi": sa.responder_spi,
            }
            for sa in passive_sa_models
        ]

        # 2. Fetch passive observations
        obs_stmt = select(ProtocolObservation).where(
            ProtocolObservation.analysis_id == analysis_id
        )
        obs_res = await self.db.execute(obs_stmt)
        passive_obs_models = list(obs_res.scalars().all())
        passive_obs = [
            {
                "frame_number": o.frame_number,
                "category": o.category,
                "field_name": o.field_name,
                "normalized_value": o.normalized_value,
            }
            for o in passive_obs_models
        ]

        # 3. Fetch active results for target
        active_stmt = select(IkeProbeResult).where(
            IkeProbeResult.target_ip == target_ip
        )
        if job_id:
            active_stmt = active_stmt.where(IkeProbeResult.job_id == job_id)
        active_res = await self.db.execute(active_stmt)
        active_models = list(active_res.scalars().all())
        active_results = [
            {
                "response_category": r.response_category,
                "ike_version": r.ike_version,
                "handshake_type": r.handshake_type,
                "transforms_returned": r.transforms_returned,
                "rtt_ms": r.rtt_ms,
                "is_experimental": r.is_experimental,
            }
            for r in active_models
        ]

        # 4. Evaluate concordance
        evaluation: ConcordanceEvaluation = evaluate_ike_concordance(
            target_ip=target_ip,
            passive_ike_sas=passive_sas,
            passive_observations=passive_obs,
            active_probe_results=active_results,
            lab_ground_truth=lab_ground_truth,
        )

        concordance_record = IkeConcordanceRecord(
            analysis_id=analysis_id,
            ike_job_id=job_id,
            target_ip=target_ip,
            concordance_status=evaluation.concordance_status,
            passive_ike_versions=evaluation.passive_ike_versions,
            active_ike_versions=evaluation.active_ike_versions,
            passive_selected_cipher=evaluation.passive_selected_cipher,
            active_accepted_cipher=evaluation.active_accepted_cipher,
            concordance_details=evaluation.details,
        )
        self.db.add(concordance_record)
        await self.db.flush()
        return concordance_record
