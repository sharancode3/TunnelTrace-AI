"""Celery asynchronous tasks for deterministic protocol forensics."""

import asyncio
import logging
import uuid

from app.db.session import get_session_factory
from app.protocol.service import ProtocolForensicsService
from app.workers.celery_app import celery_app

logger = logging.getLogger(__name__)


@celery_app.task(name="app.workers.protocol_tasks.analyze_capture_task", bind=True, max_retries=1)
def analyze_capture_task(self, analysis_id_str: str) -> dict[str, str]:
    """Celery background worker entrypoint to execute protocol forensics analysis.

    Runs unprivileged inside the worker process pool.
    """
    analysis_id = uuid.UUID(analysis_id_str)
    logger.info(f"Worker received analysis task for '{analysis_id}'")

    async def _run() -> None:
        factory = get_session_factory()
        async with factory() as db:
            service = ProtocolForensicsService(db)
            summary = await service.execute_analysis(analysis_id)
            if summary.ipsec_detected:
                from app.reconstruction.engine import ReconstructionEngine

                engine = ReconstructionEngine(db)
                await engine.execute_reconstruction(analysis_id)

                # Stage 8: Execute deterministic Policy-as-Code, Scoring & Evidence Graph
                from app.api.v1.security.router import (
                    _ensure_assessment_executed,
                    get_security_service,
                )
                sec_service = get_security_service()
                await _ensure_assessment_executed(analysis_id, db, sec_service)

    try:
        asyncio.run(_run())
        return {"status": "SUCCESS", "analysis_id": analysis_id_str}
    except Exception as exc:
        logger.error(f"Async worker analysis failed for '{analysis_id}': {exc}")
        # Deterministic parser errors are not retried indefinitely
        return {"status": "FAILED", "analysis_id": analysis_id_str, "error": str(exc)}
