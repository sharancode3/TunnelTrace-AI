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
            from app.services.pipeline import execute_full_analysis_pipeline

            await execute_full_analysis_pipeline(analysis_id, db)

    try:
        asyncio.run(_run())
        return {"status": "SUCCESS", "analysis_id": analysis_id_str}
    except Exception as exc:
        logger.error(f"Async worker analysis failed for '{analysis_id}': {exc}")
        # Deterministic parser errors are not retried indefinitely
        return {"status": "FAILED", "analysis_id": analysis_id_str, "error": str(exc)}
