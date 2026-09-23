"""Database health check service executing real query validation."""

import logging
import time
from typing import Any

from sqlalchemy import text

from app.db.session import get_engine

logger = logging.getLogger(__name__)


async def check_database_health() -> dict[str, Any]:
    """Execute a real 'SELECT 1' against PostgreSQL to verify connectivity."""
    start_time = time.perf_counter()
    try:
        engine = get_engine()
        async with engine.connect() as conn:
            result = await conn.execute(text("SELECT 1"))
            val = result.scalar()
            latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
            if val == 1:
                return {
                    "status": "UP",
                    "latency_ms": latency_ms,
                    "error": None,
                }
            return {
                "status": "DOWN",
                "latency_ms": latency_ms,
                "error": f"Unexpected scalar query result: {val}",
            }
    except Exception as exc:
        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
        logger.warning(f"Database health check failed: {exc}")
        return {
            "status": "DOWN",
            "latency_ms": latency_ms,
            "error": str(exc),
        }
