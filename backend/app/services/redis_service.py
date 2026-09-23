"""Asynchronous Redis service client and connection health verification."""

import logging
import time
from typing import Any

import redis.asyncio as aioredis

from app.core.config import get_settings

logger = logging.getLogger(__name__)

_redis_client: aioredis.Redis | None = None


def get_redis_client() -> aioredis.Redis:
    """Retrieve or initialize the asynchronous Redis connection client."""
    global _redis_client
    if _redis_client is None:
        settings = get_settings()
        _redis_client = aioredis.from_url(
            settings.REDIS_URL,
            socket_timeout=settings.REDIS_SOCKET_TIMEOUT,
            max_connections=settings.REDIS_MAX_CONNECTIONS,
            decode_responses=True,
        )
    return _redis_client


async def check_redis_health() -> dict[str, Any]:
    """Execute a real PING against Redis to verify broker connectivity."""
    start_time = time.perf_counter()
    try:
        client = get_redis_client()
        pong = await client.ping()
        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
        if pong is True:
            return {
                "status": "UP",
                "latency_ms": latency_ms,
                "error": None,
            }
        return {
            "status": "DOWN",
            "latency_ms": latency_ms,
            "error": f"Unexpected Redis response: {pong}",
        }
    except Exception as exc:
        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
        logger.warning(f"Redis health check failed: {exc}")
        return {
            "status": "DOWN",
            "latency_ms": latency_ms,
            "error": str(exc),
        }


async def close_redis_connection() -> None:
    """Close active Redis client connections on application shutdown."""
    global _redis_client
    if _redis_client is not None:
        logger.info("Closing active Redis connection client.")
        await _redis_client.aclose()
        _redis_client = None
