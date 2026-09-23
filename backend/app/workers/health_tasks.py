"""Foundational Celery worker health verification tasks."""

import time
from datetime import datetime, timezone
from typing import Any

from app.workers.celery_app import celery_app


@celery_app.task(name="system.health_ping")
def health_ping() -> dict[str, Any]:
    """Execute a lightweight diagnostic task to verify worker execution and broker reachability."""
    return {
        "status": "PONG",
        "worker": "tunneltrace_worker",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "epoch_time": time.time(),
    }
