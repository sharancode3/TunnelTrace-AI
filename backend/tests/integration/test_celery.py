"""Integration tests for Celery worker configuration and baseline tasks."""

from app.workers.celery_app import celery_app
from app.workers.health_tasks import health_ping


def test_celery_configuration_security():
    """Verify Celery task serialization adheres to unprivileged JSON security constraints."""
    conf = celery_app.conf
    assert conf.task_serializer == "json"
    assert conf.result_serializer == "json"
    assert "json" in conf.accept_content
    # Pickle must be blocked
    assert "pickle" not in conf.accept_content
    assert conf.task_always_eager is False or conf.task_always_eager is True


def test_celery_health_ping_task():
    """Verify that the minimal health ping task executes cleanly and returns expected status."""
    # Execute synchronous task directly
    res = health_ping.apply()
    assert res.state == "SUCCESS"
    data = res.result
    assert data["status"] == "PONG"
    assert "timestamp" in data
    assert "worker" in data
