"""Integration tests for System Health API (Liveness & Readiness)."""

from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient


def test_liveness_probe_returns_up(client: TestClient):
    """GET /api/v1/system/health/live should return HTTP 200 and UP without external dependencies."""
    response = client.get("/api/v1/system/health/live")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "UP"
    assert "timestamp" in data
    assert "X-Request-ID" in response.headers


def test_readiness_probe_all_healthy(client: TestClient):
    """GET /api/v1/system/health/ready returns 200 and READY when DB, Redis, and Storage succeed."""
    with (
        patch("app.api.v1.system.health.check_database_health", new_callable=AsyncMock) as mock_db,
        patch("app.api.v1.system.health.check_redis_health", new_callable=AsyncMock) as mock_redis,
        patch("app.api.v1.system.health.check_storage_health") as mock_storage,
    ):
        mock_db.return_value = {"status": "UP", "details": {"latency_ms": 1.5}}
        mock_redis.return_value = {"status": "UP", "details": {"latency_ms": 0.8}}
        mock_storage.return_value = {"status": "UP", "details": {"root": "/var/lib/storage"}}

        response = client.get("/api/v1/system/health/ready")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "READY"
        assert data["dependencies"]["database"]["status"] == "UP"
        assert data["dependencies"]["redis"]["status"] == "UP"
        assert data["dependencies"]["storage"]["status"] == "UP"
        # Dependencies reported as UP (if present on host) or NOT_CONFIGURED
        assert data["dependencies"]["tshark"]["status"] in ("NOT_CONFIGURED", "UP")
        assert data["dependencies"]["privileged_agent"]["status"] in ("NOT_CONFIGURED", "UP")
        assert data["dependencies"]["ml_engine"]["status"] in ("NOT_CONFIGURED", "UP")


def test_readiness_probe_database_down(client: TestClient):
    """GET /api/v1/system/health/ready returns 503 and NOT_READY when database is down."""
    with (
        patch("app.api.v1.system.health.check_database_health", new_callable=AsyncMock) as mock_db,
        patch("app.api.v1.system.health.check_redis_health", new_callable=AsyncMock) as mock_redis,
        patch("app.api.v1.system.health.check_storage_health") as mock_storage,
    ):
        mock_db.return_value = {"status": "DOWN", "error": "Connection refused"}
        mock_redis.return_value = {"status": "UP", "details": {"latency_ms": 0.8}}
        mock_storage.return_value = {"status": "UP", "details": {"root": "/var/lib/storage"}}

        response = client.get("/api/v1/system/health/ready")
        assert response.status_code == 503
        data = response.json()
        assert data["status"] == "NOT_READY"
        assert data["dependencies"]["database"]["status"] == "DOWN"


def test_readiness_probe_redis_down(client: TestClient):
    """GET /api/v1/system/health/ready returns 503 and NOT_READY when Redis is down."""
    with (
        patch("app.api.v1.system.health.check_database_health", new_callable=AsyncMock) as mock_db,
        patch("app.api.v1.system.health.check_redis_health", new_callable=AsyncMock) as mock_redis,
        patch("app.api.v1.system.health.check_storage_health") as mock_storage,
    ):
        mock_db.return_value = {"status": "UP", "details": {"latency_ms": 1.2}}
        mock_redis.return_value = {"status": "DOWN", "error": "Connection timeout"}
        mock_storage.return_value = {"status": "UP", "details": {"root": "/var/lib/storage"}}

        response = client.get("/api/v1/system/health/ready")
        assert response.status_code == 503
        data = response.json()
        assert data["status"] == "NOT_READY"
        assert data["dependencies"]["redis"]["status"] == "DOWN"


def test_readiness_probe_storage_down(client: TestClient):
    """GET /api/v1/system/health/ready returns 503 and NOT_READY when storage is unwritable."""
    with (
        patch("app.api.v1.system.health.check_database_health", new_callable=AsyncMock) as mock_db,
        patch("app.api.v1.system.health.check_redis_health", new_callable=AsyncMock) as mock_redis,
        patch("app.api.v1.system.health.check_storage_health") as mock_storage,
    ):
        mock_db.return_value = {"status": "UP", "details": {"latency_ms": 1.2}}
        mock_redis.return_value = {"status": "UP", "details": {"latency_ms": 0.5}}
        mock_storage.return_value = {"status": "DOWN", "error": "Permission denied"}

        response = client.get("/api/v1/system/health/ready")
        assert response.status_code == 503
        data = response.json()
        assert data["status"] == "NOT_READY"
        assert data["dependencies"]["storage"]["status"] == "DOWN"
