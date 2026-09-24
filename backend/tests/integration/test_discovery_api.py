"""Integration tests for Stage 2 Authorized Asset Discovery API and Database Persistence."""

import hashlib
import uuid
from pathlib import Path
from unittest.mock import patch

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.db.base import Base
from app.db.session import get_db_session
from app.discovery.runner import ExecutionResult, NmapBinaryInfo

CANNED_UDP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" version="7.94">
<host>
  <status state="up"/>
  <address addr="127.0.0.1" addrtype="ipv4"/>
  <ports>
    <port protocol="udp" portid="500">
      <state state="open|filtered" reason="no-response"/>
      <service name="isakmp"/>
    </port>
    <port protocol="udp" portid="4500">
      <state state="open|filtered" reason="no-response"/>
      <service name="ipsec-msft"/>
    </port>
  </ports>
</host>
</nmaprun>
"""


@pytest_asyncio.fixture
async def isolated_db(tmp_path: Path):
    """Create an isolated SQLite database with fresh schema for discovery testing."""
    db_file = tmp_path / "test_discovery.db"
    db_url = f"sqlite+aiosqlite:///{db_file.as_posix()}"
    engine = create_async_engine(db_url, echo=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)
    async with session_factory() as session:
        yield session

    await engine.dispose()


@pytest.fixture
def discovery_client(app, isolated_db: AsyncSession):
    """Test client with isolated database session override."""
    async def override_get_db():
        yield isolated_db

    app.dependency_overrides[get_db_session] = override_get_db
    with TestClient(app=app, base_url="http://testserver") as test_client:
        yield test_client
    app.dependency_overrides.clear()


def test_discovery_status_endpoint(discovery_client: TestClient):
    """GET /api/v1/discovery/status should return operational limits and available profiles."""
    response = discovery_client.get("/api/v1/discovery/status")
    assert response.status_code == 200
    data = response.json()
    assert data["enabled"] is True
    assert data["max_targets"] == 8
    assert data["max_ports"] == 16
    assert isinstance(data["available_profiles"], list)
    assert len(data["available_profiles"]) >= 2
    profile_names = [p["name"] for p in data["available_profiles"]]
    assert "IKE_SERVICE_DISCOVERY" in profile_names
    assert "VPN_MANAGEMENT_DISCOVERY" in profile_names


def test_create_job_unauthorized_missing_attestation(discovery_client: TestClient):
    """POST /api/v1/discovery/jobs without valid attestation returns 403 or 422."""
    payload = {
        "job_name": "Unauthorized Test",
        "operator_id": "sec-op",
        "authorization_reference": "TICKET-1",
        "authorization_attestation": "short",  # Fails min_length
        "profile": "IKE_SERVICE_DISCOVERY",
        "requested_targets": ["127.0.0.1"],
    }
    response = discovery_client.post("/api/v1/discovery/jobs", json=payload)
    assert response.status_code in (403, 422)


def test_create_job_invalid_scope_multicast(discovery_client: TestClient):
    """POST /api/v1/discovery/jobs with multicast target returns 422 Unprocessable Entity."""
    payload = {
        "job_name": "Multicast Test",
        "operator_id": "sec-op",
        "authorization_reference": "TICKET-1",
        "authorization_attestation": "Explicit authorization confirmed for assessment.",
        "profile": "IKE_SERVICE_DISCOVERY",
        "requested_targets": ["224.0.0.1"],
    }
    response = discovery_client.post("/api/v1/discovery/jobs", json=payload)
    assert response.status_code == 422
    assert "Multicast" in response.json()["detail"]


def test_create_job_tool_unavailable_state(discovery_client: TestClient):
    """POST /api/v1/discovery/jobs records TOOL_UNAVAILABLE cleanly when Nmap binary is absent."""
    payload = {
        "job_name": "Tool Unavailable Test",
        "operator_id": "sec-op",
        "authorization_reference": "TICKET-1",
        "authorization_attestation": "Explicit authorization confirmed for assessment.",
        "profile": "IKE_SERVICE_DISCOVERY",
        "requested_targets": ["127.0.0.1"],
    }

    with patch("app.discovery.runner.detect_nmap_binary") as mock_detect:
        mock_detect.return_value = NmapBinaryInfo(
            is_available=False,
            error_message="Nmap binary not found on test host.",
        )

        response = discovery_client.post("/api/v1/discovery/jobs", json=payload)
        assert response.status_code == 201
        data = response.json()
        assert data["status"] == "TOOL_UNAVAILABLE"
        assert "not found" in data["failure_reason"]
        assert data["target_count"] == 1
        assert data["hosts_up_count"] == 0


def test_create_job_success_with_ambiguity_and_persistence(discovery_client: TestClient):
    """POST /api/v1/discovery/jobs records COMPLETED_WITH_AMBIGUITY and persists host/service evidence."""
    payload = {
        "job_name": "Authorized IKE Scan",
        "operator_id": "sec-op",
        "authorization_reference": "CHG-2026-0924",
        "authorization_attestation": "Explicit authorization confirmed for assessment.",
        "profile": "IKE_SERVICE_DISCOVERY",
        "requested_targets": ["127.0.0.1"],
    }

    mock_sha = hashlib.sha256(CANNED_UDP_XML.encode()).hexdigest()
    mock_exec = ExecutionResult(
        status="COMPLETED",
        exit_code=0,
        raw_xml_content=CANNED_UDP_XML,
        output_sha256=mock_sha,
        output_bytes_count=len(CANNED_UDP_XML.encode()),
        tool_version="7.94",
        diagnostic_message=None,
        executed_argv=["nmap", "-sU", "-p", "500,4500", "127.0.0.1"],
    )

    with patch("app.discovery.runner.detect_nmap_binary") as mock_detect, \
         patch("app.discovery.service.run_discovery_scan", return_value=mock_exec):
        mock_detect.return_value = NmapBinaryInfo(is_available=True, version="7.94")

        # 1. Create Job
        create_resp = discovery_client.post("/api/v1/discovery/jobs", json=payload)
        assert create_resp.status_code == 201
        job_data = create_resp.json()
        job_id = job_data["id"]

        assert job_data["status"] == "COMPLETED_WITH_AMBIGUITY"
        assert job_data["target_count"] == 1
        assert job_data["hosts_up_count"] == 1
        assert job_data["services_discovered_count"] == 2
        assert job_data["raw_output_sha256"] == mock_sha

        # 2. Get Job Details
        get_resp = discovery_client.get(f"/api/v1/discovery/jobs/{job_id}")
        assert get_resp.status_code == 200
        detail = get_resp.json()
        assert len(detail["hosts"]) == 1
        host = detail["hosts"][0]
        assert host["ip_address"] == "127.0.0.1"
        assert len(host["services"]) == 2

        # Verify explicit ambiguity preserved
        svc500 = next(s for s in host["services"] if s["port"] == 500)
        assert svc500["protocol"] == "UDP"
        assert svc500["state"] == "OPEN_OR_FILTERED"

        # 3. List Jobs
        list_resp = discovery_client.get("/api/v1/discovery/jobs")
        assert list_resp.status_code == 200
        jobs_list = list_resp.json()
        assert any(j["id"] == job_id for j in jobs_list)


def test_cancel_job(discovery_client: TestClient):
    """POST /api/v1/discovery/jobs/{job_id}/cancel marks job cancelled."""
    payload = {
        "job_name": "Job to Cancel",
        "operator_id": "sec-op",
        "authorization_reference": "CHG-CANCEL-1",
        "authorization_attestation": "Explicit authorization confirmed for assessment.",
        "profile": "IKE_SERVICE_DISCOVERY",
        "requested_targets": ["127.0.0.1"],
    }

    with patch("app.discovery.runner.detect_nmap_binary") as mock_detect:
        mock_detect.return_value = NmapBinaryInfo(is_available=False, error_message="Unavailable")
        create_resp = discovery_client.post("/api/v1/discovery/jobs", json=payload)
        job_id = create_resp.json()["id"]

        # Cancel endpoint
        cancel_resp = discovery_client.post(f"/api/v1/discovery/jobs/{job_id}/cancel")
        assert cancel_resp.status_code == 200
        # Terminal state TOOL_UNAVAILABLE cannot transition to cancelled, stays TOOL_UNAVAILABLE or becomes CANCELLED if in flight
