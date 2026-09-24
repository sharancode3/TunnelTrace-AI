"""Integration tests for IKE Negotiation Assessment API and Concordance."""

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
from app.protocol.ike_scan.runner import ExecutionResult, IkeBinaryInfo

CANNED_IKE_SCAN_OUT = """Starting ike-scan 1.9 with 1 hosts (http://www.nta-monitor.com/ike-scan/)
192.168.1.50\tMain Mode Handshake returned
\tHDR=(CKY-R=8b9c0d1e2f3a4b5c)
\tSA=(Enc=3DES Hash=SHA1 Auth=PSK Group=2:modp1024 LifeType=Seconds LifeDuration=28800)
\tVID=1234567890abcdef (Cisco Unity)

Ending ike-scan 1.9: 1 hosts scanned in 0.045 seconds (22.22 hosts/sec). 1 returned handshake; 0 returned notify
"""


@pytest_asyncio.fixture
async def isolated_db(tmp_path: Path):
    """Create an isolated SQLite database with fresh schema for IKE assessment testing."""
    db_file = tmp_path / "test_ike_assessment.db"
    db_url = f"sqlite+aiosqlite:///{db_file.as_posix()}"
    engine = create_async_engine(db_url, echo=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)
    async with session_factory() as session:
        yield session

    await engine.dispose()


@pytest.fixture
def ike_client(app, isolated_db: AsyncSession):
    """Test client with isolated database session override."""
    async def override_get_db():
        yield isolated_db

    app.dependency_overrides[get_db_session] = override_get_db
    with TestClient(app=app, base_url="http://testserver") as test_client:
        yield test_client
    app.dependency_overrides.clear()


def test_status_endpoint(ike_client: TestClient):
    """GET /api/v1/ike-assessment/status should return operational limits and profiles."""
    response = ike_client.get("/api/v1/ike-assessment/status")
    assert response.status_code == 200
    data = response.json()
    assert data["enabled"] is True
    assert "available_profiles" in data
    assert len(data["available_profiles"]) == 2
    profile_names = [p["name"] for p in data["available_profiles"]]
    assert "IKEV1_MAIN_MODE_DISCOVERY" in profile_names
    assert "IKEV2_DEFAULT_EXPERIMENTAL" in profile_names


def test_create_job_rejects_missing_authorization(ike_client: TestClient):
    """POST /api/v1/ike-assessment/jobs should return 403 when authorization is missing."""
    payload = {
        "job_name": "Unauthorized Test",
        "operator_id": "",
        "authorization_reference": "",
        "authorization_attestation": "short",
        "profile_name": "IKEV1_MAIN_MODE_DISCOVERY",
        "target": "192.168.1.50",
    }
    response = ike_client.post("/api/v1/ike-assessment/jobs", json=payload)
    assert response.status_code in (403, 422)


def test_create_job_rejects_cidr(ike_client: TestClient):
    """POST /api/v1/ike-assessment/jobs should return 422 when target is a CIDR sweep."""
    payload = {
        "job_name": "CIDR Test",
        "operator_id": "op-sec",
        "authorization_reference": "AUTH-100",
        "authorization_attestation": "Authorized pentest engagement #100",
        "profile_name": "IKEV1_MAIN_MODE_DISCOVERY",
        "target": "192.168.1.0/24",
    }
    response = ike_client.post("/api/v1/ike-assessment/jobs", json=payload)
    assert response.status_code == 422
    assert "CIDR" in response.json()["detail"]


def test_create_job_records_tool_unavailable(ike_client: TestClient):
    """POST /api/v1/ike-assessment/jobs records TOOL_UNAVAILABLE truthfully when binary missing."""
    payload = {
        "job_name": "Probe Missing Tool",
        "operator_id": "op-sec",
        "authorization_reference": "AUTH-100",
        "authorization_attestation": "Authorized pentest engagement #100",
        "profile_name": "IKEV1_MAIN_MODE_DISCOVERY",
        "target": "192.168.1.50",
    }
    with patch("app.protocol.ike_scan.runner.detect_ike_scan_binary") as mock_detect:
        mock_detect.return_value = IkeBinaryInfo(
            is_available=False,
            error_message="ike-scan binary not installed",
        )
        response = ike_client.post("/api/v1/ike-assessment/jobs", json=payload)
        assert response.status_code == 201
        data = response.json()
        assert data["status"] == "TOOL_UNAVAILABLE"
        assert len(data["results"]) == 1
        assert data["results"][0]["response_category"] == "TOOL_UNAVAILABLE"


def test_create_job_and_retrieve_success(ike_client: TestClient):
    """POST /api/v1/ike-assessment/jobs completes probe and persists evidence."""
    payload = {
        "job_name": "Authorized IKE Probe",
        "operator_id": "op-sec",
        "authorization_reference": "AUTH-100",
        "authorization_attestation": "Authorized pentest engagement #100",
        "profile_name": "IKEV1_MAIN_MODE_DISCOVERY",
        "target": "192.168.1.50",
        "port": 500,
    }
    mock_bytes = CANNED_IKE_SCAN_OUT.encode("utf-8")
    mock_sha = hashlib.sha256(mock_bytes).hexdigest()

    with patch("app.protocol.ike_scan.runner.detect_ike_scan_binary") as mock_detect, \
         patch("app.protocol.ike_scan.service.run_ike_scan") as mock_run:
        mock_detect.return_value = IkeBinaryInfo(is_available=True, path="/usr/bin/ike-scan", version="ike-scan 1.9")
        mock_run.return_value = ExecutionResult(
            status="COMPLETED",
            exit_code=0,
            raw_stdout=CANNED_IKE_SCAN_OUT,
            output_sha256=mock_sha,
            output_bytes_count=len(mock_bytes),
            tool_version="ike-scan 1.9",
            diagnostic_message=None,
            executed_argv=["ike-scan", "--retry=2", "192.168.1.50"],
        )

        response = ike_client.post("/api/v1/ike-assessment/jobs", json=payload)
        assert response.status_code == 201
        job_data = response.json()
        assert job_data["status"] == "COMPLETED"
        assert job_data["target_ip"] == "192.168.1.50"
        assert job_data["raw_output_sha256"] == mock_sha
        assert len(job_data["results"]) == 1

        result = job_data["results"][0]
        assert result["response_category"] == "RESPONDED_HANDSHAKE"
        assert result["ike_version"] == "IKEv1"
        assert len(result["transforms_returned"]) == 1
        assert result["transforms_returned"][0]["encr"] == "3DES"

        # GET /jobs/{job_id}
        job_id = job_data["id"]
        get_res = ike_client.get(f"/api/v1/ike-assessment/jobs/{job_id}")
        assert get_res.status_code == 200
        assert get_res.json()["id"] == job_id


def test_concordance_api_empty_analysis(ike_client: TestClient):
    """GET /api/v1/ike-assessment/analyses/{analysis_id}/concordance returns empty list when none exist."""
    fake_id = uuid.uuid4()
    response = ike_client.get(f"/api/v1/ike-assessment/analyses/{fake_id}/concordance")
    assert response.status_code == 200
    assert response.json() == []
