"""API contract tests for Stage 5 Dataset Factory, Sessions, Splits, and Benchmarks."""

import asyncio

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import Settings
from app.db.base import Base
from app.db.session import get_db_session
from app.main import create_app


@pytest.fixture
def test_settings(temp_storage_dir: str) -> Settings:
    return Settings(
        app_name="TunnelTrace AI Test",
        app_env="testing",
        app_debug=True,
        app_log_level="INFO",
        database_url="sqlite+aiosqlite:///:memory:",
        storage_root=temp_storage_dir,
        cors_allowed_origins=["http://localhost:3000"],
    )


@pytest.fixture
def db_session_factory():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    session_factory = async_sessionmaker(
        bind=engine, class_=AsyncSession, expire_on_commit=False
    )

    async def _init_tables():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    asyncio.run(_init_tables())
    yield session_factory

    async def _dispose():
        await engine.dispose()

    asyncio.run(_dispose())


@pytest.fixture
def test_client(test_settings: Settings, db_session_factory) -> TestClient:
    app = create_app(test_settings)

    async def _override_db():
        async with db_session_factory() as session:
            yield session

    app.dependency_overrides[get_db_session] = _override_db
    return TestClient(app)


def test_dataset_api_lifecycle(test_client: TestClient):
    """Test full dataset lifecycle: create family, create version, add sessions, partition, export manifest and card."""
    # 1. Create dataset family
    resp = test_client.post(
        "/api/v1/datasets",
        json={
            "name": "TunnelTrace_Native_IPsec",
            "vpn_technology": "IPSEC_NATIVE",
            "role": "PRIMARY",
            "description": "Primary corpus generated from strongSwan testbed",
        },
    )
    assert resp.status_code == 201
    ds_data = resp.json()
    dataset_id = ds_data["id"]
    assert ds_data["name"] == "TunnelTrace_Native_IPsec"
    assert ds_data["vpn_technology"] == "IPSEC_NATIVE"

    # 2. List datasets
    resp = test_client.get("/api/v1/datasets")
    assert resp.status_code == 200
    datasets = resp.json()
    assert any(d["id"] == dataset_id for d in datasets)

    # 3. Create dataset version
    resp = test_client.post(
        f"/api/v1/datasets/{dataset_id}/versions",
        json={"version_tag": "v1.0.0"},
    )
    assert resp.status_code == 201
    version_data = resp.json()
    version_id = version_data["id"]
    assert version_data["version_tag"] == "v1.0.0"
    assert version_data["status"] == "DRAFT"

    # 4. Add sessions (e.g. Web, VoIP, OOD_HOLDOUT)
    session_payloads = [
        {
            "workload_class": "Web",
            "workload_profile_id": "web_prof_1",
            "workload_seed": 42,
            "scenario_id": "scen_web_1",
            "mode": "TUNNEL",
            "ip_version": "IPv4",
            "cipher_suite": "aes128gcm16",
            "pfs_status": "ENABLED",
            "is_nat_t": False,
            "encrypted_capture_sha256": "1111111111111111111111111111111111111111111111111111111111111111",
            "duration_seconds": 5.0,
            "packet_count": 100,
            "byte_count": 25000,
        },
        {
            "workload_class": "VoIP",
            "workload_profile_id": "voip_prof_1",
            "workload_seed": 42,
            "scenario_id": "scen_voip_1",
            "mode": "TRANSPORT",
            "ip_version": "IPv6",
            "cipher_suite": "chacha20poly1305",
            "pfs_status": "DISABLED",
            "is_nat_t": True,
            "encrypted_capture_sha256": "2222222222222222222222222222222222222222222222222222222222222222",
            "duration_seconds": 5.0,
            "packet_count": 200,
            "byte_count": 32000,
        },
        {
            "workload_class": "OOD_HOLDOUT",
            "workload_profile_id": "ood_prof_1",
            "workload_seed": 99,
            "scenario_id": "scen_ood_1",
            "mode": "TUNNEL",
            "ip_version": "IPv4",
            "cipher_suite": "aes256gcm16",
            "pfs_status": "ENABLED",
            "is_nat_t": False,
            "encrypted_capture_sha256": "3333333333333333333333333333333333333333333333333333333333333333",
            "duration_seconds": 3.0,
            "packet_count": 50,
            "byte_count": 8000,
        },
    ]

    for p in session_payloads:
        resp = test_client.post(
            f"/api/v1/datasets/versions/{version_id}/sessions",
            json=p,
        )
        assert resp.status_code == 201
        assert resp.json()["quality_status"] == "ACCEPTED"

    # 5. List sessions
    resp = test_client.get(f"/api/v1/datasets/versions/{version_id}/sessions")
    assert resp.status_code == 200
    sessions = resp.json()
    assert len(sessions) == 3

    # 6. Partition version
    resp = test_client.post(
        f"/api/v1/datasets/versions/{version_id}/partition",
        json={"train_ratio": 0.50, "val_ratio": 0.25, "test_ratio": 0.25, "random_seed": 42},
    )
    assert resp.status_code == 200
    part_data = resp.json()
    assert part_data["is_clean"] is True
    assert part_data["total_assigned"] == 3
    assert "OOD_HOLDOUT" in part_data["split_counts"]
    assert part_data["split_counts"]["OOD_HOLDOUT"] == 1

    # 7. Get splits summary
    resp = test_client.get(f"/api/v1/datasets/versions/{version_id}/splits")
    assert resp.status_code == 200
    splits_summary = resp.json()
    assert splits_summary["is_clean"] is True
    assert splits_summary["total_splits"] == 3

    # 8. Export manifest
    resp = test_client.get(f"/api/v1/datasets/versions/{version_id}/manifest")
    assert resp.status_code == 200
    manifest = resp.json()
    assert manifest["dataset_name"] == "TunnelTrace_Native_IPsec"
    assert manifest["version_tag"] == "v1.0.0"
    assert manifest["total_sessions"] == 3
    assert "manifest_sha256" in manifest

    # 9. Get dataset card (markdown)
    resp = test_client.get(f"/api/v1/datasets/versions/{version_id}/card")
    assert resp.status_code == 200
    assert "text/markdown" in resp.headers["content-type"]
    assert "# Dataset Card: TunnelTrace_Native_IPsec (v1.0.0)" in resp.text
    assert "POINT_A_PURGED_ENCRYPTED_WAN_ONLY" in resp.text


def test_matrix_coverage_endpoint(test_client: TestClient):
    """Test matrix coverage query endpoint."""
    resp = test_client.get("/api/v1/datasets/matrix/coverage")
    assert resp.status_code == 200
    data = resp.json()
    assert "total_planned_scenarios" in data
    assert "active_sessions_analyzed" in data
    assert "dimension_coverage" in data


def test_external_benchmark_inventory_endpoint(test_client: TestClient):
    """Test external benchmark inventory query endpoint."""
    resp = test_client.get("/api/v1/datasets/external-benchmark/inventory")
    assert resp.status_code == 200
    data = resp.json()
    assert data["dataset_name"] == "UNB_CIC_ISCXVPN2016"
    assert data["vpn_technology"] == "OPENVPN"
    assert data["role"] == "SUPPORTING_BENCHMARK"
    assert "DOMAIN SHIFT NOTICE" in data["domain_shift_notice"]
