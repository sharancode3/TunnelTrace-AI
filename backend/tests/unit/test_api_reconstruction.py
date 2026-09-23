"""API contract tests for Stage 4 Reconstruction endpoints."""

import asyncio
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import Settings
from app.db.base import Base
from app.db.models.capture import AnalysisRun, Capture
from app.db.models.reconstruction import (
    ChildSecurityAssociation,
    ESPFlow,
    IKESecurityAssociation,
    IKESession,
    TrafficSelector,
)
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
    session_factory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)

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


def test_reconstruction_api_lifecycle(test_client: TestClient, db_session_factory):
    """Test full querying of IKE sessions, SAs, SA graph, and flows via API."""
    analysis_id = uuid.uuid4()
    capture_id = uuid.uuid4()
    session_id = uuid.uuid4()
    ike_sa_id = uuid.uuid4()
    child_sa_id = uuid.uuid4()
    flow_id = uuid.uuid4()

    async def _seed_data():
        async with db_session_factory() as db:
            cap = Capture(
                id=capture_id,
                capture_source="OFFLINE_UPLOAD",
                capture_format="PCAP",
                original_filename="test.pcap",
                storage_path="captures/test/raw.pcap",
                file_size_bytes=1000,
                sha256_hash="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            )
            db.add(cap)

            analysis = AnalysisRun(
                id=analysis_id,
                capture_id=capture_id,
                status="COMPLETED",
                current_stage="COMPLETED",
            )
            db.add(analysis)

            ike_sess = IKESession(
                id=session_id,
                analysis_id=analysis_id,
                initiator_spi="1122334455667788",
                responder_spi="8877665544332211",
                ike_version="IKEv2",
                initiator_ip="198.51.100.1",
                responder_ip="198.51.100.2",
                first_observed_at=10.0,
                last_observed_at=10.5,
                lifecycle_state="ACTIVE_INFERRED",
                is_nat_detected=False,
                retransmission_count=0,
                packet_count=4,
                evidence_state="VERIFIED",
                frame_numbers=[1, 2, 3, 4],
            )
            db.add(ike_sess)

            ike_sa = IKESecurityAssociation(
                id=ike_sa_id,
                session_id=session_id,
                encryption_algorithm="AES-GCM-16-256",
                key_length_bits=256,
                prf_algorithm="PRF_HMAC_SHA2_256",
                integrity_algorithm="NONE / NOT_APPLICABLE",
                dh_group="ECP-256 (DH19)",
                selection_evidence_state="VERIFIED",
                established_at=10.5,
                evidence_state="VERIFIED",
            )
            db.add(ike_sa)

            child_sa = ChildSecurityAssociation(
                id=child_sa_id,
                analysis_id=analysis_id,
                ike_sa_id=ike_sa_id,
                protocol="ESP",
                inbound_spi="0x11111111",
                outbound_spi="0x22222222",
                src_ip="198.51.100.1",
                dst_ip="198.51.100.2",
                mode="UNKNOWN",
                mode_evidence_state="UNKNOWN",
                pfs_status="UNKNOWN",
                pfs_evidence_state="UNKNOWN",
                first_observed_at=11.0,
                last_observed_at=15.0,
                lifecycle_state="ACTIVE_INFERRED",
                evidence_state="VERIFIED",
            )
            db.add(child_sa)

            ts = TrafficSelector(
                id=uuid.uuid4(),
                child_sa_id=child_sa_id,
                direction="INITIATOR",
                ip_subnet="10.10.1.0/24",
                evidence_state="VERIFIED",
            )
            db.add(ts)

            flow = ESPFlow(
                id=flow_id,
                analysis_id=analysis_id,
                child_sa_id=child_sa_id,
                spi="0x11111111",
                reverse_spi="0x22222222",
                src_ip="198.51.100.1",
                dst_ip="198.51.100.2",
                ip_version="IPv4",
                is_nat_t=False,
                orientation_basis="FIRST_SEEN",
                start_time=11.0,
                end_time=15.0,
                duration_seconds=4.0,
                packet_count=10,
                byte_count=1200,
                forward_packets=6,
                forward_bytes=700,
                reverse_packets=4,
                reverse_bytes=500,
                association_state="PAIRED_BIDIRECTIONAL",
                end_reason="CAPTURE_ENDED",
            )
            db.add(flow)
            await db.commit()

    asyncio.run(_seed_data())

    # 1. GET /ike-sessions
    res = test_client.get(f"/api/v1/analyses/{analysis_id}/ike-sessions")
    assert res.status_code == 200
    sessions = res.json()
    assert len(sessions) == 1
    assert sessions[0]["initiator_spi"] == "1122334455667788"
    assert sessions[0]["responder_spi"] == "8877665544332211"

    # 2. GET /ike-sessions/{session_id}
    res = test_client.get(f"/api/v1/analyses/{analysis_id}/ike-sessions/{session_id}")
    assert res.status_code == 200
    detail = res.json()
    assert detail["parent_sa"]["encryption_algorithm"] == "AES-GCM-16-256"
    assert len(detail["child_sas"]) == 1
    assert detail["child_sas"][0]["inbound_spi"] == "0x11111111"
    assert len(detail["child_sas"][0]["traffic_selectors"]) == 1

    # 3. GET /security-associations
    res = test_client.get(f"/api/v1/analyses/{analysis_id}/security-associations")
    assert res.status_code == 200
    sas = res.json()
    assert len(sas) == 1
    assert sas[0]["inbound_spi"] == "0x11111111"
    assert sas[0]["outbound_spi"] == "0x22222222"
    assert sas[0]["mode"] == "UNKNOWN"

    # 4. GET /security-associations/graph
    res = test_client.get(f"/api/v1/analyses/{analysis_id}/security-associations/graph")
    assert res.status_code == 200
    graph = res.json()
    node_types = {n["type"] for n in graph["nodes"]}
    assert "peer" in node_types
    assert "session" in node_types
    assert "ike_sa" in node_types
    assert "child_sa" in node_types
    assert "flow" in node_types

    edge_labels = {e["label"] for e in graph["edges"]}
    assert "PARTICIPATES_IN" in edge_labels
    assert "NEGOTIATES" in edge_labels
    assert "PARENT_OF" in edge_labels
    assert "PROTECTS" in edge_labels

    # 5. GET /flows
    res = test_client.get(f"/api/v1/analyses/{analysis_id}/flows?limit=10&offset=0")
    assert res.status_code == 200
    flows_data = res.json()
    assert flows_data["total_flows"] == 1
    assert len(flows_data["items"]) == 1
    fl = flows_data["items"][0]
    assert fl["packet_count"] == 10
    assert fl["association_state"] == "PAIRED_BIDIRECTIONAL"

    # Invariant: No ML features or security scores in DTO
    assert "traffic_class" not in fl
    assert "confidence" not in fl
    assert "security_score" not in fl

    # 6. Unknown analysis returns 404
    bad_id = uuid.uuid4()
    res = test_client.get(f"/api/v1/analyses/{bad_id}/ike-sessions")
    assert res.status_code == 404
