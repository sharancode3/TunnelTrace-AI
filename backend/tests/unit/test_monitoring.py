"""Comprehensive unit tests for Continuous Monitoring:
- Schema contracts and secret scrubbing
- Sensor registration, token issuance, and constant-time authentication
- Scope authorization and cross-scope rejection (403 Forbidden)
- Append-only event ingestion idempotency and replay safety
- Sequence gap detection and source reboot/reset handling
- Capture drop accounting and quality warnings
- Dynamic freshness evaluation (UNKNOWN -> HEALTHY -> DEGRADED -> STALE)
- Non-deletion of SAs on sensor staleness (is_stale=True, zero deletion)
- Deterministic score non-interference (zero mutations to SecurityFindingModel or ComplianceEvaluationModel)
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from fastapi import status
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import settings
from app.db.base import Base
from app.db.models.monitoring import (
    MonitoredGateway,
    MonitoredSAState,
    MonitoredSensor,
    MonitoringEvent,
    SensorHealthState,
)
from app.db.models.security import ComplianceEvaluationModel, SecurityFindingModel
from app.db.session import get_db_session
from app.main import app
from app.monitoring.auth import (
    ScopeAuthorizationError,
    SensorAuthenticationError,
    generate_sensor_token,
    hash_token,
    validate_sensor_event_scope,
    verify_sensor_credential,
)
from app.monitoring.schema import (
    EventKind,
    EvidenceGrade,
    GatewayStatus,
    MonitoringEventBatchRequest,
    MonitoringEventDTO,
    RegisterGatewayRequest,
    RegisterSensorRequest,
    SAState,
    SensorHealthStatus,
    SensorStatus,
    SensorType,
)
from app.monitoring.service import MonitoringService


# ------------------------------------------------------------------------------
# In-Memory SQLite Test Fixtures
# ------------------------------------------------------------------------------


@pytest_asyncio.fixture
async def async_test_session():
    """Provides an isolated SQLite in-memory database session for monitoring tests."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    async with session_factory() as session:
        yield session

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


# ------------------------------------------------------------------------------
# 1. Schema Validation & Secret Scrubbing Tests
# ------------------------------------------------------------------------------


def test_schema_version_validation():
    """Rejects unsupported major schema versions."""
    now_utc = datetime.now(timezone.utc)
    # Valid v1
    dto = MonitoringEventDTO(
        sensor_id=uuid.uuid4(),
        gateway_id=uuid.uuid4(),
        authorized_scope="198.51.100.0/24",
        event_kind=EventKind.GATEWAY_HEARTBEAT,
        source_timestamp=now_utc,
        schema_version="v1.0.0",
    )
    assert dto.schema_version == "v1.0.0"

    # Invalid v2
    with pytest.raises(ValueError, match="Unsupported schema_version"):
        MonitoringEventDTO(
            sensor_id=uuid.uuid4(),
            gateway_id=uuid.uuid4(),
            authorized_scope="198.51.100.0/24",
            event_kind=EventKind.GATEWAY_HEARTBEAT,
            source_timestamp=now_utc,
            schema_version="v2.0.0",
        )


def test_unreasonable_future_timestamp_rejected():
    """Rejects timestamps more than 60s into the future."""
    future_time = datetime.now(timezone.utc) + timedelta(minutes=5)
    with pytest.raises(ValueError, match="in the future"):
        MonitoringEventDTO(
            sensor_id=uuid.uuid4(),
            gateway_id=uuid.uuid4(),
            authorized_scope="198.51.100.0/24",
            event_kind=EventKind.GATEWAY_HEARTBEAT,
            source_timestamp=future_time,
        )


def test_secret_scrubbing_invariant():
    """Ensures secret keys (PSK, private_key, password) are scrubbed before persistence."""
    now_utc = datetime.now(timezone.utc)
    raw_event = {
        "sensor_id": str(uuid.uuid4()),
        "gateway_id": str(uuid.uuid4()),
        "authorized_scope": "198.51.100.0/24",
        "event_kind": "GATEWAY_IKE_SA_ESTABLISHED",
        "source_timestamp": now_utc.isoformat(),
        "psk": "super_secret_preshared_key_12345",
        "private_key": "-----BEGIN RSA PRIVATE KEY-----...",
        "payload": {
            "tunnel_id": "tun0",
            "auth_key": "raw_auth_material_abc",
            "safe_metric": 42,
        },
    }
    dto = MonitoringEventDTO.model_validate(raw_event)
    assert not hasattr(dto, "psk")
    assert dto.payload is not None
    assert "auth_key" not in dto.payload
    assert dto.payload.get("safe_metric") == 42


# ------------------------------------------------------------------------------
# 2. Sensor Authentication & Scope Authorization Tests
# ------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sensor_token_issuance_and_authentication(async_test_session: AsyncSession):
    """Registers a sensor, verifies token hash generation, and authenticates via verify_sensor_credential."""
    gw = await MonitoringService.register_gateway(
        async_test_session,
        RegisterGatewayRequest(
            name="HQ-Gateway-East",
            gateway_ip="198.51.100.1",
            authorized_scope="198.51.100.0/24",
            operator_id="op_alice",
            authorization_reference="REQ-SEC-2026-001",
        ),
    )

    sensor, raw_token = await MonitoringService.register_sensor(
        async_test_session,
        RegisterSensorRequest(
            sensor_name="collector-hq-01",
            sensor_type=SensorType.GATEWAY_COLLECTOR,
            gateway_id=gw.id,
            authorized_scope="198.51.100.0/24",
        ),
    )

    assert raw_token.startswith("tt_sn_")
    assert sensor.token_prefix == f"{raw_token[:12]}..."
    assert sensor.auth_token_hash == hash_token(raw_token)

    # Verify authentication success with correct token
    authed_sensor = await verify_sensor_credential(async_test_session, raw_token)
    assert authed_sensor is not None
    assert authed_sensor.id == sensor.id

    # Verify authentication failure with wrong token
    with pytest.raises(SensorAuthenticationError, match="Invalid sensor authentication credential"):
        await verify_sensor_credential(async_test_session, "tt_sn_invalid_bogus_token")


@pytest.mark.asyncio
async def test_revoked_sensor_rejected(async_test_session: AsyncSession):
    """Ensures a revoked sensor credential is rejected with HTTP 403 Forbidden."""
    gw = await MonitoringService.register_gateway(
        async_test_session,
        RegisterGatewayRequest(
            name="Branch-Gateway-01",
            gateway_ip="198.51.100.2",
            authorized_scope="198.51.100.0/24",
            operator_id="op_bob",
            authorization_reference="REQ-SEC-2026-002",
        ),
    )

    sensor, raw_token = await MonitoringService.register_sensor(
        async_test_session,
        RegisterSensorRequest(
            sensor_name="collector-branch-01",
            sensor_type=SensorType.GATEWAY_COLLECTOR,
            gateway_id=gw.id,
            authorized_scope="198.51.100.0/24",
        ),
    )

    # Revoke sensor
    await MonitoringService.revoke_sensor(async_test_session, sensor.id)

    # Attempt to authenticate
    with pytest.raises(SensorAuthenticationError) as exc_info:
        await verify_sensor_credential(async_test_session, raw_token)
    assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
    assert "revoked" in str(exc_info.value.detail)


def test_cross_scope_and_cross_gateway_rejection():
    """Tests strict rejection when an authenticated sensor attempts cross-scope or cross-gateway ingestion."""
    gw_a_id = uuid.uuid4()
    gw_b_id = uuid.uuid4()
    sensor = MonitoredSensor(
        id=uuid.uuid4(),
        sensor_name="sensor-scoped-01",
        sensor_type="GATEWAY_COLLECTOR",
        gateway_id=gw_a_id,
        authorized_scope="198.51.100.0/24",
        auth_token_hash="dummy_hash",
        token_prefix="tt_sn_...",
        status="ACTIVE",
    )

    # Valid scope & gateway
    validate_sensor_event_scope(sensor, gw_a_id, "198.51.100.0/24")

    # Cross-gateway violation
    with pytest.raises(ScopeAuthorizationError, match="Cross-gateway authorization violation"):
        validate_sensor_event_scope(sensor, gw_b_id, "198.51.100.0/24")

    # Cross-scope violation
    with pytest.raises(ScopeAuthorizationError, match="Cross-scope authorization violation"):
        validate_sensor_event_scope(sensor, gw_a_id, "10.0.0.0/24")


# ------------------------------------------------------------------------------
# 3. Ingestion Idempotency & Replay Handling
# ------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_event_ingestion_idempotency(async_test_session: AsyncSession):
    """Submitting the exact same event_id multiple times must record duplicate_count without error."""
    gw = await MonitoringService.register_gateway(
        async_test_session,
        RegisterGatewayRequest(
            name="GW-Idempotency-Test",
            gateway_ip="198.51.100.3",
            authorized_scope="198.51.100.0/24",
            operator_id="op_admin",
            authorization_reference="CHG-9999",
        ),
    )
    sensor, _ = await MonitoringService.register_sensor(
        async_test_session,
        RegisterSensorRequest(
            sensor_name="collector-idem-01",
            sensor_type=SensorType.GATEWAY_COLLECTOR,
            gateway_id=gw.id,
            authorized_scope="198.51.100.0/24",
        ),
    )

    shared_event_id = uuid.uuid4()
    now_utc = datetime.now(timezone.utc)
    event_dto = MonitoringEventDTO(
        event_id=shared_event_id,
        sensor_id=sensor.id,
        gateway_id=gw.id,
        authorized_scope="198.51.100.0/24",
        event_kind=EventKind.GATEWAY_HEARTBEAT,
        source_timestamp=now_utc,
        sequence_number=1,
    )

    # 1. First ingestion
    batch_1 = MonitoringEventBatchRequest(events=[event_dto])
    res_1 = await MonitoringService.ingest_event_batch(async_test_session, sensor, batch_1)
    assert res_1.accepted_count == 1
    assert res_1.duplicate_count == 0

    # 2. Second ingestion with identical event_id
    batch_2 = MonitoringEventBatchRequest(events=[event_dto])
    res_2 = await MonitoringService.ingest_event_batch(async_test_session, sensor, batch_2)
    assert res_2.accepted_count == 0
    assert res_2.duplicate_count == 1

    # Verify only 1 row exists in database
    count = await async_test_session.scalar(
        select(func.count()).select_from(MonitoringEvent).where(MonitoringEvent.event_id == shared_event_id)
    )
    assert count == 1


# ------------------------------------------------------------------------------
# 4. Sequence Gap & Source Reset Handling
# ------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sequence_gap_and_reset_detection(async_test_session: AsyncSession):
    """Detects sequence gaps (e.g. 1 -> 5) and sequence resets (e.g. 5 -> 1 on reboot)."""
    gw = await MonitoringService.register_gateway(
        async_test_session,
        RegisterGatewayRequest(
            name="GW-Seq-Test",
            gateway_ip="198.51.100.4",
            authorized_scope="198.51.100.0/24",
            operator_id="op_admin",
            authorization_reference="CHG-0001",
        ),
    )
    sensor, _ = await MonitoringService.register_sensor(
        async_test_session,
        RegisterSensorRequest(
            sensor_name="collector-seq-01",
            sensor_type=SensorType.GATEWAY_COLLECTOR,
            gateway_id=gw.id,
            authorized_scope="198.51.100.0/24",
        ),
    )

    now = datetime.now(timezone.utc)

    # 1. Event seq=1
    e1 = MonitoringEventDTO(
        sensor_id=sensor.id,
        gateway_id=gw.id,
        authorized_scope="198.51.100.0/24",
        event_kind=EventKind.GATEWAY_HEARTBEAT,
        source_timestamp=now,
        sequence_number=1,
    )
    res_1 = await MonitoringService.ingest_event_batch(async_test_session, sensor, MonitoringEventBatchRequest(events=[e1]))
    assert res_1.sequence_gaps_detected == 0

    # 2. Event seq=5 (skipped 2, 3, 4)
    e2 = MonitoringEventDTO(
        sensor_id=sensor.id,
        gateway_id=gw.id,
        authorized_scope="198.51.100.0/24",
        event_kind=EventKind.GATEWAY_HEARTBEAT,
        source_timestamp=now + timedelta(seconds=1),
        sequence_number=5,
    )
    res_2 = await MonitoringService.ingest_event_batch(async_test_session, sensor, MonitoringEventBatchRequest(events=[e2]))
    assert res_2.sequence_gaps_detected == 1
    assert any("skipped 3 events" in w for w in res_2.warnings)

    # Check health projection: must be DEGRADED due to sequence gap
    health_list = await MonitoringService.get_sensor_health_summary(async_test_session)
    s_health = next(h for h in health_list if h.sensor_id == sensor.id)
    assert s_health.current_health == SensorHealthStatus.DEGRADED
    assert s_health.sequence_gaps_count == 1
    assert "SEQUENCE_GAP_DETECTED" in s_health.active_quality_warnings

    # 3. Event seq=1 (Source reboot/reset)
    e3 = MonitoringEventDTO(
        sensor_id=sensor.id,
        gateway_id=gw.id,
        authorized_scope="198.51.100.0/24",
        event_kind=EventKind.GATEWAY_HEARTBEAT,
        source_timestamp=now + timedelta(seconds=2),
        sequence_number=1,
    )
    res_3 = await MonitoringService.ingest_event_batch(async_test_session, sensor, MonitoringEventBatchRequest(events=[e3]))
    assert any("Sequence reset" in w for w in res_3.warnings)


# ------------------------------------------------------------------------------
# 5. Capture Sensor Drops & Quality Warnings
# ------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_capture_sensor_drops_reporting(async_test_session: AsyncSession):
    """Verifies that capture drop counters update total_drops_reported and transition sensor to DEGRADED."""
    gw = await MonitoringService.register_gateway(
        async_test_session,
        RegisterGatewayRequest(
            name="GW-Capture-Drops-Test",
            gateway_ip="198.51.100.5",
            authorized_scope="198.51.100.0/24",
            operator_id="op_admin",
            authorization_reference="CHG-0002",
        ),
    )
    sensor, _ = await MonitoringService.register_sensor(
        async_test_session,
        RegisterSensorRequest(
            sensor_name="pcap-sensor-eth0",
            sensor_type=SensorType.CAPTURE_SENSOR,
            gateway_id=gw.id,
            authorized_scope="198.51.100.0/24",
        ),
    )

    now = datetime.now(timezone.utc)
    evt = MonitoringEventDTO(
        sensor_id=sensor.id,
        gateway_id=gw.id,
        authorized_scope="198.51.100.0/24",
        event_kind=EventKind.CAPTURE_DROPS_RECORDED,
        source_timestamp=now,
        interface_name="veth-wan",
        packet_count=1000,
        drop_count=45,
    )

    res = await MonitoringService.ingest_event_batch(async_test_session, sensor, MonitoringEventBatchRequest(events=[evt]))
    assert res.accepted_count == 1
    assert any("Capture drops reported: 45" in w for w in res.warnings)

    health_list = await MonitoringService.get_sensor_health_summary(async_test_session)
    s_health = next(h for h in health_list if h.sensor_id == sensor.id)
    assert s_health.current_health == SensorHealthStatus.DEGRADED
    assert s_health.total_drops_reported == 45
    assert "CAPTURE_DROPS_RECORDED" in s_health.active_quality_warnings


# ------------------------------------------------------------------------------
# 6. Freshness, Stale & Unknown Semantics (Non-Deletion Invariant)
# ------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_freshness_state_machine_and_sa_non_deletion(async_test_session: AsyncSession):
    """Verifies:
    1. Zero events -> UNKNOWN (never healthy).
    2. Fresh events -> HEALTHY.
    3. Elapsed > freshness_window_seconds -> STALE.
    4. SA Non-Deletion Invariant: Stale sensor marks active SA as is_stale=True, but never deletes it!
    """
    gw = await MonitoringService.register_gateway(
        async_test_session,
        RegisterGatewayRequest(
            name="GW-Freshness-Test",
            gateway_ip="198.51.100.6",
            authorized_scope="198.51.100.0/24",
            operator_id="op_admin",
            authorization_reference="CHG-0003",
        ),
    )
    sensor, _ = await MonitoringService.register_sensor(
        async_test_session,
        RegisterSensorRequest(
            sensor_name="collector-fresh-01",
            sensor_type=SensorType.GATEWAY_COLLECTOR,
            gateway_id=gw.id,
            authorized_scope="198.51.100.0/24",
            freshness_window_seconds=10,  # 10 second freshness window
        ),
    )

    # 1. Zero events -> UNKNOWN
    health_initial = await MonitoringService.get_sensor_health_summary(async_test_session)
    h_init = next(h for h in health_initial if h.sensor_id == sensor.id)
    assert h_init.current_health == SensorHealthStatus.UNKNOWN
    assert h_init.total_events_received == 0

    # 2. Ingest SA Established event
    now = datetime.now(timezone.utc)
    sa_event = MonitoringEventDTO(
        sensor_id=sensor.id,
        gateway_id=gw.id,
        authorized_scope="198.51.100.0/24",
        event_kind=EventKind.GATEWAY_IKE_SA_ESTABLISHED,
        source_timestamp=now,
        initiator_spi="0102030405060708",
        responder_spi="090a0b0c0d0e0f10",
        local_endpoint="198.51.100.6:500",
        remote_endpoint="198.51.100.10:500",
        cipher_suite="AES_GCM_16_256/PRF_HMAC_SHA2_256/MODP_2048",
    )
    await MonitoringService.ingest_event_batch(async_test_session, sensor, MonitoringEventBatchRequest(events=[sa_event]))

    # Verify HEALTHY immediately after event
    health_fresh = await MonitoringService.get_sensor_health_summary(async_test_session)
    h_fresh = next(h for h in health_fresh if h.sensor_id == sensor.id)
    assert h_fresh.current_health == SensorHealthStatus.HEALTHY
    assert h_fresh.is_stale is False

    # Verify SA state is ESTABLISHED
    sa_list = await MonitoringService.get_active_sa_states(async_test_session, gateway_id=gw.id)
    assert len(sa_list) == 1
    assert sa_list[0].state == SAState.ESTABLISHED
    assert sa_list[0].is_stale is False

    # 3. Simulate passage of time: set last_received_at to 30 seconds ago (freshness window = 10s)
    health_row = await async_test_session.get(SensorHealthState, sensor.id)
    assert health_row is not None
    health_row.last_received_at = now - timedelta(seconds=30)
    await async_test_session.commit()

    # Query health: should dynamically evaluate to STALE
    health_stale = await MonitoringService.get_sensor_health_summary(async_test_session)
    h_stale = next(h for h in health_stale if h.sensor_id == sensor.id)
    assert h_stale.current_health == SensorHealthStatus.STALE
    assert h_stale.is_stale is True
    assert "Stale telemetry" in h_stale.health_reason

    # 4. Verify SA Non-Deletion Invariant: SA remains in database with is_stale=True
    sa_after_stale = await MonitoringService.get_active_sa_states(async_test_session, gateway_id=gw.id)
    assert sa_after_stale[0].state == SAState.ESTABLISHED  # SA state is preserved!
    assert sa_after_stale[0].is_stale is True  # Marked stale, NOT deleted
    assert "Stale telemetry" in (sa_after_stale[0].staleness_reason or "")


# ------------------------------------------------------------------------------
# 7. Explicit IKE and Child SA Lifecycle Transitions
# ------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ike_and_child_sa_lifecycle_transitions(async_test_session: AsyncSession):
    """Traces full explicit SA lifecycle:
    INIT_STARTED -> ESTABLISHED -> CHILD_ESTABLISHED -> CHILD_REKEYED -> CHILD_DELETED.
    """
    gw = await MonitoringService.register_gateway(
        async_test_session,
        RegisterGatewayRequest(
            name="GW-Lifecycle-Test",
            gateway_ip="198.51.100.7",
            authorized_scope="198.51.100.0/24",
            operator_id="op_admin",
            authorization_reference="CHG-0004",
        ),
    )
    sensor, _ = await MonitoringService.register_sensor(
        async_test_session,
        RegisterSensorRequest(
            sensor_name="collector-lifecycle-01",
            sensor_type=SensorType.GATEWAY_COLLECTOR,
            gateway_id=gw.id,
            authorized_scope="198.51.100.0/24",
        ),
    )

    t0 = datetime.now(timezone.utc)
    init_spi = "aabbccddeeff0011"
    child_in = "12345678"

    # Step 1: IKE SA Init
    e_init = MonitoringEventDTO(
        sensor_id=sensor.id,
        gateway_id=gw.id,
        authorized_scope="198.51.100.0/24",
        event_kind=EventKind.GATEWAY_IKE_SA_INIT_STARTED,
        source_timestamp=t0,
        initiator_spi=init_spi,
    )
    await MonitoringService.ingest_event_batch(async_test_session, sensor, MonitoringEventBatchRequest(events=[e_init]))

    sa_states = await MonitoringService.get_active_sa_states(async_test_session, gateway_id=gw.id)
    assert len(sa_states) == 1
    assert sa_states[0].sa_type == "IKE_SA"
    assert sa_states[0].state == SAState.INITIATING

    # Step 2: IKE SA Established
    e_est = MonitoringEventDTO(
        sensor_id=sensor.id,
        gateway_id=gw.id,
        authorized_scope="198.51.100.0/24",
        event_kind=EventKind.GATEWAY_IKE_SA_ESTABLISHED,
        source_timestamp=t0 + timedelta(seconds=1),
        initiator_spi=init_spi,
        responder_spi="2233445566778899",
        cipher_suite="AES_GCM_16_256",
    )
    await MonitoringService.ingest_event_batch(async_test_session, sensor, MonitoringEventBatchRequest(events=[e_est]))

    sa_states = await MonitoringService.get_active_sa_states(async_test_session, gateway_id=gw.id)
    assert sa_states[0].state == SAState.ESTABLISHED
    assert sa_states[0].responder_spi == "2233445566778899"

    # Step 3: Child SA Established
    e_child = MonitoringEventDTO(
        sensor_id=sensor.id,
        gateway_id=gw.id,
        authorized_scope="198.51.100.0/24",
        event_kind=EventKind.GATEWAY_CHILD_SA_ESTABLISHED,
        source_timestamp=t0 + timedelta(seconds=2),
        initiator_spi=init_spi,
        child_spi_in=child_in,
        child_spi_out="87654321",
        cipher_suite="ESP:AES_GCM_16_256",
    )
    await MonitoringService.ingest_event_batch(async_test_session, sensor, MonitoringEventBatchRequest(events=[e_child]))

    sa_states = await MonitoringService.get_active_sa_states(async_test_session, gateway_id=gw.id)
    assert len(sa_states) == 2
    child_sa = next(s for s in sa_states if s.sa_type == "CHILD_SA")
    assert child_sa.state == SAState.ESTABLISHED
    assert child_sa.child_spi_in == child_in

    # Step 4: Child SA Rekeyed
    e_rekey = MonitoringEventDTO(
        sensor_id=sensor.id,
        gateway_id=gw.id,
        authorized_scope="198.51.100.0/24",
        event_kind=EventKind.GATEWAY_CHILD_SA_REKEYED,
        source_timestamp=t0 + timedelta(seconds=10),
        initiator_spi=init_spi,
        child_spi_in=child_in,
    )
    await MonitoringService.ingest_event_batch(async_test_session, sensor, MonitoringEventBatchRequest(events=[e_rekey]))

    sa_states = await MonitoringService.get_active_sa_states(async_test_session, gateway_id=gw.id)
    child_sa = next(s for s in sa_states if s.sa_type == "CHILD_SA")
    assert child_sa.state == SAState.REKEYED

    # Step 5: Child SA Deleted
    e_del = MonitoringEventDTO(
        sensor_id=sensor.id,
        gateway_id=gw.id,
        authorized_scope="198.51.100.0/24",
        event_kind=EventKind.GATEWAY_CHILD_SA_DELETED,
        source_timestamp=t0 + timedelta(seconds=20),
        initiator_spi=init_spi,
        child_spi_in=child_in,
    )
    await MonitoringService.ingest_event_batch(async_test_session, sensor, MonitoringEventBatchRequest(events=[e_del]))

    sa_states = await MonitoringService.get_active_sa_states(async_test_session, gateway_id=gw.id)
    child_sa = next(s for s in sa_states if s.sa_type == "CHILD_SA")
    assert child_sa.state == SAState.DELETED


# ------------------------------------------------------------------------------
# 8. Deterministic Score Non-Interference Invariant
# ------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_deterministic_score_non_interference(async_test_session: AsyncSession):
    """CRITICAL INVARIANT: Monitoring ingestion must NEVER create or mutate rows in
    SecurityFindingModel or ComplianceEvaluationModel. Score impact is strictly ZERO.
    """
    findings_before = await async_test_session.scalar(select(func.count()).select_from(SecurityFindingModel)) or 0
    compliance_before = await async_test_session.scalar(select(func.count()).select_from(ComplianceEvaluationModel)) or 0

    gw = await MonitoringService.register_gateway(
        async_test_session,
        RegisterGatewayRequest(
            name="GW-NonInterference",
            gateway_ip="198.51.100.8",
            authorized_scope="198.51.100.0/24",
            operator_id="op_admin",
            authorization_reference="CHG-0005",
        ),
    )
    sensor, _ = await MonitoringService.register_sensor(
        async_test_session,
        RegisterSensorRequest(
            sensor_name="collector-non-int",
            sensor_type=SensorType.GATEWAY_COLLECTOR,
            gateway_id=gw.id,
            authorized_scope="198.51.100.0/24",
        ),
    )

    now = datetime.now(timezone.utc)
    events = [
        MonitoringEventDTO(
            sensor_id=sensor.id,
            gateway_id=gw.id,
            authorized_scope="198.51.100.0/24",
            event_kind=EventKind.GATEWAY_IKE_SA_FAILED,
            source_timestamp=now,
            failure_reason="NO_PROPOSAL_CHOSEN: proposal mismatch in IKE_SA_INIT",
            failure_code="NO_PROPOSAL_CHOSEN",
        ),
        MonitoringEventDTO(
            sensor_id=sensor.id,
            gateway_id=gw.id,
            authorized_scope="198.51.100.0/24",
            event_kind=EventKind.CAPTURE_DROPS_RECORDED,
            source_timestamp=now + timedelta(seconds=1),
            drop_count=100,
        ),
    ]

    res = await MonitoringService.ingest_event_batch(async_test_session, sensor, MonitoringEventBatchRequest(events=events))
    assert res.accepted_count == 2

    findings_after = await async_test_session.scalar(select(func.count()).select_from(SecurityFindingModel)) or 0
    compliance_after = await async_test_session.scalar(select(func.count()).select_from(ComplianceEvaluationModel)) or 0

    assert findings_after == findings_before, "SecurityFindingModel was mutated by monitoring telemetry!"
    assert compliance_after == compliance_before, "ComplianceEvaluationModel was mutated by monitoring telemetry!"


# ------------------------------------------------------------------------------
# 9. REST API Integration Tests via TestClient
# ------------------------------------------------------------------------------


def test_rest_api_gateway_sensor_event_flow():
    """Validates the REST API endpoints using FastAPI TestClient with SQLite in-memory DB override."""
    from sqlalchemy.ext.asyncio import create_async_engine

    test_engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)

    async def init_tables():
        async with test_engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    import asyncio
    asyncio.run(init_tables())

    async_session = async_sessionmaker(test_engine, expire_on_commit=False, class_=AsyncSession)

    async def override_get_db():
        async with async_session() as s:
            yield s

    app.dependency_overrides[get_db_session] = override_get_db
    client = TestClient(app)

    try:
        # 1. Register Gateway
        gw_resp = client.post(
            "/api/v1/monitoring/gateways",
            json={
                "name": "API-Test-Gateway",
                "gateway_ip": "198.51.100.99",
                "authorized_scope": "198.51.100.0/24",
                "operator_id": "op_test",
                "authorization_reference": "REF-REST-01",
            },
        )
        assert gw_resp.status_code == 201
        gw_data = gw_resp.json()
        gw_id = gw_data["id"]

        # 2. Register Sensor
        sensor_resp = client.post(
            "/api/v1/monitoring/sensors",
            json={
                "sensor_name": "api-sensor-01",
                "sensor_type": "GATEWAY_COLLECTOR",
                "gateway_id": gw_id,
                "authorized_scope": "198.51.100.0/24",
                "freshness_window_seconds": 60,
                "reporting_interval_seconds": 30,
            },
        )
        assert sensor_resp.status_code == 201
        sensor_data = sensor_resp.json()
        sensor_id = sensor_data["id"]
        raw_token = sensor_data["raw_token"]
        assert raw_token.startswith("tt_sn_")

        # 3. Query initial health: must be UNKNOWN
        health_resp = client.get("/api/v1/monitoring/health")
        assert health_resp.status_code == 200
        health_items = health_resp.json()
        assert len(health_items) >= 1
        s_health = next(h for h in health_items if h["sensor_id"] == sensor_id)
        assert s_health["current_health"] == "UNKNOWN"

        # 4. Ingest Event with X-Sensor-Token
        now_iso = datetime.now(timezone.utc).isoformat()
        event_payload = {
            "events": [
                {
                    "event_id": str(uuid.uuid4()),
                    "sensor_id": sensor_id,
                    "gateway_id": gw_id,
                    "authorized_scope": "198.51.100.0/24",
                    "event_kind": "GATEWAY_IKE_SA_ESTABLISHED",
                    "source_timestamp": now_iso,
                    "initiator_spi": "1122334455667788",
                    "responder_spi": "8877665544332211",
                    "cipher_suite": "AES_GCM_16_256",
                }
            ]
        }
        ingest_resp = client.post(
            "/api/v1/monitoring/events",
            json=event_payload,
            headers={"X-Sensor-Token": raw_token},
        )
        assert ingest_resp.status_code == 200
        assert ingest_resp.json()["accepted_count"] == 1

        # 5. Query health again: must be HEALTHY
        health_resp_2 = client.get("/api/v1/monitoring/health")
        s_health_2 = next(h for h in health_resp_2.json() if h["sensor_id"] == sensor_id)
        assert s_health_2["current_health"] == "HEALTHY"
        assert s_health_2["total_events_received"] == 1

        # 6. Query SA States
        sa_resp = client.get(f"/api/v1/monitoring/sa-states?gateway_id={gw_id}")
        assert sa_resp.status_code == 200
        sas = sa_resp.json()
        assert len(sas) == 1
        assert sas[0]["initiator_spi"] == "1122334455667788"
        assert sas[0]["state"] == "ESTABLISHED"

        # 7. Query Timeline
        tl_resp = client.get(f"/api/v1/monitoring/timeline?gateway_id={gw_id}")
        assert tl_resp.status_code == 200
        tl_data = tl_resp.json()
        assert tl_data["total_count"] == 1
        assert tl_data["items"][0]["event_kind"] == "GATEWAY_IKE_SA_ESTABLISHED"

    finally:
        app.dependency_overrides.clear()
