"""Integration tests for Stage 3 Protocol Forensics Engine against real Stage 2 PCAPs.

Verifies deterministic TShark extraction, SHA-256 provenance, and ground truth alignment.
"""

import hashlib
import uuid
from pathlib import Path

import pytest
from app.capture.metadata import extract_capture_metadata
from app.capture.validation import validate_capture_file
from app.db.base import Base
from app.db.models.capture import AnalysisRun, Capture, ProtocolObservation
from app.protocol.service import ProtocolForensicsService
from app.services.storage.local import LocalStorageProvider
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

STAGE2_RUN01_WAN = Path("storage/lab/runs/tt-1790185654-25c4bc/captures/wan_encrypted.pcap")
STAGE2_RUN01_PLAINTEXT = Path("storage/lab/runs/tt-1790185654-25c4bc/captures/client_plaintext.pcap")
STAGE2_RUN04_IPV6 = Path("storage/lab/runs/tt-1790185891-f96398/captures/wan_encrypted.pcap")
STAGE2_RUN06_NATT = Path("storage/lab/runs/tt-1790185927-b1d8f6/captures/wan_encrypted.pcap")

FIXTURE_PCAPNG = Path("tests/fixtures/captures/real_tunnel_gcm.pcapng")
FIXTURE_ESP_ONLY = Path("tests/fixtures/captures/real_esp_only.pcap")


@pytest.fixture
def temp_storage_dir(tmp_path: Path) -> str:
    """Provide isolated temp storage path for tests."""
    return str(tmp_path)


@pytest.fixture
async def async_db(temp_storage_dir: str):
    """Isolated async SQLite database session for integration testing."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    session_factory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with session_factory() as session:
        yield session

    await engine.dispose()


@pytest.mark.asyncio
async def test_real_stage2_run01_tunnel_gcm_pfs(async_db: AsyncSession, temp_storage_dir: str):
    """Test 1: Ingest and analyze real Stage 2 Tunnel IPv4 AES-256-GCM + PFS PCAP."""
    assert STAGE2_RUN01_WAN.exists(), f"Ground-truth capture missing: {STAGE2_RUN01_WAN}"

    # 1. Structural check & SHA-256
    file_bytes = STAGE2_RUN01_WAN.read_bytes()
    expected_sha = hashlib.sha256(file_bytes).hexdigest().lower()
    assert expected_sha == "0eca936dffea9c38d0cedadd51f2a36084b3f7f03aa6fff9ef1fe58a988c70a9"

    fmt, _magic_type = validate_capture_file(STAGE2_RUN01_WAN)
    assert fmt.value == "PCAP"

    meta = extract_capture_metadata(STAGE2_RUN01_WAN)
    assert meta.packet_count == 12
    assert meta.file_size_bytes == 2774

    # 2. Register Capture
    storage = LocalStorageProvider(root_dir=temp_storage_dir)
    rel_path = "captures/run01_test/raw.pcap"
    storage.save_file(rel_path, file_bytes)

    capture_id = uuid.uuid4()
    cap = Capture(
        id=capture_id,
        capture_source="TESTBED_GENERATED",
        capture_format="PCAP",
        original_filename="wan_encrypted.pcap",
        storage_path=rel_path,
        file_size_bytes=len(file_bytes),
        sha256_hash=expected_sha,
        packet_count=12,
        validation_state="VALIDATED",
    )
    async_db.add(cap)

    # 3. Create AnalysisRun
    analysis_id = uuid.uuid4()
    analysis = AnalysisRun(
        id=analysis_id,
        capture_id=capture_id,
        status="QUEUED",
        current_stage="INGESTING",
        parser_engine="tshark",
        parser_version="unknown",
    )
    async_db.add(analysis)
    await async_db.commit()

    # 4. Execute Analysis with service
    service = ProtocolForensicsService(async_db)
    service.storage = storage
    summary = await service.execute_analysis(analysis_id)

    # 5. Assert ground-truth facts
    assert summary.ipsec_detected is True
    assert summary.outcome == "IPSEC_OBSERVED"
    assert summary.protocols_observed == ["ESP", "IKEv2"]
    assert summary.ip_versions_observed == ["IPv4"]
    assert summary.packet_counts["ike"] == 4
    assert summary.packet_counts["esp"] == 8
    assert summary.packet_counts["ah"] == 0
    # strongSwan floated IKE_AUTH to UDP/4500 after NAT-detection payloads
    assert summary.natt_observed is True
    assert "IKEv2" in summary.ike_versions_observed
    assert "IKE_SA_INIT" in summary.exchange_types_observed
    assert "IKE_AUTH" in summary.exchange_types_observed

    # Verify observed transforms match strongSwan requested scenario:
    # AES-GCM-16-256, PRF_HMAC_SHA2_256, ECP-256 (DH19)
    tf_names = [c.transform_name for c in summary.crypto_observations]
    assert any("AES-GCM" in name and "256" in name for name in tf_names)
    assert any("PRF_HMAC_SHA2_256" in name for name in tf_names)
    assert any("DH19" in name or "ECP-256" in name for name in tf_names)


@pytest.mark.asyncio
async def test_real_stage2_run01_plaintext_no_ipsec(async_db: AsyncSession, temp_storage_dir: str):
    """Test 2: Ingest real non-IPsec packet trace (client ICMP ping) -> verify NO_IPSEC_FOUND."""
    assert STAGE2_RUN01_PLAINTEXT.exists()
    file_bytes = STAGE2_RUN01_PLAINTEXT.read_bytes()

    storage = LocalStorageProvider(root_dir=temp_storage_dir)
    rel_path = "captures/plaintext_test/raw.pcap"
    storage.save_file(rel_path, file_bytes)

    capture_id = uuid.uuid4()
    cap = Capture(
        id=capture_id,
        capture_source="TESTBED_GENERATED",
        capture_format="PCAP",
        original_filename="client_plaintext.pcap",
        storage_path=rel_path,
        file_size_bytes=len(file_bytes),
        sha256_hash=hashlib.sha256(file_bytes).hexdigest().lower(),
        validation_state="VALIDATED",
    )
    async_db.add(cap)

    analysis_id = uuid.uuid4()
    analysis = AnalysisRun(
        id=analysis_id,
        capture_id=capture_id,
        status="QUEUED",
        current_stage="INGESTING",
    )
    async_db.add(analysis)
    await async_db.commit()

    service = ProtocolForensicsService(async_db)
    service.storage = storage
    summary = await service.execute_analysis(analysis_id)

    assert summary.ipsec_detected is False
    assert summary.outcome == "NO_IPSEC_FOUND"
    assert summary.packet_counts["ike"] == 0
    assert summary.packet_counts["esp"] == 0
    assert len(summary.crypto_observations) == 0


@pytest.mark.asyncio
async def test_real_stage2_run04_ipv6(async_db: AsyncSession, temp_storage_dir: str):
    """Test 3: Ingest real IPv6 strongSwan capture -> verify IPv6 protocol detection."""
    assert STAGE2_RUN04_IPV6.exists()
    file_bytes = STAGE2_RUN04_IPV6.read_bytes()

    storage = LocalStorageProvider(root_dir=temp_storage_dir)
    rel_path = "captures/ipv6_test/raw.pcap"
    storage.save_file(rel_path, file_bytes)

    capture_id = uuid.uuid4()
    cap = Capture(
        id=capture_id,
        capture_source="TESTBED_GENERATED",
        capture_format="PCAP",
        original_filename="wan_ipv6.pcap",
        storage_path=rel_path,
        file_size_bytes=len(file_bytes),
        sha256_hash=hashlib.sha256(file_bytes).hexdigest().lower(),
        validation_state="VALIDATED",
    )
    async_db.add(cap)

    analysis_id = uuid.uuid4()
    analysis = AnalysisRun(
        id=analysis_id,
        capture_id=capture_id,
        status="QUEUED",
        current_stage="INGESTING",
    )
    async_db.add(analysis)
    await async_db.commit()

    service = ProtocolForensicsService(async_db)
    service.storage = storage
    summary = await service.execute_analysis(analysis_id)

    assert summary.ipsec_detected is True
    assert "IPv6" in summary.ip_versions_observed

    # Verify observed IPv6 addresses in database
    obs_res = await async_db.execute(
        select(ProtocolObservation)
        .where(ProtocolObservation.analysis_id == analysis_id)
        .where(ProtocolObservation.protocol == "IPv6")
    )
    ipv6_obs = obs_res.scalars().all()
    assert len(ipv6_obs) > 0
    assert any("fd00:ba" in str(o.src_ip or "") for o in ipv6_obs)


@pytest.mark.asyncio
async def test_real_stage2_run06_natt(async_db: AsyncSession, temp_storage_dir: str):
    """Test 4: Ingest real NAT-T strongSwan capture -> verify UDP port 4500 encapsulation."""
    assert STAGE2_RUN06_NATT.exists()
    file_bytes = STAGE2_RUN06_NATT.read_bytes()

    storage = LocalStorageProvider(root_dir=temp_storage_dir)
    rel_path = "captures/natt_test/raw.pcap"
    storage.save_file(rel_path, file_bytes)

    capture_id = uuid.uuid4()
    cap = Capture(
        id=capture_id,
        capture_source="TESTBED_GENERATED",
        capture_format="PCAP",
        original_filename="wan_natt.pcap",
        storage_path=rel_path,
        file_size_bytes=len(file_bytes),
        sha256_hash=hashlib.sha256(file_bytes).hexdigest().lower(),
        validation_state="VALIDATED",
    )
    async_db.add(cap)

    analysis_id = uuid.uuid4()
    analysis = AnalysisRun(
        id=analysis_id,
        capture_id=capture_id,
        status="QUEUED",
        current_stage="INGESTING",
    )
    async_db.add(analysis)
    await async_db.commit()

    service = ProtocolForensicsService(async_db)
    service.storage = storage
    summary = await service.execute_analysis(analysis_id)

    assert summary.ipsec_detected is True
    assert summary.natt_observed is True
    assert summary.packet_counts["natt"] > 0


@pytest.mark.asyncio
async def test_real_pcapng_ingestion_and_forensics(async_db: AsyncSession, temp_storage_dir: str):
    """Test 5: Ingest real PCAPNG format capture -> verify Section Header Block and dissection."""
    assert FIXTURE_PCAPNG.exists()
    file_bytes = FIXTURE_PCAPNG.read_bytes()

    fmt, _magic_type = validate_capture_file(FIXTURE_PCAPNG)
    assert fmt.value == "PCAPNG"

    storage = LocalStorageProvider(root_dir=temp_storage_dir)
    rel_path = "captures/pcapng_test/raw.pcapng"
    storage.save_file(rel_path, file_bytes)

    capture_id = uuid.uuid4()
    cap = Capture(
        id=capture_id,
        capture_source="OFFLINE_UPLOAD",
        capture_format="PCAPNG",
        original_filename="real_tunnel_gcm.pcapng",
        storage_path=rel_path,
        file_size_bytes=len(file_bytes),
        sha256_hash=hashlib.sha256(file_bytes).hexdigest().lower(),
        validation_state="VALIDATED",
    )
    async_db.add(cap)

    analysis_id = uuid.uuid4()
    analysis = AnalysisRun(
        id=analysis_id,
        capture_id=capture_id,
        status="QUEUED",
        current_stage="INGESTING",
    )
    async_db.add(analysis)
    await async_db.commit()

    service = ProtocolForensicsService(async_db)
    service.storage = storage
    summary = await service.execute_analysis(analysis_id)

    assert summary.ipsec_detected is True
    assert summary.packet_counts["ike"] == 4
    assert summary.packet_counts["esp"] == 8


@pytest.mark.asyncio
async def test_real_partial_esp_only(async_db: AsyncSession, temp_storage_dir: str):
    """Test 6: Ingest partial ESP-only capture (frames 5-12 without IKE handshake).

    Strict Stage 3 Requirement:
    - ESP verified, SPIs verified, sequence numbers verified.
    - IKE = UNKNOWN / NOT OBSERVED.
    - Crypto configuration = UNKNOWN.
    - Zero crash, zero fake cipher inference from ESP ciphertext!
    """
    assert FIXTURE_ESP_ONLY.exists()
    file_bytes = FIXTURE_ESP_ONLY.read_bytes()

    storage = LocalStorageProvider(root_dir=temp_storage_dir)
    rel_path = "captures/esp_only_test/raw.pcap"
    storage.save_file(rel_path, file_bytes)

    capture_id = uuid.uuid4()
    cap = Capture(
        id=capture_id,
        capture_source="OFFLINE_UPLOAD",
        capture_format="PCAP",
        original_filename="real_esp_only.pcap",
        storage_path=rel_path,
        file_size_bytes=len(file_bytes),
        sha256_hash=hashlib.sha256(file_bytes).hexdigest().lower(),
        validation_state="VALIDATED",
    )
    async_db.add(cap)

    analysis_id = uuid.uuid4()
    analysis = AnalysisRun(
        id=analysis_id,
        capture_id=capture_id,
        status="QUEUED",
        current_stage="INGESTING",
    )
    async_db.add(analysis)
    await async_db.commit()

    service = ProtocolForensicsService(async_db)
    service.storage = storage
    summary = await service.execute_analysis(analysis_id)

    assert summary.ipsec_detected is True
    assert summary.protocols_observed == ["ESP"]
    assert summary.packet_counts["ike"] == 0
    assert summary.packet_counts["esp"] == 8
    # Invariant: Never claim AES-256 or ciphers from ESP header alone!
    assert len(summary.crypto_observations) == 0
    assert len(summary.ike_versions_observed) == 0


@pytest.mark.asyncio
async def test_analysis_reproducibility(async_db: AsyncSession, temp_storage_dir: str):
    """Test 7: Two consecutive analyses on the same immutable capture yield identical protocol facts."""
    file_bytes = STAGE2_RUN01_WAN.read_bytes()

    storage = LocalStorageProvider(root_dir=temp_storage_dir)
    rel_path = "captures/repro_test/raw.pcap"
    storage.save_file(rel_path, file_bytes)

    capture_id = uuid.uuid4()
    cap = Capture(
        id=capture_id,
        capture_source="OFFLINE_UPLOAD",
        capture_format="PCAP",
        original_filename="wan_encrypted.pcap",
        storage_path=rel_path,
        file_size_bytes=len(file_bytes),
        sha256_hash=hashlib.sha256(file_bytes).hexdigest().lower(),
        validation_state="VALIDATED",
    )
    async_db.add(cap)

    # Run 1
    a1_id = uuid.uuid4()
    a1 = AnalysisRun(id=a1_id, capture_id=capture_id, status="QUEUED")
    async_db.add(a1)
    await async_db.commit()

    service = ProtocolForensicsService(async_db)
    service.storage = storage
    s1 = await service.execute_analysis(a1_id)

    # Run 2
    a2_id = uuid.uuid4()
    a2 = AnalysisRun(id=a2_id, capture_id=capture_id, status="QUEUED")
    async_db.add(a2)
    await async_db.commit()

    s2 = await service.execute_analysis(a2_id)

    # Verify identical facts
    assert s1.ipsec_detected == s2.ipsec_detected
    assert s1.protocols_observed == s2.protocols_observed
    assert s1.packet_counts == s2.packet_counts
    assert s1.exchange_types_observed == s2.exchange_types_observed
    assert len(s1.crypto_observations) == len(s2.crypto_observations)
    assert [c.transform_name for c in s1.crypto_observations] == [c.transform_name for c in s2.crypto_observations]
