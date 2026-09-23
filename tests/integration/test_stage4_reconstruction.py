"""Integration tests for Stage 4 Reconstruction against genuine Stage 2 PCAP/PCAPNG artifacts.

Validates:
- IKE session grouping and SPI pair tracking.
- Parent IKE SA transform selection and AEAD handling.
- Child SA creation, orphan handling, mode & PFS uncertainty invariants.
- ESP directional stream aggregation and bidirectional pairing.
- IPv6 and NAT-T handling.
- Idempotency (re-running on same analysis produces identical state with zero duplicates).
"""

from __future__ import annotations

import hashlib
import uuid
from pathlib import Path

import pytest
from app.db.base import Base
from app.db.models.capture import AnalysisRun, Capture
from app.db.models.reconstruction import (
    ChildSecurityAssociation,
    ESPFlow,
    IKESecurityAssociation,
    IKESession,
)
from app.protocol.service import ProtocolForensicsService
from app.reconstruction.engine import ReconstructionEngine
from app.reconstruction.models import (
    FlowAssociationState,
    LifecycleState,
    Mode,
    PFSStatus,
)
from app.services.storage.local import LocalStorageProvider
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

# Ground truth paths
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
STAGE2_RUN01_WAN = REPO_ROOT / "storage" / "lab" / "runs" / "tt-1790185654-25c4bc" / "captures" / "wan_encrypted.pcap"
STAGE2_RUN01_PLAINTEXT = REPO_ROOT / "storage" / "lab" / "runs" / "tt-1790185654-25c4bc" / "captures" / "client_plaintext.pcap"
STAGE2_RUN03_TRANSPORT = REPO_ROOT / "storage" / "lab" / "runs" / "tt-1790185791-2fd383" / "captures" / "wan_encrypted.pcap"
STAGE2_RUN04_IPV6 = REPO_ROOT / "storage" / "lab" / "runs" / "tt-1790185891-f96398" / "captures" / "wan_encrypted.pcap"
STAGE2_RUN06_NATT = REPO_ROOT / "storage" / "lab" / "runs" / "tt-1790185927-b1d8f6" / "captures" / "wan_encrypted.pcap"
FIXTURE_ESP_ONLY = REPO_ROOT / "tests" / "fixtures" / "captures" / "real_esp_only.pcap"


@pytest.fixture
def temp_storage_dir(tmp_path: Path) -> str:
    """Provide isolated temp storage path for tests."""
    return str(tmp_path)


@pytest.fixture
async def async_db():
    """In-memory async SQLite database session fixture."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    session_factory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with session_factory() as session:
        yield session

    await engine.dispose()


@pytest.mark.asyncio
async def test_real_stage2_run01_tunnel_gcm_reconstruction(async_db: AsyncSession, temp_storage_dir: str):
    """Test 1: Reconstruct real Run 01 Tunnel IPv4 AES-GCM + PFS capture."""
    assert STAGE2_RUN01_WAN.exists()
    file_bytes = STAGE2_RUN01_WAN.read_bytes()

    storage = LocalStorageProvider(root_dir=temp_storage_dir)
    rel_path = "captures/stage4_run01/raw.pcap"
    storage.save_file(rel_path, file_bytes)

    capture_id = uuid.uuid4()
    cap = Capture(
        id=capture_id,
        capture_source="TESTBED_GENERATED",
        capture_format="PCAP",
        original_filename="wan_encrypted.pcap",
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

    # Step 1: Execute Stage 3 protocol forensics to populate observations
    proto_service = ProtocolForensicsService(async_db)
    proto_service.storage = storage
    proto_summary = await proto_service.execute_analysis(analysis_id)
    assert proto_summary.ipsec_detected is True

    # Step 2: Execute Stage 4 reconstruction
    engine = ReconstructionEngine(async_db)
    recon_summary = await engine.execute_reconstruction(analysis_id)

    # 1. Verify IKE Session
    assert recon_summary.ike_sessions_count == 1
    sess_res = await async_db.execute(select(IKESession).where(IKESession.analysis_id == analysis_id))
    sess = sess_res.scalar_one()
    assert sess.initiator_spi == "3b9b84844fa6b437"
    assert sess.responder_spi is not None
    assert sess.ike_version == "IKEv2"
    assert sess.lifecycle_state == "ACTIVE_INFERRED"
    assert sess.packet_count == 4
    assert sess.retransmission_count == 0

    # 2. Verify Parent IKE SA
    assert recon_summary.ike_sas_count == 1
    ike_sa_res = await async_db.execute(select(IKESecurityAssociation).where(IKESecurityAssociation.session_id == sess.id))
    ike_sa = ike_sa_res.scalar_one()
    assert ike_sa.encryption_algorithm == "AES-GCM-16-256"
    assert ike_sa.key_length_bits == 256
    assert ike_sa.prf_algorithm == "PRF_HMAC_SHA2_256"
    assert ike_sa.dh_group == "ECP-256 (DH19)"
    assert ike_sa.integrity_algorithm == "NONE / NOT_APPLICABLE"

    # 3. Verify Child SA
    assert recon_summary.child_sas_count == 1
    csa_res = await async_db.execute(select(ChildSecurityAssociation).where(ChildSecurityAssociation.analysis_id == analysis_id))
    csa = csa_res.scalar_one()
    assert csa.ike_sa_id == ike_sa.id
    assert csa.protocol == "ESP"
    assert csa.inbound_spi is not None
    assert csa.outbound_spi is not None
    # Invariant: Passive capture without keys must evaluate mode & PFS to UNKNOWN
    assert csa.mode == Mode.UNKNOWN.value
    assert csa.pfs_status == PFSStatus.UNKNOWN.value
    # Invariant: Never copy parent IKE cipher to Child SA!
    assert csa.encryption_algorithm is None

    # 4. Verify Bidirectional ESP Flow
    assert recon_summary.paired_flows_count == 1
    flow_res = await async_db.execute(select(ESPFlow).where(ESPFlow.analysis_id == analysis_id))
    flow = flow_res.scalar_one()
    assert flow.association_state == FlowAssociationState.PAIRED_BIDIRECTIONAL.value
    assert flow.packet_count == 8
    assert flow.forward_packets == 4
    assert flow.reverse_packets == 4
    assert flow.byte_count > 0
    assert flow.child_sa_id == csa.id


@pytest.mark.asyncio
async def test_real_stage2_run03_transport_reconstruction(async_db: AsyncSession, temp_storage_dir: str):
    """Test 2: Reconstruct real Run 03 Transport Mode capture."""
    assert STAGE2_RUN03_TRANSPORT.exists()
    file_bytes = STAGE2_RUN03_TRANSPORT.read_bytes()

    storage = LocalStorageProvider(root_dir=temp_storage_dir)
    rel_path = "captures/stage4_run03/raw.pcap"
    storage.save_file(rel_path, file_bytes)

    capture_id = uuid.uuid4()
    cap = Capture(
        id=capture_id,
        capture_source="TESTBED_GENERATED",
        capture_format="PCAP",
        original_filename="wan_transport.pcap",
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

    proto_service = ProtocolForensicsService(async_db)
    proto_service.storage = storage
    await proto_service.execute_analysis(analysis_id)

    engine = ReconstructionEngine(async_db)
    recon_summary = await engine.execute_reconstruction(analysis_id)

    assert recon_summary.ike_sessions_count == 1
    assert recon_summary.child_sas_count == 1
    assert recon_summary.paired_flows_count == 1


@pytest.mark.asyncio
async def test_real_stage2_run04_ipv6_reconstruction(async_db: AsyncSession, temp_storage_dir: str):
    """Test 3: Reconstruct real Run 04 IPv6 Tunnel capture."""
    assert STAGE2_RUN04_IPV6.exists()
    file_bytes = STAGE2_RUN04_IPV6.read_bytes()

    storage = LocalStorageProvider(root_dir=temp_storage_dir)
    rel_path = "captures/stage4_run04/raw.pcap"
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

    proto_service = ProtocolForensicsService(async_db)
    proto_service.storage = storage
    await proto_service.execute_analysis(analysis_id)

    engine = ReconstructionEngine(async_db)
    recon_summary = await engine.execute_reconstruction(analysis_id)

    assert recon_summary.ike_sessions_count == 1

    flow_res = await async_db.execute(select(ESPFlow).where(ESPFlow.analysis_id == analysis_id))
    flow = flow_res.scalar_one()
    assert flow.ip_version == "IPv6"
    assert "fd00:ba" in flow.src_ip


@pytest.mark.asyncio
async def test_real_stage2_run06_natt_reconstruction(async_db: AsyncSession, temp_storage_dir: str):
    """Test 4: Reconstruct real Run 06 NAT-T UDP 4500 capture."""
    assert STAGE2_RUN06_NATT.exists()
    file_bytes = STAGE2_RUN06_NATT.read_bytes()

    storage = LocalStorageProvider(root_dir=temp_storage_dir)
    rel_path = "captures/stage4_run06/raw.pcap"
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

    proto_service = ProtocolForensicsService(async_db)
    proto_service.storage = storage
    await proto_service.execute_analysis(analysis_id)

    engine = ReconstructionEngine(async_db)
    recon_summary = await engine.execute_reconstruction(analysis_id)

    assert recon_summary.ike_sessions_count == 1
    sess_res = await async_db.execute(select(IKESession).where(IKESession.analysis_id == analysis_id))
    sess = sess_res.scalar_one()
    assert sess.is_nat_detected is True

    flow_res = await async_db.execute(select(ESPFlow).where(ESPFlow.analysis_id == analysis_id))
    flow = flow_res.scalar_one()
    assert flow.is_nat_t is True


@pytest.mark.asyncio
async def test_real_esp_only_orphan_reconstruction(async_db: AsyncSession, temp_storage_dir: str):
    """Test 5: Reconstruct partial ESP-only capture without IKE handshake."""
    assert FIXTURE_ESP_ONLY.exists()
    file_bytes = FIXTURE_ESP_ONLY.read_bytes()

    storage = LocalStorageProvider(root_dir=temp_storage_dir)
    rel_path = "captures/stage4_esp_only/raw.pcap"
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

    proto_service = ProtocolForensicsService(async_db)
    proto_service.storage = storage
    await proto_service.execute_analysis(analysis_id)

    engine = ReconstructionEngine(async_db)
    recon_summary = await engine.execute_reconstruction(analysis_id)

    # Invariants for orphan ESP
    assert recon_summary.ike_sessions_count == 0
    assert recon_summary.ike_sas_count == 0
    assert recon_summary.orphan_child_sas_count == 1

    csa_res = await async_db.execute(select(ChildSecurityAssociation).where(ChildSecurityAssociation.analysis_id == analysis_id))
    csa = csa_res.scalar_one()
    assert csa.ike_sa_id is None
    assert csa.lifecycle_state == LifecycleState.ORPHAN.value
    assert csa.encryption_algorithm is None
    assert csa.mode == Mode.UNKNOWN.value

    flow_res = await async_db.execute(select(ESPFlow).where(ESPFlow.analysis_id == analysis_id))
    flow = flow_res.scalar_one()
    assert flow.packet_count == 8


@pytest.mark.asyncio
async def test_non_ipsec_reconstruction(async_db: AsyncSession, temp_storage_dir: str):
    """Test 6: Plaintext non-IPsec capture cleanly produces zero sessions, SAs, and flows."""
    assert STAGE2_RUN01_PLAINTEXT.exists()
    file_bytes = STAGE2_RUN01_PLAINTEXT.read_bytes()

    storage = LocalStorageProvider(root_dir=temp_storage_dir)
    rel_path = "captures/stage4_plaintext/raw.pcap"
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

    proto_service = ProtocolForensicsService(async_db)
    proto_service.storage = storage
    await proto_service.execute_analysis(analysis_id)

    engine = ReconstructionEngine(async_db)
    recon_summary = await engine.execute_reconstruction(analysis_id)

    assert recon_summary.ike_sessions_count == 0
    assert recon_summary.child_sas_count == 0
    assert recon_summary.paired_flows_count == 0


@pytest.mark.asyncio
async def test_reconstruction_idempotency_and_reproducibility(async_db: AsyncSession, temp_storage_dir: str):
    """Test 7: Executing reconstruction twice on the same capture produces identical state with zero duplicates."""
    file_bytes = STAGE2_RUN01_WAN.read_bytes()
    storage = LocalStorageProvider(root_dir=temp_storage_dir)
    rel_path = "captures/stage4_idempotent/raw.pcap"
    storage.save_file(rel_path, file_bytes)

    capture_id = uuid.uuid4()
    cap = Capture(
        id=capture_id,
        capture_source="TESTBED_GENERATED",
        capture_format="PCAP",
        original_filename="wan_encrypted.pcap",
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

    proto_service = ProtocolForensicsService(async_db)
    proto_service.storage = storage
    await proto_service.execute_analysis(analysis_id)

    engine = ReconstructionEngine(async_db)

    # Run 1
    summary1 = await engine.execute_reconstruction(analysis_id)

    # Run 2
    summary2 = await engine.execute_reconstruction(analysis_id)

    # Verify identical counts
    assert summary1.ike_sessions_count == summary2.ike_sessions_count == 1
    assert summary1.child_sas_count == summary2.child_sas_count == 1
    assert summary1.paired_flows_count == summary2.paired_flows_count == 1

    # Verify zero duplicate rows in database
    sess_count = (await async_db.execute(select(func.count(IKESession.id)).where(IKESession.analysis_id == analysis_id))).scalar_one()
    assert sess_count == 1

    csa_count = (await async_db.execute(select(func.count(ChildSecurityAssociation.id)).where(ChildSecurityAssociation.analysis_id == analysis_id))).scalar_one()
    assert csa_count == 1

    flow_count = (await async_db.execute(select(func.count(ESPFlow.id)).where(ESPFlow.analysis_id == analysis_id))).scalar_one()
    assert flow_count == 1
