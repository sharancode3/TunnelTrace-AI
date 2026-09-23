"""Unit tests for MLDatasetBuilder and session-isolated partition assembly."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.db.base import Base
from app.db.models.capture import AnalysisRun, Capture, ProtocolObservation
from app.db.models.dataset import Dataset, DatasetSession, DatasetSplit, DatasetVersion
from app.db.models.reconstruction import ESPFlow
from app.ml.dataset import (
    MLDatasetBuilder,
)
from app.ml.schema import FeatureSchema


@pytest.fixture
async def async_db():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    session_factory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with session_factory() as session:
        yield session

    await engine.dispose()


@pytest.mark.asyncio
async def test_dataset_builder_partitions(async_db: AsyncSession):
    """Verify that MLDatasetBuilder extracts flows and builds isolated TRAIN/VAL/TEST partitions."""
    # 1. Create Dataset & DatasetVersion
    dataset = Dataset(name="Test_DS", vpn_technology="IPSEC_NATIVE", role="PRIMARY")
    async_db.add(dataset)
    await async_db.commit()
    await async_db.refresh(dataset)

    version = DatasetVersion(dataset_id=dataset.id, version_tag="v1.0.0-test", status="LOCKED", manifest_hash="mhash123")
    async_db.add(version)
    await async_db.commit()
    await async_db.refresh(version)

    # 2. Create 3 sessions (Train, Val, Test) for "Web" and "VoIP"
    classes = ["Web", "VoIP"]
    split_types = ["TRAIN", "VALIDATION", "TEST"]

    for i, stype in enumerate(split_types):
        cls_name = classes[i % len(classes)]
        cap_id = uuid.uuid4()
        cap = Capture(
            id=cap_id,
            capture_source="TESTBED_LAB",
            capture_format="PCAP",
            original_filename=f"cap_{stype}.pcap",
            storage_path=f"captures/{stype}.pcap",
            file_size_bytes=1000,
            sha256_hash=f"sha_{stype}",
            packet_count=10,
            duration_sec=2.0,
            validation_state="VALIDATED",
        )
        async_db.add(cap)

        analysis_id = uuid.uuid4()
        analysis = AnalysisRun(id=analysis_id, capture_id=cap_id, status="COMPLETED", current_stage="COMPLETED")
        async_db.add(analysis)

        sess_id = uuid.uuid4()
        sess = DatasetSession(
            id=sess_id,
            version_id=version.id,
            capture_id=cap_id,
            analysis_id=analysis_id,
            workload_class=cls_name,
            workload_profile_id=f"prof_{cls_name.lower()}",
            workload_seed=42,
            scenario_id="01_tunnel.yaml",
            mode="TUNNEL",
            ip_version="IPv4",
            cipher_suite="aes256gcm16",
            quality_status="ACCEPTED",
            encrypted_capture_sha256=f"sha_{stype}",
        )
        async_db.add(sess)

        # Split record
        sp = DatasetSplit(version_id=version.id, session_id=sess_id, split_type=stype, group_id=str(sess_id))
        async_db.add(sp)

        # Add ESPFlow
        flow = ESPFlow(
            id=uuid.uuid4(),
            analysis_id=analysis_id,
            spi="0x11111111",
            reverse_spi="0x22222222",
            src_ip="192.168.100.2",
            dst_ip="192.168.200.2",
            ip_version="IPv4",
            start_time=10.0,
            end_time=12.0,
            duration_seconds=2.0,
            packet_count=2,
            byte_count=200,
        )
        async_db.add(flow)

        # Add ProtocolObservations for this flow
        obs1 = ProtocolObservation(
            analysis_id=analysis_id,
            frame_number=1,
            packet_time=10.0,
            protocol="ESP",
            category="ENCAPSULATION",
            src_ip="192.168.100.2",
            dst_ip="192.168.200.2",
            field_name="esp.spi",
            raw_value="0x11111111",
            normalized_value="0x11111111",
            source_field="esp.spi",
            source_tool="tshark",
            source_tool_version="4.0.0",
            evidence_state="VERIFIED",
            extra_attributes={"packet_len_bytes": 100},
        )
        obs2 = ProtocolObservation(
            analysis_id=analysis_id,
            frame_number=2,
            packet_time=12.0,
            protocol="ESP",
            category="ENCAPSULATION",
            src_ip="192.168.200.2",
            dst_ip="192.168.100.2",
            field_name="esp.spi",
            raw_value="0x22222222",
            normalized_value="0x22222222",
            source_field="esp.spi",
            source_tool="tshark",
            source_tool_version="4.0.0",
            evidence_state="VERIFIED",
            extra_attributes={"packet_len_bytes": 100},
        )
        async_db.add(obs1)
        async_db.add(obs2)

    await async_db.commit()

    # Build partitions
    builder = MLDatasetBuilder(FeatureSchema())
    partitions = await builder.build_partitions_from_db(async_db, str(version.id))

    assert "TRAIN" in partitions
    assert "VALIDATION" in partitions
    assert "TEST" in partitions

    assert partitions["TRAIN"].num_rows == 1
    assert partitions["VALIDATION"].num_rows == 1
    assert partitions["TEST"].num_rows == 1

    # Check that X has 24 feature columns
    assert partitions["TRAIN"].X.shape[1] == 24
    assert list(partitions["TRAIN"].X.columns) == FeatureSchema().feature_names
