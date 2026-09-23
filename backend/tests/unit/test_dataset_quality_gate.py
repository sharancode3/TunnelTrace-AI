"""Unit tests for Stage 5 Dataset Quality Gate."""

from lab.workloads.models import WorkloadClass, WorkloadExecutionResult

from app.datasets.quality import DatasetQualityGate


def test_quality_gate_accepts_valid_session():
    """Verify session is accepted when all quality invariants are satisfied."""
    workload_res = WorkloadExecutionResult(
        profile_id="web_test_01",
        workload_class=WorkloadClass.WEB,
        success=True,
        start_time=100.0,
        end_time=105.0,
        duration_seconds=5.0,
        bytes_sent=50000,
        packets_sent=150,
    )
    res = DatasetQualityGate.validate(
        sa_established=True,
        workload_result=workload_res,
        outer_packet_count=150,
        outer_byte_count=50000,
        esp_packet_count=145,
        duration_seconds=5.0,
    )
    assert res.accepted is True
    assert res.status == "ACCEPTED"
    assert res.rejection_reason is None
    assert len(res.failures) == 0


def test_quality_gate_rejects_when_sa_failed():
    """Session must be rejected if IPsec SA failed to establish."""
    workload_res = WorkloadExecutionResult(
        profile_id="web_test_01",
        workload_class=WorkloadClass.WEB,
        success=True,
        start_time=100.0,
        end_time=105.0,
        duration_seconds=5.0,
    )
    res = DatasetQualityGate.validate(
        sa_established=False,
        workload_result=workload_res,
        outer_packet_count=100,
        outer_byte_count=20000,
        esp_packet_count=0,
        duration_seconds=5.0,
    )
    assert res.accepted is False
    assert res.status == "REJECTED"
    assert "SA negotiation failed" in (res.rejection_reason or "")


def test_quality_gate_rejects_when_no_esp_detected():
    """Session must be rejected if 0 ESP or NAT-T packets were observed."""
    workload_res = WorkloadExecutionResult(
        profile_id="web_test_01",
        workload_class=WorkloadClass.WEB,
        success=True,
        start_time=100.0,
        end_time=105.0,
        duration_seconds=5.0,
    )
    res = DatasetQualityGate.validate(
        sa_established=True,
        workload_result=workload_res,
        outer_packet_count=100,
        outer_byte_count=20000,
        esp_packet_count=0,
        duration_seconds=5.0,
    )
    assert res.accepted is False
    assert res.status == "REJECTED"
    assert any("Zero ESP/NAT-T packets detected" in f for f in res.failures)


def test_quality_gate_rejects_when_workload_failed():
    """Session must be rejected if workload client/server execution reported failure."""
    workload_res = WorkloadExecutionResult(
        profile_id="voip_test_01",
        workload_class=WorkloadClass.VOIP,
        success=False,
        start_time=100.0,
        end_time=102.0,
        duration_seconds=2.0,
        error_message="Client connection timed out",
    )
    res = DatasetQualityGate.validate(
        sa_established=True,
        workload_result=workload_res,
        outer_packet_count=20,
        outer_byte_count=1000,
        esp_packet_count=18,
        duration_seconds=2.0,
    )
    assert res.accepted is False
    assert res.status == "REJECTED"
    assert any("Workload execution reported failure" in f for f in res.failures)


def test_quality_gate_rejects_insufficient_packets_or_bytes():
    """Session must be rejected if packets < min_packets or bytes < min_bytes."""
    workload_res = WorkloadExecutionResult(
        profile_id="icmp_test_01",
        workload_class=WorkloadClass.ICMP,
        success=True,
        start_time=100.0,
        end_time=101.0,
        duration_seconds=1.0,
    )
    # 2 packets is below min_packets (5)
    res = DatasetQualityGate.validate(
        sa_established=True,
        workload_result=workload_res,
        outer_packet_count=2,
        outer_byte_count=20,
        esp_packet_count=2,
        duration_seconds=1.0,
        min_packets=5,
        min_bytes=100,
    )
    assert res.accepted is False
    assert res.status == "REJECTED"
    assert len(res.failures) >= 1
