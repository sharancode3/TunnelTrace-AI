"""Unit tests for Stage 5 Workload Generators, Factory Registry, and Doctor."""

import pytest
from lab.workloads import (
    WORKLOAD_GENERATOR_REGISTRY,
    ChatGenerator,
    EmailGenerator,
    FileTransferGenerator,
    ICMPGenerator,
    OODHoldoutGenerator,
    VideoGenerator,
    VoIPGenerator,
    WebGenerator,
    WorkloadClass,
    WorkloadDoctor,
    WorkloadProfile,
    get_generator_for_profile,
)


def test_generator_registry_covers_all_classes():
    """Verify registry has an entry for all 8 workload classes."""
    for member in WorkloadClass:
        assert member in WORKLOAD_GENERATOR_REGISTRY


@pytest.mark.parametrize(
    ("workload_class", "expected_generator_class"),
    [
        (WorkloadClass.WEB, WebGenerator),
        (WorkloadClass.VIDEO_STREAMING, VideoGenerator),
        (WorkloadClass.VOIP, VoIPGenerator),
        (WorkloadClass.CHAT_MESSAGING, ChatGenerator),
        (WorkloadClass.EMAIL, EmailGenerator),
        (WorkloadClass.ICMP, ICMPGenerator),
        (WorkloadClass.FILE_TRANSFER, FileTransferGenerator),
        (WorkloadClass.OOD_HOLDOUT, OODHoldoutGenerator),
    ],
)
def test_get_generator_for_profile(workload_class, expected_generator_class):
    """Verify correct generator class returned by factory helper."""
    profile = WorkloadProfile(
        profile_id=f"test_{workload_class.name.lower()}",
        workload_class=workload_class,
        duration_seconds=5.0,
    )
    generator = get_generator_for_profile(profile)
    assert isinstance(generator, expected_generator_class)
    assert generator.profile == profile


def test_web_generator_lifecycle_and_defaults():
    profile = WorkloadProfile(
        profile_id="web_test",
        workload_class=WorkloadClass.WEB,
        target_port=8080,
    )
    gen = WebGenerator(profile)
    assert gen.profile.target_port == 8080
    assert gen.server_proc is None
    # Stopping an unstarted server should be a safe no-op
    gen.stop_server()


def test_voip_generator_cadence_parameters():
    profile = WorkloadProfile(
        profile_id="voip_test",
        workload_class=WorkloadClass.VOIP,
        target_port=5004,
        parameters={"interval_ms": 20, "payload_size": 160},
    )
    gen = VoIPGenerator(profile)
    assert gen.profile.parameters["interval_ms"] == 20
    assert gen.profile.parameters["payload_size"] == 160


def test_file_transfer_generator_parameters():
    profile = WorkloadProfile(
        profile_id="ft_test",
        workload_class=WorkloadClass.FILE_TRANSFER,
        target_port=9000,
        parameters={"total_size_mb": 5, "chunk_size_kb": 64},
    )
    gen = FileTransferGenerator(profile)
    assert gen.profile.parameters["total_size_mb"] == 5
    assert gen.profile.parameters["chunk_size_kb"] == 64


def test_icmp_generator_has_no_server():
    """ICMP ping targets peer IP directly and requires no user-space server listener."""
    profile = WorkloadProfile(
        profile_id="icmp_test",
        workload_class=WorkloadClass.ICMP,
    )
    gen = ICMPGenerator(profile)
    # start_server should be a safe no-op without spawning user-space process
    gen.start_server(server_netns="ns_peer", bind_ip="192.168.1.2", port=0)
    assert gen.server_proc is None
    gen.stop_server()


def test_ood_generator_parameters():
    profile = WorkloadProfile(
        profile_id="ood_test",
        workload_class=WorkloadClass.OOD_HOLDOUT,
        target_port=9999,
        parameters={"telemetry_burst_interval_ms": 50},
    )
    gen = OODHoldoutGenerator(profile)
    assert gen.profile.parameters["telemetry_burst_interval_ms"] == 50


def test_workload_doctor_diagnostics():
    """Verify WorkloadDoctor runs diagnostics and returns structured dictionary."""
    report = WorkloadDoctor.check_environment()
    assert isinstance(report, dict)
    assert "ready" in report
    assert "checks" in report
    assert "classes_supported" in report["checks"]
    assert "Web" in report["checks"]["classes_supported"]
    assert "supported_classes_count" in report
