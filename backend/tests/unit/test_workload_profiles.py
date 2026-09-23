"""Unit tests for Stage 5 Workload Profiles, Protocols, and Domain Models."""

import pytest
from lab.workloads.models import (
    WorkloadClass,
    WorkloadExecutionResult,
    WorkloadProfile,
    WorkloadProtocol,
)
from pydantic import ValidationError


def test_workload_class_enum_contains_required_classes():
    """Verify all 7 supervised classes plus OOD_HOLDOUT are present in enum."""
    expected = {
        "WEB": "Web",
        "VIDEO_STREAMING": "Video Streaming",
        "VOIP": "VoIP",
        "CHAT_MESSAGING": "Chat/Messaging",
        "EMAIL": "Email",
        "ICMP": "ICMP",
        "FILE_TRANSFER": "File Transfer",
        "OOD_HOLDOUT": "OOD_HOLDOUT",
    }
    for member_name, display_value in expected.items():
        assert hasattr(WorkloadClass, member_name)
        assert getattr(WorkloadClass, member_name).value == display_value


def test_workload_protocol_enum():
    assert WorkloadProtocol.TCP.value == "TCP"
    assert WorkloadProtocol.UDP.value == "UDP"
    assert WorkloadProtocol.ICMP.value == "ICMP"


def test_workload_profile_valid_creation():
    """Verify valid WorkloadProfile creation with default parameters."""
    profile = WorkloadProfile(
        profile_id="web_standard_01",
        workload_class=WorkloadClass.WEB,
        protocol=WorkloadProtocol.TCP,
        target_port=8080,
        duration_seconds=10.0,
        parameters={"num_requests": 20, "resource_types": ["html", "css", "img"]},
    )
    assert profile.profile_id == "web_standard_01"
    assert profile.workload_class == WorkloadClass.WEB
    assert profile.protocol == WorkloadProtocol.TCP
    assert profile.target_port == 8080
    assert profile.duration_seconds == 10.0
    assert profile.parameters["num_requests"] == 20


def test_workload_profile_port_validation():
    """Verify target_port must be between 1 and 65535."""
    with pytest.raises(ValidationError):
        WorkloadProfile(
            profile_id="invalid_port_low",
            workload_class=WorkloadClass.WEB,
            target_port=0,
        )

    with pytest.raises(ValidationError):
        WorkloadProfile(
            profile_id="invalid_port_high",
            workload_class=WorkloadClass.WEB,
            target_port=70000,
        )


def test_workload_profile_duration_validation():
    """Verify duration_seconds bounds (1.0 to 300.0)."""
    with pytest.raises(ValidationError):
        WorkloadProfile(
            profile_id="invalid_duration_too_short",
            workload_class=WorkloadClass.VOIP,
            duration_seconds=0.1,
        )

    with pytest.raises(ValidationError):
        WorkloadProfile(
            profile_id="invalid_duration_too_long",
            workload_class=WorkloadClass.VOIP,
            duration_seconds=500.0,
        )


def test_workload_profile_safety_validation():
    """Verify profile disallows forbidden injection keywords."""
    profile = WorkloadProfile(
        profile_id="unsafe_profile",
        workload_class=WorkloadClass.WEB,
        parameters={"shell": "rm -rf /"},
    )
    with pytest.raises(ValueError, match="Forbidden parameter key 'shell'"):
        profile.validate_safety()


def test_workload_execution_result_defaults():
    """Verify WorkloadExecutionResult default structure."""
    result = WorkloadExecutionResult(
        profile_id="test_run_01",
        workload_class=WorkloadClass.WEB,
        success=True,
        start_time=100.0,
        end_time=105.2,
        duration_seconds=5.2,
        bytes_sent=1048576,
        packets_sent=750,
    )
    assert result.success is True
    assert result.duration_seconds == 5.2
    assert result.bytes_sent == 1048576
    assert result.packets_sent == 750
    assert result.error_message is None
