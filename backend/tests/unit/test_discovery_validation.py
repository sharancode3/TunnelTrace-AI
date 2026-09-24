"""Unit tests for Stage 2 scope validation, target canonicalization, and authorization gates."""

import pytest
from app.core.config import settings
from app.discovery.profiles import DiscoveryProfile
from app.discovery.validator import (
    AuthorizationError,
    ScopeValidationError,
    validate_scope_request,
)


def test_validation_missing_operator_id():
    """Ensure empty operator_id raises AuthorizationError."""
    with pytest.raises(AuthorizationError, match="operator_id is required"):
        validate_scope_request(
            operator_id="",
            authorization_reference="TICKET-1234",
            authorization_attestation="Explicit written approval granted for network asset scan.",
            profile_name="IKE_SERVICE_DISCOVERY",
            requested_targets=["127.0.0.1"],
        )


def test_validation_missing_authorization_reference():
    """Ensure empty authorization reference raises AuthorizationError."""
    with pytest.raises(AuthorizationError, match="authorization_reference is required"):
        validate_scope_request(
            operator_id="sec-op-1",
            authorization_reference="   ",
            authorization_attestation="Explicit written approval granted for network asset scan.",
            profile_name="IKE_SERVICE_DISCOVERY",
            requested_targets=["127.0.0.1"],
        )


def test_validation_trivial_authorization_attestation():
    """Ensure short/trivial attestation is rejected."""
    with pytest.raises(AuthorizationError, match="must contain an explicit statement"):
        validate_scope_request(
            operator_id="sec-op-1",
            authorization_reference="TICKET-1234",
            authorization_attestation="too short",
            profile_name="IKE_SERVICE_DISCOVERY",
            requested_targets=["127.0.0.1"],
        )


def test_validation_empty_targets_rejected():
    """Ensure empty target list is rejected."""
    with pytest.raises(ScopeValidationError, match="requested_targets cannot be empty"):
        validate_scope_request(
            operator_id="sec-op-1",
            authorization_reference="TICKET-1234",
            authorization_attestation="Explicit authorization granted for testing.",
            profile_name="IKE_SERVICE_DISCOVERY",
            requested_targets=[],
        )


def test_validation_wildcards_prohibited():
    """Ensure wildcards like '*' or '0.0.0.0/0' are rejected."""
    for bad_target in ["*", "all", "0.0.0.0/0", "::/0"]:
        with pytest.raises(ScopeValidationError, match="Wildcard target .* is strictly prohibited"):
            validate_scope_request(
                operator_id="sec-op-1",
                authorization_reference="TICKET-1234",
                authorization_attestation="Explicit authorization granted for testing.",
                profile_name="IKE_SERVICE_DISCOVERY",
                requested_targets=[bad_target],
            )


def test_validation_multicast_unspecified_rejected():
    """Ensure multicast and unspecified IP addresses are rejected."""
    # Multicast
    with pytest.raises(ScopeValidationError, match="Multicast"):
        validate_scope_request(
            operator_id="sec-op-1",
            authorization_reference="TICKET-1234",
            authorization_attestation="Explicit authorization granted for testing.",
            profile_name="IKE_SERVICE_DISCOVERY",
            requested_targets=["224.0.0.1"],
        )

    # Unspecified 0.0.0.0
    with pytest.raises(ScopeValidationError, match="Unspecified"):
        validate_scope_request(
            operator_id="sec-op-1",
            authorization_reference="TICKET-1234",
            authorization_attestation="Explicit authorization granted for testing.",
            profile_name="IKE_SERVICE_DISCOVERY",
            requested_targets=["0.0.0.0"],
        )


def test_validation_target_cap_exceeded_by_cidr():
    """Ensure CIDR blocks that expand past the max targets limit are rejected."""
    # /24 has 256 addresses; default max is 8
    with pytest.raises(ScopeValidationError, match="exceeding max target cap"):
        validate_scope_request(
            operator_id="sec-op-1",
            authorization_reference="TICKET-1234",
            authorization_attestation="Explicit authorization granted for testing.",
            profile_name="IKE_SERVICE_DISCOVERY",
            requested_targets=["192.168.1.0/24"],
            max_targets=8,
        )


def test_validation_target_cap_exceeded_by_ip_list():
    """Ensure more than max_targets individual IPs are rejected."""
    ips = [f"192.168.1.{i}" for i in range(1, 10)]  # 9 IPs, cap is 8
    with pytest.raises(ScopeValidationError, match="exceeding conservative cap"):
        validate_scope_request(
            operator_id="sec-op-1",
            authorization_reference="TICKET-1234",
            authorization_attestation="Explicit authorization granted for testing.",
            profile_name="IKE_SERVICE_DISCOVERY",
            requested_targets=ips,
            max_targets=8,
        )


def test_validation_port_cap_exceeded():
    """Ensure requesting more than max_ports is rejected."""
    ports = list(range(1, 20))  # 19 ports, cap is 16
    with pytest.raises(ScopeValidationError, match="exceeds maximum port limit"):
        validate_scope_request(
            operator_id="sec-op-1",
            authorization_reference="TICKET-1234",
            authorization_attestation="Explicit authorization granted for testing.",
            profile_name="IKE_SERVICE_DISCOVERY",
            requested_targets=["127.0.0.1"],
            permitted_ports=ports,
            max_ports=16,
        )


def test_validation_invalid_port_range():
    """Ensure out-of-range ports are rejected."""
    with pytest.raises(ScopeValidationError, match="Invalid port"):
        validate_scope_request(
            operator_id="sec-op-1",
            authorization_reference="TICKET-1234",
            authorization_attestation="Explicit authorization granted for testing.",
            profile_name="IKE_SERVICE_DISCOVERY",
            requested_targets=["127.0.0.1"],
            permitted_ports=[0],
        )


def test_validation_exclusion_filtering():
    """Ensure exclusions filter out requested targets prior to scan execution."""
    scope = validate_scope_request(
        operator_id="sec-op-1",
        authorization_reference="TICKET-1234",
        authorization_attestation="Explicit authorization granted for testing.",
        profile_name="IKE_SERVICE_DISCOVERY",
        requested_targets=["192.168.10.1", "192.168.10.2", "192.168.10.3"],
        exclusions=["192.168.10.2"],
    )
    assert scope.canonical_targets == ["192.168.10.1", "192.168.10.3"]
    assert scope.target_count == 2


def test_validation_all_targets_excluded():
    """Ensure error is raised if all targets are excluded."""
    with pytest.raises(ScopeValidationError, match="No executable targets remain"):
        validate_scope_request(
            operator_id="sec-op-1",
            authorization_reference="TICKET-1234",
            authorization_attestation="Explicit authorization granted for testing.",
            profile_name="IKE_SERVICE_DISCOVERY",
            requested_targets=["192.168.10.1"],
            exclusions=["192.168.10.0/24"],
        )


def test_validation_hostname_resolution_and_pinning(monkeypatch):
    """Ensure hostnames are resolved once and pinned to concrete canonical IP addresses."""
    # Mock socket.getaddrinfo to avoid external DNS dependency during unit test
    def mock_getaddrinfo(host, port):
        if host == "vpn-gateway.internal":
            return [(2, 1, 6, "", ("10.200.1.5", 0))]
        raise OSError("DNS not found")

    import socket
    monkeypatch.setattr(socket, "getaddrinfo", mock_getaddrinfo)

    scope = validate_scope_request(
        operator_id="sec-op-1",
        authorization_reference="TICKET-1234",
        authorization_attestation="Explicit authorization granted for testing.",
        profile_name="VPN_MANAGEMENT_DISCOVERY",
        requested_targets=["vpn-gateway.internal"],
    )

    assert scope.canonical_targets == ["10.200.1.5"]
    assert scope.resolved_host_map == {"vpn-gateway.internal": ["10.200.1.5"]}
    assert scope.profile == DiscoveryProfile.VPN_MANAGEMENT_DISCOVERY
    assert scope.permitted_ports == [22, 80, 443, 8443]  # Profile defaults
