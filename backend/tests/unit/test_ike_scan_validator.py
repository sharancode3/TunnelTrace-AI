"""Unit tests for IKE-scan scope and authorization validation."""

import pytest

from app.core.config import settings
from app.discovery.validator import AuthorizationError, ScopeValidationError
from app.protocol.ike_scan.profiles import IkeScanProfile
from app.protocol.ike_scan.validator import validate_ike_scope


def test_validation_requires_authorization_metadata():
    """Verify operator_id, authorization_reference, and attestation are mandatory."""
    # Missing operator_id
    with pytest.raises(AuthorizationError, match="operator_id is required"):
        validate_ike_scope(
            operator_id="",
            authorization_reference="TICKET-101",
            authorization_attestation="Valid authorization statement",
            profile_name=IkeScanProfile.IKEV1_MAIN_MODE_DISCOVERY.value,
            target="192.168.1.1",
        )

    # Missing authorization_reference
    with pytest.raises(AuthorizationError, match="authorization_reference is required"):
        validate_ike_scope(
            operator_id="op-admin",
            authorization_reference="",
            authorization_attestation="Valid authorization statement",
            profile_name=IkeScanProfile.IKEV1_MAIN_MODE_DISCOVERY.value,
            target="192.168.1.1",
        )

    # Short attestation (<10 chars)
    with pytest.raises(AuthorizationError, match="authorization_attestation must contain an explicit statement"):
        validate_ike_scope(
            operator_id="op-admin",
            authorization_reference="TICKET-101",
            authorization_attestation="too short",
            profile_name=IkeScanProfile.IKEV1_MAIN_MODE_DISCOVERY.value,
            target="192.168.1.1",
        )


def test_validation_rejects_cidr_sweeps_and_invalid_ips():
    """Verify IKE scans require exact single IP target, rejecting CIDR sweeps and broadcast."""
    # CIDR rejected
    with pytest.raises(ScopeValidationError, match="CIDR range sweeps are forbidden"):
        validate_ike_scope(
            operator_id="op-admin",
            authorization_reference="TICKET-101",
            authorization_attestation="Authorized penetration test engagement #12345",
            profile_name=IkeScanProfile.IKEV1_MAIN_MODE_DISCOVERY.value,
            target="192.168.1.0/24",
        )

    # Broadcast rejected
    with pytest.raises(ScopeValidationError, match="Broadcast address"):
        validate_ike_scope(
            operator_id="op-admin",
            authorization_reference="TICKET-101",
            authorization_attestation="Authorized penetration test engagement #12345",
            profile_name=IkeScanProfile.IKEV1_MAIN_MODE_DISCOVERY.value,
            target="255.255.255.255",
        )

    # Multicast rejected
    with pytest.raises(ScopeValidationError, match="Multicast target"):
        validate_ike_scope(
            operator_id="op-admin",
            authorization_reference="TICKET-101",
            authorization_attestation="Authorized penetration test engagement #12345",
            profile_name=IkeScanProfile.IKEV1_MAIN_MODE_DISCOVERY.value,
            target="224.0.0.1",
        )


def test_validation_profile_and_experimental_v2(monkeypatch):
    """Verify profile validation and experimental IKEv2 toggles."""
    # Invalid profile
    with pytest.raises(ScopeValidationError, match="Invalid profile"):
        validate_ike_scope(
            operator_id="op-admin",
            authorization_reference="TICKET-101",
            authorization_attestation="Authorized penetration test engagement #12345",
            profile_name="NON_EXISTENT_PROFILE",
            target="192.168.1.1",
        )

    # Experimental v2 disabled by config
    monkeypatch.setattr(settings, "IKE_SCAN_ALLOW_EXPERIMENTAL_V2", False)
    with pytest.raises(ScopeValidationError, match="Experimental IKEv2 probing is disabled"):
        validate_ike_scope(
            operator_id="op-admin",
            authorization_reference="TICKET-101",
            authorization_attestation="Authorized penetration test engagement #12345",
            profile_name=IkeScanProfile.IKEV2_DEFAULT_EXPERIMENTAL.value,
            target="192.168.1.1",
        )


def test_validation_success():
    """Verify valid request produces frozen ValidatedIkeScope."""
    scope = validate_ike_scope(
        operator_id="op-admin",
        authorization_reference="TICKET-101",
        authorization_attestation="Authorized penetration test engagement #12345",
        profile_name=IkeScanProfile.IKEV1_MAIN_MODE_DISCOVERY.value,
        target="192.168.1.50",
        port=500,
    )
    assert scope.target_ip == "192.168.1.50"
    assert scope.target_port == 500
    assert scope.ike_version == "1"
    assert not scope.is_experimental
