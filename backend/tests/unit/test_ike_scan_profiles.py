"""Unit tests for IKE-scan profile definitions and forbidden argument safety enforcement."""

import pytest

from app.protocol.ike_scan.profiles import (
    FORBIDDEN_FLAGS,
    SCAN_PROFILES,
    IkeScanProfile,
    assert_no_forbidden_arguments,
)


def test_supported_profiles_finite_and_versioned():
    """Verify only allowlisted, safe, non-intrusive profiles exist."""
    assert len(SCAN_PROFILES) == 2
    assert IkeScanProfile.IKEV1_MAIN_MODE_DISCOVERY in SCAN_PROFILES
    assert IkeScanProfile.IKEV2_DEFAULT_EXPERIMENTAL in SCAN_PROFILES

    v1_cfg = SCAN_PROFILES[IkeScanProfile.IKEV1_MAIN_MODE_DISCOVERY]
    assert v1_cfg.ike_version == "1"
    assert not v1_cfg.is_experimental
    assert v1_cfg.default_port == 500
    assert 500 in v1_cfg.permitted_ports
    assert v1_cfg.retries <= 3

    v2_cfg = SCAN_PROFILES[IkeScanProfile.IKEV2_DEFAULT_EXPERIMENTAL]
    assert v2_cfg.ike_version == "2"
    assert v2_cfg.is_experimental  # Must be explicitly labelled experimental
    assert v2_cfg.retries <= 3


def test_forbidden_flags_rejection():
    """Verify strictly forbidden flags (cracking, aggressive mode, fuzzing) are rejected."""
    forbidden_samples = [
        "--pskcrack",
        "--pskcrack=hash.txt",
        "-P",
        "-Phash.txt",
        "-A",
        "--aggressive",
        "--fuzz",
        "--random",
        "--sport=1234",
        "--source-ip=1.2.3.4",
        "--trans=1,2,3",
    ]
    for flag in forbidden_samples:
        with pytest.raises(ValueError, match="Forbidden or intrusive ike-scan argument"):
            assert_no_forbidden_arguments(["--retry=2", flag, "192.168.1.1"])


def test_allowed_arguments_pass_validation():
    """Verify standard bounded discovery arguments pass safety checks."""
    valid_argv = ["--retry=2", "--timeout=2000", "--backoff=2", "--destport=500", "192.168.1.1"]
    assert_no_forbidden_arguments(valid_argv)
