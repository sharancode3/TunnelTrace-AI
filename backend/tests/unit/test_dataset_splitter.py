"""Unit tests for Stage 5 Session-Level Splitter and Leakage Audit."""

import uuid

import pytest

from app.datasets.splitter import (
    SessionLevelSplitter,
    SplitAssignment,
)


def make_dummy_sessions(count_per_class: int = 10) -> list[dict]:
    """Generates dummy sessions across the 7 supervised classes + OOD."""
    classes = [
        "Web",
        "Video Streaming",
        "VoIP",
        "Chat/Messaging",
        "Email",
        "ICMP",
        "File Transfer",
        "OOD_HOLDOUT",
    ]
    sessions = []
    for cls in classes:
        for i in range(count_per_class):
            sessions.append({
                "id": str(uuid.uuid4()),
                "workload_class": cls,
                "scenario_id": f"scenario_{cls.lower()}_{i}",
                "encrypted_capture_sha256": f"sha256_{cls}_{i}",
            })
    return sessions


def test_splitter_ratios_validation():
    """Ratios must sum to 1.0 and cannot be negative."""
    with pytest.raises(ValueError, match="Split ratios must sum to 1.0"):
        SessionLevelSplitter(train_ratio=0.5, val_ratio=0.2, test_ratio=0.1)

    with pytest.raises(ValueError, match="Split ratios cannot be negative"):
        SessionLevelSplitter(train_ratio=1.2, val_ratio=-0.1, test_ratio=-0.1)


def test_session_level_isolation_and_disjointness():
    """Every session must belong to exactly one split; pairwise intersections must be empty."""
    sessions = make_dummy_sessions(count_per_class=10)
    splitter = SessionLevelSplitter(train_ratio=0.70, val_ratio=0.15, test_ratio=0.15, random_seed=42)
    assignments = splitter.partition(sessions)

    assert len(assignments) == len(sessions)

    # Build SHA map
    sha_map = {s["id"]: s["encrypted_capture_sha256"] for s in sessions}

    # Run mathematical audit
    audit = SessionLevelSplitter.audit_leakage(assignments, sha_map)
    assert audit.is_clean is True
    assert len(audit.error_messages) == 0
    assert len(audit.session_overlaps) == 0
    assert len(audit.sha_overlaps) == 0

    # Verify all 4 splits exist
    assert "TRAIN" in audit.split_counts
    assert "VALIDATION" in audit.split_counts
    assert "TEST" in audit.split_counts
    assert "OOD_HOLDOUT" in audit.split_counts

    # Verify OOD holdout sessions count
    assert audit.split_counts["OOD_HOLDOUT"] == 10
    # Supervised total is 7 * 10 = 70 sessions
    supervised_total = (
        audit.split_counts["TRAIN"]
        + audit.split_counts["VALIDATION"]
        + audit.split_counts["TEST"]
    )
    assert supervised_total == 70


def test_ood_holdout_strict_quarantine():
    """OOD_HOLDOUT sessions must never be allocated to TRAIN, VALIDATION, or TEST."""
    sessions = make_dummy_sessions(count_per_class=5)
    splitter = SessionLevelSplitter()
    assignments = splitter.partition(sessions)

    for a in assignments:
        if a.workload_class == "OOD_HOLDOUT":
            assert a.split_type == "OOD_HOLDOUT"
        else:
            assert a.split_type in ("TRAIN", "VALIDATION", "TEST")


def test_audit_leakage_detects_deliberate_session_overlap():
    """Audit must catch and flag intentional cross-split session contamination."""
    shared_session_id = str(uuid.uuid4())
    compromised_assignments = [
        SplitAssignment(
            session_id=shared_session_id,
            split_type="TRAIN",
            group_id=f"group_{shared_session_id}",
            workload_class="Web",
        ),
        SplitAssignment(
            session_id=shared_session_id,  # LEAKAGE: same session in TEST
            split_type="TEST",
            group_id=f"group_{shared_session_id}",
            workload_class="Web",
        ),
    ]

    audit = SessionLevelSplitter.audit_leakage(compromised_assignments)
    assert audit.is_clean is False
    assert len(audit.error_messages) >= 1
    assert "TRAIN_x_TEST" in audit.session_overlaps
    assert shared_session_id in audit.session_overlaps["TRAIN_x_TEST"]


def test_audit_leakage_detects_sha_overlap():
    """Audit must catch when two different sessions share the exact same capture hash."""
    s1_id = str(uuid.uuid4())
    s2_id = str(uuid.uuid4())
    shared_sha = "duplicate_pcap_sha256_hash_value"

    assignments = [
        SplitAssignment(
            session_id=s1_id,
            split_type="TRAIN",
            group_id=f"group_{s1_id}",
            workload_class="VoIP",
        ),
        SplitAssignment(
            session_id=s2_id,
            split_type="VALIDATION",
            group_id=f"group_{s2_id}",
            workload_class="VoIP",
        ),
    ]
    sha_map = {s1_id: shared_sha, s2_id: shared_sha}

    audit = SessionLevelSplitter.audit_leakage(assignments, sha_map)
    assert audit.is_clean is False
    assert any("PCAP SHAs overlap" in msg for msg in audit.error_messages)
    assert "TRAIN_x_VALIDATION" in audit.sha_overlaps
