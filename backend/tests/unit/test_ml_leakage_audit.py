"""Unit tests for LeakageAuditor and shortcut detection."""

from __future__ import annotations

import pandas as pd
import pytest

from app.ml.auditor import LeakageAuditor, LeakageDetectedError
from app.ml.schema import FeatureSchema


def test_audit_approved_canonical_columns():
    """Verify that all 24 canonical features pass the forbidden columns audit without violation."""
    schema = FeatureSchema()
    violations = LeakageAuditor.audit_forbidden_columns(schema.feature_names)
    assert violations == []


@pytest.mark.parametrize(
    "prohibited_col",
    [
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "esp_spi",
        "spi",
        "session_id",
        "flow_id",
        "capture_id",
        "analysis_id",
        "filename",
        "filepath",
        "cipher_suite",
        "encryption_algorithm",
        "mode",
        "pfs_status",
        "is_nat_t",
        "netem_profile",
        "label",
        "ground_truth_label",
        "target",
        "scenario_id",
        "workload_seed",
    ],
)
def test_audit_forbidden_columns_rejection(prohibited_col: str):
    """Verify that every prohibited metadata column name triggers LeakageDetectedError."""
    schema = FeatureSchema()
    dirty_columns = schema.feature_names + [prohibited_col]
    with pytest.raises(LeakageDetectedError, match="FORBIDDEN_COLUMNS_DETECTED"):
        LeakageAuditor.audit_forbidden_columns(dirty_columns)


def test_session_isolation_audit():
    """Verify that overlapping session IDs across partitions are detected and rejected."""
    # 1. Clean disjoint partitions
    clean_splits = {
        "TRAIN": ["sess_1", "sess_2", "sess_3"],
        "VALIDATION": ["sess_4", "sess_5"],
        "TEST": ["sess_6", "sess_7"],
        "OOD_HOLDOUT": ["sess_8"],
    }
    LeakageAuditor.audit_session_isolation(clean_splits)  # Must pass without error

    # 2. Leaky partitions (sess_2 in both TRAIN and TEST)
    leaky_splits = {
        "TRAIN": ["sess_1", "sess_2", "sess_3"],
        "VALIDATION": ["sess_4", "sess_5"],
        "TEST": ["sess_2", "sess_7"],
    }
    with pytest.raises(LeakageDetectedError, match="DATA_LEAKAGE_DETECTED"):
        LeakageAuditor.audit_session_isolation(leaky_splits)


def test_high_cardinality_audit():
    """Verify detection of near-unique numeric columns."""
    df = pd.DataFrame({
        "feature_normal": [1.0, 1.0, 2.0, 2.0, 3.0, 3.0, 4.0, 4.0, 5.0, 5.0],
        "feature_id_like": [float(i) for i in range(10)],  # 100% unique
    })
    warnings = LeakageAuditor.audit_high_cardinality(df, cardinality_threshold=0.95)
    assert len(warnings) == 1
    assert warnings[0]["column"] == "feature_id_like"


def test_contingency_shortcuts_audit():
    """Verify warning when class is coupled 100% to a single cipher."""
    metadata_df = pd.DataFrame({
        "workload_class": ["Web", "Web", "VoIP", "VoIP"],
        "cipher_suite": ["AES-GCM", "AES-GCM", "ChaCha20", "ChaCha20"],
    })
    report = LeakageAuditor.audit_contingency_shortcuts(metadata_df)
    assert len(report["confounded_pairs"]) == 2  # Both Web and VoIP are confounded
