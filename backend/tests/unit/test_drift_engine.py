"""Unit tests for Configuration Drift Engine."""

import pytest
from app.inventory.drift_engine import ConfigurationDriftEngine
from app.inventory.schemas import ComparisonStatus, FieldDriftStatus


@pytest.fixture
def baseline_ir():
    return {
        "format": "SWANCTL",
        "connections": {
            "tunnel-primary": {
                "version": 2,
                "local_addrs": "192.0.2.1",
                "remote_addrs": "198.51.100.1",
                "raw_proposals": ["aes256gcm16-prfsha256-ecp256"],
                "encap": True,
                "rekey_time": "14400s",
                "local": {"id": "gw-a.example.com", "auth": "pubkey"},
                "remote": {"id": "gw-b.example.com", "auth": "pubkey"},
                "children": {
                    "net-lan": {
                        "mode": "tunnel",
                        "local_ts": "10.1.0.0/24",
                        "remote_ts": "10.2.0.0/24",
                        "raw_esp_proposals": ["aes256gcm16-ecp256"],
                        "start_action": "start",
                        "rekey_time": "3600s",
                        "replay_window": 128,
                    }
                },
            }
        },
        "secrets": {"key1": {"secret": "[REDACTED_SECRET]", "is_redacted": True}},
    }


def test_matching_snapshots_no_drift(baseline_ir):
    status, summary, items = ConfigurationDriftEngine.compare_snapshots(
        baseline_ir=baseline_ir,
        observed_ir=baseline_ir,
        baseline_identity="gw-a.example.com",
        observed_identity="gw-a.example.com",
    )
    assert status == ComparisonStatus.MATCHED
    assert summary["drift_detected"] is False
    assert summary["changed_count"] == 0
    assert summary["missing_count"] == 0
    assert summary["new_count"] == 0
    assert summary["matched_count"] > 5


def test_crypto_proposal_drift_detected(baseline_ir):
    import copy

    observed_ir = copy.deepcopy(baseline_ir)
    observed_ir["connections"]["tunnel-primary"]["raw_proposals"] = ["3des-sha1-modp1024"]

    status, summary, items = ConfigurationDriftEngine.compare_snapshots(
        baseline_ir=baseline_ir,
        observed_ir=observed_ir,
        baseline_identity="gw-a.example.com",
        observed_identity="gw-a.example.com",
    )
    assert status == ComparisonStatus.DRIFT_DETECTED
    assert summary["drift_detected"] is True
    assert summary["changed_count"] >= 1

    prop_item = next(i for i in items if i.field_path == "connections.tunnel-primary.proposals")
    assert prop_item.status == FieldDriftStatus.CHANGED
    assert prop_item.baseline_value == ["aes256gcm16-prfsha256-ecp256"]
    assert prop_item.observed_value == ["3des-sha1-modp1024"]


def test_traffic_selector_and_lifetime_drift(baseline_ir):
    import copy

    observed_ir = copy.deepcopy(baseline_ir)
    child = observed_ir["connections"]["tunnel-primary"]["children"]["net-lan"]
    child["local_ts"] = "10.1.0.0/16"
    child["rekey_time"] = "7200s"

    status, summary, items = ConfigurationDriftEngine.compare_snapshots(
        baseline_ir=baseline_ir,
        observed_ir=observed_ir,
        baseline_identity="gw-a.example.com",
        observed_identity="gw-a.example.com",
    )
    assert status == ComparisonStatus.DRIFT_DETECTED
    ts_item = next(i for i in items if i.field_path == "connections.tunnel-primary.children.net-lan.local_ts")
    assert ts_item.status == FieldDriftStatus.CHANGED
    assert ts_item.baseline_value == "10.1.0.0/24"
    assert ts_item.observed_value == "10.1.0.0/16"


def test_missing_and_new_connections(baseline_ir):
    import copy

    # Baseline has two connections
    base = copy.deepcopy(baseline_ir)
    base["connections"]["backup-conn"] = {"version": 2, "encap": False}

    # Observed drops backup-conn and adds new-conn
    obs = copy.deepcopy(baseline_ir)
    obs["connections"]["new-conn"] = {"version": 2, "encap": True}

    status, summary, items = ConfigurationDriftEngine.compare_snapshots(
        baseline_ir=base,
        observed_ir=obs,
        baseline_identity="gw-a.example.com",
        observed_identity="gw-a.example.com",
    )
    assert status == ComparisonStatus.DRIFT_DETECTED
    assert summary["missing_count"] >= 1
    assert summary["new_count"] >= 1

    missing_item = next(i for i in items if i.field_path == "connections.backup-conn")
    assert missing_item.status == FieldDriftStatus.MISSING_IN_OBSERVED

    new_item = next(i for i in items if i.field_path == "connections.new-conn")
    assert new_item.status == FieldDriftStatus.NEW_IN_OBSERVED


def test_incomparable_gateway_identities(baseline_ir):
    status, summary, items = ConfigurationDriftEngine.compare_snapshots(
        baseline_ir=baseline_ir,
        observed_ir=baseline_ir,
        baseline_identity="gw-a.example.com",
        observed_identity="gw-different.example.com",
    )
    assert status == ComparisonStatus.INCOMPARABLE
    assert "Gateway identity mismatch" in summary["reason"]


def test_secrets_marked_not_comparable(baseline_ir):
    status, summary, items = ConfigurationDriftEngine.compare_snapshots(
        baseline_ir=baseline_ir,
        observed_ir=baseline_ir,
        baseline_identity="gw-a.example.com",
        observed_identity="gw-a.example.com",
    )
    sec_item = next(i for i in items if i.field_path == "secrets")
    assert sec_item.status == FieldDriftStatus.NOT_COMPARABLE
    assert sec_item.baseline_value == "[REDACTED_SECRET]"
    assert sec_item.observed_value == "[REDACTED_SECRET]"
