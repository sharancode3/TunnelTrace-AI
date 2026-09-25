"""Integration tests for Inventory & Configuration Drift Service.

Tests configuration import, automatic secret redaction, certificate ingestion,
private key rejection boundary, baseline designation, drift comparison, and summary queries.
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path
import pytest
import pytest_asyncio
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.db.base import Base
from app.db.session import get_db_session
from app.main import app


@pytest_asyncio.fixture
async def isolated_db(tmp_path: Path):
    """Create an isolated SQLite database with fresh schema for inventory testing."""
    db_file = tmp_path / "test_inventory.db"
    db_url = f"sqlite+aiosqlite:///{db_file.as_posix()}"
    engine = create_async_engine(db_url, echo=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)
    async with session_factory() as session:
        yield session

    await engine.dispose()


@pytest.fixture
def client(isolated_db: AsyncSession):
    async def override_get_db():
        yield isolated_db

    app.dependency_overrides[get_db_session] = override_get_db
    with TestClient(app=app, base_url="http://testserver") as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def sample_swanctl_conf():
    return """
connections {
    gw-primary {
        version = 2
        local_addrs = 192.0.2.1
        remote_addrs = 198.51.100.1
        proposals = aes256gcm16-prfsha256-ecp256
        encap = yes
        local {
            auth = pubkey
            id = gw-a.example.com
            certs = gw-a-cert.pem
        }
        remote {
            auth = pubkey
            id = gw-b.example.com
        }
        children {
            net-lan {
                mode = tunnel
                local_ts = 10.1.0.0/24
                remote_ts = 10.2.0.0/24
                esp_proposals = aes256gcm16-ecp256
                start_action = start
                rekey_time = 3600s
                replay_window = 128
            }
        }
    }
}
secrets {
    ike-psk {
        secret = "supersecret123"
    }
}
"""


@pytest.fixture
def sample_cert_pem():
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    ca_subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Test Lab Root CA"),
    ])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_subject)
        .issuer_name(ca_subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    ee_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ee_subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "gw-a.example.com"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(ee_subject)
        .issuer_name(ca_subject)
        .public_key(ee_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=90))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("gw-a.example.com")]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    ca_pem = ca_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    return cert_pem, ca_pem


def test_configuration_ingestion_and_redaction(client, sample_swanctl_conf):
    resp = client.post(
        "/api/v1/inventory/configurations/import",
        json={
            "gateway_identity": "gw-a.example.com",
            "config_text": sample_swanctl_conf,
            "operator_id": "secops-admin-1",
            "authorization_reference": "AUTH-REF-001",
        },
    )
    assert resp.status_code == 201
    snap = resp.json()
    assert snap["gateway_identity"] == "gw-a.example.com"
    assert snap["canonical_digest"] is not None
    assert "gw-primary" in snap["normalized_ir"]["connections"]

    # Verify secrets strictly scrubbed
    secrets = snap["normalized_ir"]["secrets"]
    assert secrets["ike-psk"]["secret"] == "[REDACTED_SECRET]"
    assert secrets["ike-psk"]["is_redacted"] is True


def test_certificate_ingestion_and_security_boundary(client, sample_cert_pem, sample_swanctl_conf):
    # First ingest configuration snapshot
    snap_resp = client.post(
        "/api/v1/inventory/configurations/import",
        json={
            "gateway_identity": "gw-a.example.com",
            "config_text": sample_swanctl_conf,
            "operator_id": "secops-admin-1",
            "authorization_reference": "AUTH-REF-001",
        },
    )
    assert snap_resp.status_code == 201
    snap_id = snap_resp.json()["id"]

    cert_pem, ca_pem = sample_cert_pem

    # 1. Successful import with chain validation against CA bundle
    resp = client.post(
        "/api/v1/inventory/certificates/import",
        json={
            "gateway_identity": "gw-a.example.com",
            "snapshot_id": snap_id,
            "certificate_pem": cert_pem,
            "trust_store_pem": ca_pem,
            "source_alias": "gw-a-cert.pem",
            "operator_id": "secops-admin-1",
            "authorization_reference": "AUTH-REF-001",
        },
    )
    assert resp.status_code == 201
    certs = resp.json()
    assert len(certs) == 1
    c = certs[0]
    assert "gw-a.example.com" in c["subject_dn"]
    assert c["validity_status"] == "VALID"
    assert c["public_key_algorithm"] == "RSA"
    assert c["chain_validation_status"] == "VALIDATED"
    assert c["associated_connection"] == "gw-primary"
    assert c["identity_association_status"] == "MATCHED"

    # 2. Rejection of private key material (Security boundary enforcement)
    fake_key_pem = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC...\n-----END PRIVATE KEY-----"
    bad_resp = client.post(
        "/api/v1/inventory/certificates/import",
        json={
            "gateway_identity": "gw-a.example.com",
            "certificate_pem": f"{cert_pem}\n{fake_key_pem}",
            "source_alias": "bad_key.pem",
            "operator_id": "secops-admin-1",
            "authorization_reference": "AUTH-REF-001",
        },
    )
    assert bad_resp.status_code == 403
    assert "Private key material detected" in bad_resp.json()["detail"]


def test_drift_comparison_across_snapshots(client, sample_swanctl_conf):
    # Snapshot 1: Baseline
    s1_resp = client.post(
        "/api/v1/inventory/configurations/import",
        json={
            "gateway_identity": "gw-drift-node.example.com",
            "config_text": sample_swanctl_conf,
            "operator_id": "secops-admin-1",
            "authorization_reference": "AUTH-REF-001",
        },
    )
    assert s1_resp.status_code == 201
    s1_id = s1_resp.json()["id"]

    # Designate as baseline
    des_resp = client.post(
        f"/api/v1/inventory/configurations/{s1_id}/baseline",
        json={
            "operator_id": "secops-admin-1",
            "approval_reference": "APPROVAL-REF-001",
            "baseline_version": 1,
        },
    )
    assert des_resp.status_code == 200
    assert des_resp.json()["is_baseline"] is True

    # Snapshot 2: Drifted proposals and local traffic selector
    modified_conf = sample_swanctl_conf.replace(
        "proposals = aes256gcm16-prfsha256-ecp256",
        "proposals = 3des-sha1-modp1024",
    ).replace(
        "local_ts = 10.1.0.0/24",
        "local_ts = 10.1.0.0/16",
    )
    s2_resp = client.post(
        "/api/v1/inventory/configurations/import",
        json={
            "gateway_identity": "gw-drift-node.example.com",
            "config_text": modified_conf,
            "operator_id": "secops-admin-1",
            "authorization_reference": "AUTH-REF-002",
        },
    )
    assert s2_resp.status_code == 201
    s2_id = s2_resp.json()["id"]

    # Execute drift comparison endpoint
    drift_resp = client.post(
        "/api/v1/inventory/configurations/drift",
        json={"baseline_snapshot_id": s1_id, "observed_snapshot_id": s2_id},
    )
    assert drift_resp.status_code == 201
    drift = drift_resp.json()
    assert drift["comparison_status"] == "DRIFT_DETECTED"
    assert drift["drift_summary"]["drift_detected"] is True
    assert drift["drift_summary"]["changed_count"] >= 2

    # Check changed paths
    changed_paths = [item["field_path"] for item in drift["field_drifts"] if item["status"] == "CHANGED"]
    assert "connections.gw-primary.proposals" in changed_paths
    assert "connections.gw-primary.children.net-lan.local_ts" in changed_paths


def test_inventory_gateway_summary_endpoint(client, sample_swanctl_conf):
    client.post(
        "/api/v1/inventory/configurations/import",
        json={
            "gateway_identity": "gw-a.example.com",
            "config_text": sample_swanctl_conf,
            "operator_id": "secops-admin-1",
            "authorization_reference": "AUTH-REF-001",
        },
    )
    summary_resp = client.get("/api/v1/inventory/gateways/summary")
    assert summary_resp.status_code == 200
    summaries = summary_resp.json()
    assert isinstance(summaries, list)
    assert len(summaries) >= 1
    gw_names = [s["gateway_identity"] for s in summaries]
    assert "gw-a.example.com" in gw_names
