"""Unit tests for X.509 Certificate Parser and Identity Association."""

from datetime import datetime, timedelta, timezone
import ipaddress
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.inventory.certificate_parser import (
    CertificateParseError,
    CertificateSecurityViolation,
    SafeCertificateParser,
)


def generate_test_ca():
    """Generate self-signed test CA."""
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    ca_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "TunnelTrace Test CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "TunnelTrace Root CA"),
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
    ca_pem = ca_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    return ca_key, ca_cert, ca_pem


def generate_test_cert(
    ca_key,
    ca_cert,
    cn="gw-a.example.com",
    sans_dns=None,
    sans_ip=None,
    valid_days=90,
    backdate_days=1,
):
    """Generate end-entity certificate signed by CA."""
    ee_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    ee_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "TunnelTrace Lab"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])

    san_items = []
    for dns in (sans_dns or []):
        san_items.append(x509.DNSName(dns))
    for ip in (sans_ip or []):
        san_items.append(x509.IPAddress(ipaddress.ip_address(ip)))

    builder = (
        x509.CertificateBuilder()
        .subject_name(ee_subject)
        .issuer_name(ca_cert.subject)
        .public_key(ee_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=backdate_days))
        .not_valid_after(now + timedelta(days=valid_days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    )
    if san_items:
        builder = builder.add_extension(x509.SubjectAlternativeName(san_items), critical=False)

    cert = builder.sign(ca_key, hashes.SHA256())
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    key_pem = ee_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("utf-8")
    return cert, cert_pem, key_pem


def test_parse_valid_cert_and_attributes():
    ca_key, ca_cert, ca_pem = generate_test_ca()
    cert, cert_pem, _ = generate_test_cert(
        ca_key,
        ca_cert,
        cn="gw-a.example.com",
        sans_dns=["gw-a.example.com", "vpn.example.com"],
        sans_ip=["192.0.2.1"],
        valid_days=60,
    )

    results = SafeCertificateParser.parse_pem_bundle(cert_pem)
    assert len(results) == 1
    c = results[0]
    assert "CN=gw-a.example.com" in c["subject_dn"]
    assert "CN=TunnelTrace Root CA" in c["issuer_dn"]
    assert c["validity_status"] == "VALID"
    assert c["days_until_expiry"] > 50
    assert c["public_key_algorithm"] == "RSA"
    assert c["public_key_bits"] == 2048
    assert "digital_signature" in c["key_usages"]
    assert "gw-a.example.com" in c["subject_alt_names"]["dns"]
    assert "192.0.2.1" in c["subject_alt_names"]["ip"]


def test_private_key_rejection_security_boundary():
    ca_key, ca_cert, _ = generate_test_ca()
    _, cert_pem, key_pem = generate_test_cert(ca_key, ca_cert)

    bundle_with_key = f"{cert_pem}\n{key_pem}"
    with pytest.raises(CertificateSecurityViolation, match="Private key material detected"):
        SafeCertificateParser.parse_pem_bundle(bundle_with_key)


def test_expiring_soon_and_expired_statuses():
    ca_key, ca_cert, _ = generate_test_ca()

    # Expiring soon (10 days remaining <= 30 threshold)
    _, cert_soon_pem, _ = generate_test_cert(ca_key, ca_cert, valid_days=10)
    res_soon = SafeCertificateParser.parse_pem_bundle(cert_soon_pem)
    assert res_soon[0]["validity_status"] == "EXPIRING_SOON"

    # Expired cert
    _, cert_exp_pem, _ = generate_test_cert(ca_key, ca_cert, valid_days=-5, backdate_days=30)
    res_exp = SafeCertificateParser.parse_pem_bundle(cert_exp_pem)
    assert res_exp[0]["validity_status"] == "EXPIRED"


def test_strongswan_identity_association():
    ca_key, ca_cert, _ = generate_test_ca()
    _, cert_pem, _ = generate_test_cert(
        ca_key,
        ca_cert,
        cn="vpn-gw-a.corp.net",
        sans_dns=["vpn-gw-a.corp.net"],
    )

    conns_ir = {
        "site-a-to-b": {
            "local": {"id": "vpn-gw-a.corp.net"},
            "remote": {"id": "vpn-gw-b.corp.net"},
        },
        "site-c-to-d": {
            "local": {"id": "vpn-gw-c.corp.net"},
            "remote": {"id": "vpn-gw-d.corp.net"},
        },
    }

    results = SafeCertificateParser.parse_pem_bundle(cert_pem, connections_ir=conns_ir)
    assert results[0]["identity_association_status"] == "MATCHED"
    assert results[0]["associated_connection"] == "site-a-to-b"


def test_trust_store_chain_validation():
    ca_key, ca_cert, ca_pem = generate_test_ca()
    _, cert_pem, _ = generate_test_cert(ca_key, ca_cert)

    # Valid chain against matching CA
    results_valid = SafeCertificateParser.parse_pem_bundle(cert_pem, trust_store_pem=ca_pem)
    assert results_valid[0]["chain_validation_status"] == "VALIDATED"
    assert results_valid[0]["trust_store_digest"] is not None

    # Invalid chain against unrelated CA
    _, _, other_ca_pem = generate_test_ca()
    results_invalid = SafeCertificateParser.parse_pem_bundle(cert_pem, trust_store_pem=other_ca_pem)
    assert results_invalid[0]["chain_validation_status"] == "FAILED"

    # Unchecked when no trust store provided
    results_unchecked = SafeCertificateParser.parse_pem_bundle(cert_pem)
    assert results_unchecked[0]["chain_validation_status"] == "UNCHECKED"
