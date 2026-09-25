"""X.509 Certificate Inventory Parser using cryptography.x509.

Extracts public certificate metadata, evaluates validity and expiry,
maps strongSwan IKE connection identities, and evaluates trust store chains.
Strictly prohibits and rejects private keys.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from datetime import datetime, timezone
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, padding, rsa, x25519, x448


class CertificateSecurityViolation(Exception):
    """Raised when an uploaded certificate contains private key material."""


class CertificateParseError(Exception):
    """Raised when certificate data is malformed or invalid."""


_PK_PREFIX = "-----BEGIN "
_PK_SUFFIX = "PRIVATE KEY-----"


class SafeCertificateParser:
    """Parses X.509 certificates and extracts evidence without ingesting secrets."""

    PRIVATE_KEY_MARKERS = [
        f"{_PK_PREFIX}{k} {_PK_SUFFIX}"
        for k in ("RSA", "EC", "DSA", "OPENSSH", "ENCRYPTED")
    ] + [f"{_PK_PREFIX}{_PK_SUFFIX}"]

    EXPIRING_SOON_DAYS_DEFAULT = 30

    @classmethod
    def parse_pem_bundle(
        cls,
        pem_text: str,
        trust_store_pem: str | None = None,
        connections_ir: dict[str, Any] | None = None,
        source_alias: str = "x509_certificate",
        expiring_soon_days: int = EXPIRING_SOON_DAYS_DEFAULT,
    ) -> list[dict[str, Any]]:
        """Parse one or multiple PEM certificates from text.

        Enforces strict rejection of private key material.
        """
        if not pem_text or not pem_text.strip():
            raise CertificateParseError("Certificate data is empty")

        # 1. Strict security check for private key material
        for marker in cls.PRIVATE_KEY_MARKERS:
            if marker in pem_text:
                raise CertificateSecurityViolation(
                    "Security violation: Private key material detected in certificate input. "
                    "TunnelTrace strictly prohibits ingesting or storing private keys."
                )

        # 2. Extract PEM certificate blocks
        cert_blocks = re.findall(
            r"-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----",
            pem_text,
            flags=re.DOTALL,
        )

        if not cert_blocks:
            raise CertificateParseError("No valid PEM certificate found (missing -----BEGIN CERTIFICATE----- block)")

        # Prepare trust store if provided
        ca_certs: list[x509.Certificate] = []
        trust_store_digest: str | None = None
        if trust_store_pem:
            # Check trust store for private keys as well
            for marker in cls.PRIVATE_KEY_MARKERS:
                if marker in trust_store_pem:
                    raise CertificateSecurityViolation(
                        "Security violation: Private key material detected in trust store input."
                    )
            ca_blocks = re.findall(
                r"-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----",
                trust_store_pem,
                flags=re.DOTALL,
            )
            for cb in ca_blocks:
                try:
                    ca_certs.append(x509.load_pem_x509_certificate(cb.encode("utf-8")))
                except Exception:
                    continue
            trust_store_digest = hashlib.sha256(trust_store_pem.encode("utf-8")).hexdigest()

        results: list[dict[str, Any]] = []

        now_utc = datetime.now(timezone.utc)

        for idx, block in enumerate(cert_blocks):
            try:
                cert = x509.load_pem_x509_certificate(block.encode("utf-8"))
            except Exception as e:
                raise CertificateParseError(f"Failed to parse X.509 certificate block {idx + 1}: {e}") from e

            # Extract fields
            fp_sha256 = cert.fingerprint(hashes.SHA256()).hex()
            serial_str = hex(cert.serial_number)
            subject_dn = cert.subject.rfc4514_string()
            issuer_dn = cert.issuer.rfc4514_string()

            # Validity timestamps
            try:
                not_before = cert.not_valid_before_utc
                not_after = cert.not_valid_after_utc
            except AttributeError:
                # Fallback for older cryptography versions
                not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
                not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)

            days_until_expiry = (not_after - now_utc).days

            if now_utc < not_before:
                validity_status = "NOT_YET_VALID"
            elif now_utc > not_after:
                validity_status = "EXPIRED"
            elif days_until_expiry <= expiring_soon_days:
                validity_status = "EXPIRING_SOON"
            else:
                validity_status = "VALID"

            # SANs
            sans_dict: dict[str, list[str]] = {
                "dns": [],
                "ip": [],
                "email": [],
                "directory_name": [],
            }
            try:
                san_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                for name in san_ext.value:
                    if isinstance(name, x509.DNSName):
                        sans_dict["dns"].append(name.value)
                    elif isinstance(name, x509.IPAddress):
                        sans_dict["ip"].append(str(name.value))
                    elif isinstance(name, x509.RFC822Name):
                        sans_dict["email"].append(name.value)
                    elif isinstance(name, x509.DirectoryName):
                        sans_dict["directory_name"].append(name.value.rfc4514_string())
            except x509.ExtensionNotFound:
                pass

            # Public Key Algorithm & Strength
            pub_key = cert.public_key()
            if isinstance(pub_key, rsa.RSAPublicKey):
                pk_algo = "RSA"
                pk_bits = pub_key.key_size
            elif isinstance(pub_key, ec.EllipticCurvePublicKey):
                pk_algo = f"EC-{pub_key.curve.name}"
                pk_bits = pub_key.key_size
            elif isinstance(pub_key, ed25519.Ed25519PublicKey):
                pk_algo = "Ed25519"
                pk_bits = 256
            elif isinstance(pub_key, ed448.Ed448PublicKey):
                pk_algo = "Ed448"
                pk_bits = 448
            elif isinstance(pub_key, x25519.X25519PublicKey):
                pk_algo = "X25519"
                pk_bits = 256
            elif isinstance(pub_key, x448.X448PublicKey):
                pk_algo = "X448"
                pk_bits = 448
            elif isinstance(pub_key, dsa.DSAPublicKey):
                pk_algo = "DSA"
                pk_bits = pub_key.key_size
            else:
                pk_algo = type(pub_key).__name__
                pk_bits = 0

            # Signature algorithm
            try:
                sig_algo = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else cert.signature_algorithm_oid._name
            except Exception:
                sig_algo = "unknown"

            # Basic constraints
            is_ca = False
            try:
                bc_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.BASIC_CONSTRAINTS)
                is_ca = bc_ext.value.ca
            except x509.ExtensionNotFound:
                pass

            # Key Usages
            key_usages: list[str] = []
            try:
                ku_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.KEY_USAGE)
                ku = ku_ext.value
                if ku.digital_signature:
                    key_usages.append("digital_signature")
                if ku.key_encipherment:
                    key_usages.append("key_encipherment")
                if ku.key_cert_sign:
                    key_usages.append("key_cert_sign")
                if ku.crl_sign:
                    key_usages.append("crl_sign")
                if ku.key_agreement:
                    key_usages.append("key_agreement")
            except (x509.ExtensionNotFound, ValueError):
                pass

            # Extended Key Usages
            extended_key_usages: list[str] = []
            try:
                eku_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.EXTENDED_KEY_USAGE)
                for oid in eku_ext.value:
                    extended_key_usages.append(oid._name or oid.dotted_string)
            except x509.ExtensionNotFound:
                pass

            # strongSwan Connection Identity Association
            matched_conn, assoc_status = cls.associate_strongswan_identity(
                subject_dn=subject_dn,
                sans=sans_dict,
                connections_ir=connections_ir,
            )

            # Chain validation against trust store
            chain_status = "UNCHECKED"
            trust_store_id: str | None = None
            if ca_certs:
                trust_store_id = f"TrustStore-{len(ca_certs)}Certs"
                chain_status = cls.validate_chain_against_ca_bundle(cert, ca_certs)

            results.append({
                "sha256_fingerprint": fp_sha256,
                "serial_number": serial_str,
                "subject_dn": subject_dn,
                "issuer_dn": issuer_dn,
                "subject_alt_names": sans_dict,
                "not_valid_before": not_before,
                "not_valid_after": not_after,
                "validity_status": validity_status,
                "days_until_expiry": days_until_expiry,
                "public_key_algorithm": pk_algo,
                "public_key_bits": pk_bits,
                "signature_algorithm": sig_algo,
                "is_ca": is_ca,
                "key_usages": key_usages,
                "extended_key_usages": extended_key_usages,
                "associated_connection": matched_conn,
                "identity_association_status": assoc_status,
                "chain_validation_status": chain_status,
                "trust_store_identifier": trust_store_id,
                "trust_store_digest": trust_store_digest,
                "revocation_status": "UNCHECKED",
                "source_alias": f"{source_alias}_{idx + 1}" if len(cert_blocks) > 1 else source_alias,
            })

        return results

    @classmethod
    def associate_strongswan_identity(
        cls,
        subject_dn: str,
        sans: dict[str, list[str]],
        connections_ir: dict[str, Any] | None,
    ) -> tuple[str | None, str]:
        """Apply strongSwan identity matching rules (RFC 7296 and swanctl semantics).

        Compares certificate Subject DN and SANs against connection local.id / remote.id.
        Returns: (associated_connection_name, "MATCHED" | "AMBIGUOUS" | "UNASSOCIATED")
        """
        if not connections_ir:
            return None, "UNASSOCIATED"

        matching_conns: list[str] = []

        all_cert_identifiers = set()
        # Add exact Subject DN
        all_cert_identifiers.add(subject_dn.strip().lower())
        # Add Common Name from DN if present
        cn_match = re.search(r"CN=([^,]+)", subject_dn, re.IGNORECASE)
        if cn_match:
            all_cert_identifiers.add(cn_match.group(1).strip().lower())

        # Add SAN DNS, IP, and Email
        for dns in sans.get("dns", []):
            all_cert_identifiers.add(dns.strip().lower())
        for ip in sans.get("ip", []):
            all_cert_identifiers.add(ip.strip())
        for email in sans.get("email", []):
            all_cert_identifiers.add(email.strip().lower())

        for conn_name, conn_data in connections_ir.items():
            local_info = conn_data.get("local", {})
            remote_info = conn_data.get("remote", {})

            local_id = str(local_info.get("id", "")).strip().lower()
            remote_id = str(remote_info.get("id", "")).strip().lower()

            # Check if connection references certificate filename or alias
            local_certs = str(local_info.get("certs", "")).strip().lower()

            if (local_id and local_id in all_cert_identifiers) or \
               (remote_id and remote_id in all_cert_identifiers) or \
               (local_certs and any(local_certs in ident for ident in all_cert_identifiers)):
                matching_conns.append(conn_name)

        if len(matching_conns) == 1:
            return matching_conns[0], "MATCHED"
        elif len(matching_conns) > 1:
            return None, "AMBIGUOUS"
        return None, "UNASSOCIATED"

    @classmethod
    def validate_chain_against_ca_bundle(
        cls,
        cert: x509.Certificate,
        ca_certs: list[x509.Certificate],
    ) -> str:
        """Validate certificate against explicit CA trust store."""
        for ca in ca_certs:
            if ca.subject == cert.issuer:
                # Candidate issuer found - verify public key signature
                try:
                    ca_pub_key = ca.public_key()
                    # Cryptography verify logic
                    if isinstance(ca_pub_key, rsa.RSAPublicKey):
                        ca_pub_key.verify(
                            cert.signature,
                            cert.tbs_certificate_bytes,
                            padding.PKCS1v15(),
                            cert.signature_hash_algorithm,
                        )
                        return "VALIDATED"
                    elif isinstance(ca_pub_key, ec.EllipticCurvePublicKey):
                        ca_pub_key.verify(
                            cert.signature,
                            cert.tbs_certificate_bytes,
                            ec.ECDSA(cert.signature_hash_algorithm),
                        )
                        return "VALIDATED"
                    elif isinstance(ca_pub_key, ed25519.Ed25519PublicKey):
                        ca_pub_key.verify(
                            cert.signature,
                            cert.tbs_certificate_bytes,
                        )
                        return "VALIDATED"
                except Exception:
                    return "FAILED"

        return "FAILED"
