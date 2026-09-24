"""Cryptographic Strength Engine and Authoritative Algorithm Registry.

Grounds all security bit-strength calculations in authoritative standards:
- NIST SP 800-57 Part 1 Rev. 5 (Table 2: Comparable Security Strengths)
- NIST SP 800-77 Rev. 1 (Guide to IPsec VPNs, Section 5)
- RFC 8221 (Cryptographic Algorithm Implementation Requirements for ESP/AH)
- RFC 8247 (Algorithm Implementation Requirements for IKEv2)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class CryptoAlgorithmDef:
    """Specification of a cryptographic primitive with verified security strength."""

    canonical_name: str
    family: str  # "ENCRYPTION", "INTEGRITY", "PRF", "DH"
    security_bits: int  # Effective security strength in bits per NIST SP 800-57
    is_aead: bool
    status_nist: str  # "DISALLOWED", "LEGACY_DEPRECATED", "ACCEPTABLE", "RECOMMENDED"
    status_ietf: str  # "MUST", "MUST_NOT", "SHOULD", "SHOULD_NOT", "MAY"
    normative_reference: str


# -----------------------------------------------------------------------------
# Encryption Algorithms (NIST SP 800-57 Table 2 & RFC 8221)
# -----------------------------------------------------------------------------
ENCRYPTION_REGISTRY: dict[str, CryptoAlgorithmDef] = {
    "AES-GCM-16": CryptoAlgorithmDef(
        canonical_name="AES-GCM-16",
        family="ENCRYPTION",
        security_bits=128,  # Default for 128-bit key; upgraded to 256 if key_length=256
        is_aead=True,
        status_nist="RECOMMENDED",
        status_ietf="MUST",
        normative_reference="NIST SP 800-77 Rev. 1 Sec 5.1.1; RFC 8221 Sec 4",
    ),
    "AES-GCM-256": CryptoAlgorithmDef(
        canonical_name="AES-GCM-256",
        family="ENCRYPTION",
        security_bits=256,
        is_aead=True,
        status_nist="RECOMMENDED",
        status_ietf="SHOULD",
        normative_reference="NIST SP 800-77 Rev. 1 Sec 5.1.1; RFC 8221 Sec 4",
    ),
    "AES-CBC": CryptoAlgorithmDef(
        canonical_name="AES-CBC",
        family="ENCRYPTION",
        security_bits=128,
        is_aead=False,
        status_nist="ACCEPTABLE",
        status_ietf="MUST",
        normative_reference="NIST SP 800-77 Rev. 1 Sec 5.1.1; RFC 8221 Sec 4",
    ),
    "AES-CBC-256": CryptoAlgorithmDef(
        canonical_name="AES-CBC-256",
        family="ENCRYPTION",
        security_bits=256,
        is_aead=False,
        status_nist="ACCEPTABLE",
        status_ietf="SHOULD",
        normative_reference="NIST SP 800-77 Rev. 1 Sec 5.1.1; RFC 8221 Sec 4",
    ),
    "CHACHA20-POLY1305": CryptoAlgorithmDef(
        canonical_name="CHACHA20-POLY1305",
        family="ENCRYPTION",
        security_bits=256,
        is_aead=True,
        status_nist="ACCEPTABLE",
        status_ietf="SHOULD",
        normative_reference="RFC 7634; RFC 8221 Sec 4",
    ),
    "3DES": CryptoAlgorithmDef(
        canonical_name="3DES",
        family="ENCRYPTION",
        security_bits=112,
        is_aead=False,
        status_nist="DISALLOWED",
        status_ietf="MUST_NOT",
        normative_reference="NIST SP 800-77 Rev. 1 Sec 5.1.1; RFC 9395 Sec 2",
    ),
    "DES": CryptoAlgorithmDef(
        canonical_name="DES",
        family="ENCRYPTION",
        security_bits=56,
        is_aead=False,
        status_nist="DISALLOWED",
        status_ietf="MUST_NOT",
        normative_reference="NIST SP 800-77 Rev. 1 Sec 5.1.1; RFC 8221 Sec 4",
    ),
    "NULL": CryptoAlgorithmDef(
        canonical_name="NULL",
        family="ENCRYPTION",
        security_bits=0,
        is_aead=False,
        status_nist="DISALLOWED",
        status_ietf="MUST_NOT",
        normative_reference="NIST SP 800-77 Rev. 1 Sec 5.1.1 (unless AH); RFC 8221 Sec 4",
    ),
}

# -----------------------------------------------------------------------------
# Diffie-Hellman / Key Exchange Groups (NIST SP 800-57 Table 2 & RFC 8247)
# -----------------------------------------------------------------------------
DH_GROUP_REGISTRY: dict[int, CryptoAlgorithmDef] = {
    1: CryptoAlgorithmDef(
        canonical_name="MODP-768 (Group 1)",
        family="DH",
        security_bits=68,
        is_aead=False,
        status_nist="DISALLOWED",
        status_ietf="MUST_NOT",
        normative_reference="NIST SP 800-57 Part 1 Rev. 5 Table 2; RFC 8247 Sec 3.2.4",
    ),
    2: CryptoAlgorithmDef(
        canonical_name="MODP-1024 (Group 2)",
        family="DH",
        security_bits=80,
        is_aead=False,
        status_nist="DISALLOWED",
        status_ietf="MUST_NOT",
        normative_reference="NIST SP 800-77 Rev. 1 Sec 5.1.2; RFC 8247 Sec 3.2.4",
    ),
    5: CryptoAlgorithmDef(
        canonical_name="MODP-1536 (Group 5)",
        family="DH",
        security_bits=96,
        is_aead=False,
        status_nist="DISALLOWED",
        status_ietf="MUST_NOT",
        normative_reference="NIST SP 800-77 Rev. 1 Sec 5.1.2; RFC 8247 Sec 3.2.4",
    ),
    14: CryptoAlgorithmDef(
        canonical_name="MODP-2048 (Group 14)",
        family="DH",
        security_bits=112,
        is_aead=False,
        status_nist="ACCEPTABLE",
        status_ietf="MUST",
        normative_reference="NIST SP 800-77 Rev. 1 Sec 5.1.2; RFC 8247 Sec 3.2.4",
    ),
    15: CryptoAlgorithmDef(
        canonical_name="MODP-3072 (Group 15)",
        family="DH",
        security_bits=128,
        is_aead=False,
        status_nist="RECOMMENDED",
        status_ietf="SHOULD",
        normative_reference="NIST SP 800-77 Rev. 1 Sec 5.1.2; RFC 8247 Sec 3.2.4",
    ),
    16: CryptoAlgorithmDef(
        canonical_name="MODP-4096 (Group 16)",
        family="DH",
        security_bits=152,
        is_aead=False,
        status_nist="RECOMMENDED",
        status_ietf="SHOULD",
        normative_reference="NIST SP 800-77 Rev. 1 Sec 5.1.2; RFC 8247 Sec 3.2.4",
    ),
    19: CryptoAlgorithmDef(
        canonical_name="ECP-256 (Group 19)",
        family="DH",
        security_bits=128,
        is_aead=False,
        status_nist="RECOMMENDED",
        status_ietf="MUST",
        normative_reference="NIST SP 800-77 Rev. 1 Sec 5.1.2; RFC 8247 Sec 3.2.4",
    ),
    20: CryptoAlgorithmDef(
        canonical_name="ECP-384 (Group 20)",
        family="DH",
        security_bits=192,
        is_aead=False,
        status_nist="RECOMMENDED",
        status_ietf="SHOULD",
        normative_reference="NIST SP 800-77 Rev. 1 Sec 5.1.2; RFC 8247 Sec 3.2.4",
    ),
    21: CryptoAlgorithmDef(
        canonical_name="ECP-521 (Group 21)",
        family="DH",
        security_bits=256,
        is_aead=False,
        status_nist="RECOMMENDED",
        status_ietf="SHOULD",
        normative_reference="NIST SP 800-77 Rev. 1 Sec 5.1.2; RFC 8247 Sec 3.2.4",
    ),
    31: CryptoAlgorithmDef(
        canonical_name="Curve25519 (Group 31)",
        family="DH",
        security_bits=128,
        is_aead=False,
        status_nist="ACCEPTABLE",
        status_ietf="SHOULD",
        normative_reference="RFC 8031; RFC 8247 Sec 3.2.4",
    ),
}

# -----------------------------------------------------------------------------
# Integrity / Authentication Algorithms
# -----------------------------------------------------------------------------
INTEGRITY_REGISTRY: dict[str, CryptoAlgorithmDef] = {
    "HMAC-SHA256": CryptoAlgorithmDef(
        canonical_name="HMAC-SHA256",
        family="INTEGRITY",
        security_bits=128,
        is_aead=False,
        status_nist="RECOMMENDED",
        status_ietf="MUST",
        normative_reference="NIST SP 800-77 Rev. 1 Sec 5.1.1; RFC 8247 Sec 3.2.2",
    ),
    "HMAC-SHA384": CryptoAlgorithmDef(
        canonical_name="HMAC-SHA384",
        family="INTEGRITY",
        security_bits=192,
        is_aead=False,
        status_nist="RECOMMENDED",
        status_ietf="SHOULD",
        normative_reference="NIST SP 800-77 Rev. 1 Sec 5.1.1; RFC 8247 Sec 3.2.2",
    ),
    "HMAC-SHA512": CryptoAlgorithmDef(
        canonical_name="HMAC-SHA512",
        family="INTEGRITY",
        security_bits=256,
        is_aead=False,
        status_nist="RECOMMENDED",
        status_ietf="SHOULD",
        normative_reference="NIST SP 800-77 Rev. 1 Sec 5.1.1; RFC 8247 Sec 3.2.2",
    ),
    "HMAC-SHA1": CryptoAlgorithmDef(
        canonical_name="HMAC-SHA1",
        family="INTEGRITY",
        security_bits=80,
        is_aead=False,
        status_nist="DISALLOWED",
        status_ietf="MUST_NOT",
        normative_reference="NIST SP 800-131A Rev. 2; RFC 8247 Sec 3.2.2",
    ),
    "HMAC-MD5": CryptoAlgorithmDef(
        canonical_name="HMAC-MD5",
        family="INTEGRITY",
        security_bits=0,
        is_aead=False,
        status_nist="DISALLOWED",
        status_ietf="MUST_NOT",
        normative_reference="NIST SP 800-77 Rev. 1 Sec 5.1.1; RFC 8247 Sec 3.2.2",
    ),
    "NONE": CryptoAlgorithmDef(
        canonical_name="NONE",
        family="INTEGRITY",
        security_bits=0,
        is_aead=False,
        status_nist="DISALLOWED",  # Except when AEAD cipher is active
        status_ietf="MUST_NOT",
        normative_reference="RFC 7296 Sec 3.3.2",
    ),
}

# -----------------------------------------------------------------------------
# PRF Algorithms (IKEv2 RFC 8247)
# -----------------------------------------------------------------------------
PRF_REGISTRY: dict[str, CryptoAlgorithmDef] = {
    "PRF-HMAC-SHA256": CryptoAlgorithmDef(
        canonical_name="PRF-HMAC-SHA256",
        family="PRF",
        security_bits=128,
        is_aead=False,
        status_nist="RECOMMENDED",
        status_ietf="MUST",
        normative_reference="NIST SP 800-77 Rev. 1 Sec 5.1.1; RFC 8247 Sec 3.2.1",
    ),
    "PRF-HMAC-SHA384": CryptoAlgorithmDef(
        canonical_name="PRF-HMAC-SHA384",
        family="PRF",
        security_bits=192,
        is_aead=False,
        status_nist="RECOMMENDED",
        status_ietf="SHOULD",
        normative_reference="NIST SP 800-77 Rev. 1 Sec 5.1.1; RFC 8247 Sec 3.2.1",
    ),
    "PRF-HMAC-SHA512": CryptoAlgorithmDef(
        canonical_name="PRF-HMAC-SHA512",
        family="PRF",
        security_bits=256,
        is_aead=False,
        status_nist="RECOMMENDED",
        status_ietf="SHOULD",
        normative_reference="NIST SP 800-77 Rev. 1 Sec 5.1.1; RFC 8247 Sec 3.2.1",
    ),
    "PRF-HMAC-SHA1": CryptoAlgorithmDef(
        canonical_name="PRF-HMAC-SHA1",
        family="PRF",
        security_bits=80,
        is_aead=False,
        status_nist="DISALLOWED",
        status_ietf="MUST_NOT",
        normative_reference="NIST SP 800-131A Rev. 2; RFC 8247 Sec 3.2.1",
    ),
    "PRF-HMAC-MD5": CryptoAlgorithmDef(
        canonical_name="PRF-HMAC-MD5",
        family="PRF",
        security_bits=0,
        is_aead=False,
        status_nist="DISALLOWED",
        status_ietf="MUST_NOT",
        normative_reference="NIST SP 800-77 Rev. 1 Sec 5.1.1; RFC 8247 Sec 3.2.1",
    ),
}


def normalize_algo_name(raw: str | None) -> str:
    """Normalize raw algorithm string into uppercase registry lookup key."""
    if not raw:
        return ""
    cleaned = raw.strip().upper()
    # Strip common prefixes
    for prefix in ("ENCR_", "AUTH_", "PRF_"):
        if cleaned.startswith(prefix):
            cleaned = cleaned[len(prefix):]
    # Standardize GCM
    if "GCM" in cleaned:
        if "256" in cleaned:
            return "AES-GCM-256"
        return "AES-GCM-16"
    if "CBC" in cleaned:
        if "256" in cleaned:
            return "AES-CBC-256"
        return "AES-CBC"
    if "CHACHA" in cleaned or "POLY1305" in cleaned:
        return "CHACHA20-POLY1305"
    if "3DES" in cleaned or "TRIPLE_DES" in cleaned:
        return "3DES"
    if "DES" in cleaned:
        return "DES"
    if "NULL" in cleaned:
        return "NULL"
    # Integrity mappings
    if "SHA2_256" in cleaned or "SHA256" in cleaned:
        return "HMAC-SHA256"
    if "SHA2_384" in cleaned or "SHA384" in cleaned:
        return "HMAC-SHA384"
    if "SHA2_512" in cleaned or "SHA512" in cleaned:
        return "HMAC-SHA512"
    if "SHA1" in cleaned or "SHA-1" in cleaned:
        return "HMAC-SHA1"
    if "MD5" in cleaned:
        return "HMAC-MD5"
    if "NONE" in cleaned:
        return "NONE"
    return cleaned


def is_aead_cipher(algo_name: str | None) -> bool:
    """Return True if the cipher provides authenticated encryption with associated data."""
    if not algo_name:
        return False
    norm = normalize_algo_name(algo_name)
    algo_def = ENCRYPTION_REGISTRY.get(norm)
    if algo_def:
        return algo_def.is_aead
    return "GCM" in norm or "POLY1305" in norm


def calculate_effective_security_strength(
    encryption_algo: str | None,
    dh_group: int | None,
    integrity_algo: str | None = None,
    prf_algo: str | None = None,
    key_length: int | None = None,
) -> dict[str, Any]:
    """Calculate effective security strength in bits according to the Weakest Link Principle.

    Returns itemized bit strengths and overall bound citing NIST SP 800-57 Part 1 Rev. 5.
    """
    enc_bits: int | None = None
    if encryption_algo:
        norm_enc = normalize_algo_name(encryption_algo)
        enc_def = ENCRYPTION_REGISTRY.get(norm_enc)
        if enc_def:
            enc_bits = enc_def.security_bits
            if key_length and key_length >= 256 and "AES" in norm_enc:
                enc_bits = 256

    dh_bits: int | None = None
    if dh_group:
        dh_def = DH_GROUP_REGISTRY.get(dh_group)
        if dh_def:
            dh_bits = dh_def.security_bits

    integ_bits: int | None = None
    is_aead = is_aead_cipher(encryption_algo)
    if is_aead:
        integ_bits = enc_bits or 128  # AEAD tag matches cipher strength
    elif integrity_algo:
        norm_integ = normalize_algo_name(integrity_algo)
        integ_def = INTEGRITY_REGISTRY.get(norm_integ)
        if integ_def:
            integ_bits = integ_def.security_bits

    prf_bits: int | None = None
    if prf_algo:
        norm_prf = normalize_algo_name(prf_algo)
        prf_def = PRF_REGISTRY.get(f"PRF-{norm_prf}") or PRF_REGISTRY.get(norm_prf)
        if prf_def:
            prf_bits = prf_def.security_bits

    # Weakest link across observable primitives
    evaluable = [b for b in (enc_bits, dh_bits, integ_bits, prf_bits) if b is not None]
    if evaluable:
        min_bits = min(evaluable)
    else:
        min_bits = 0

    return {
        "encryption_bits": enc_bits,
        "diffie_hellman_bits": dh_bits,
        "integrity_bits": integ_bits,
        "prf_bits": prf_bits,
        "is_aead": is_aead,
        "effective_bits": min_bits,
        "weakest_link_principle": True,
        "governing_standard": "NIST SP 800-57 Part 1 Rev. 5 Table 2",
    }
