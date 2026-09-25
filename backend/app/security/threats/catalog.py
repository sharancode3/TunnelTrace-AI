"""Pre-Authored, Authoritative Threat Catalog.

Guarantees that operational threat scenarios, exploitation vectors, and CIA impacts
are strictly sourced from verified cybersecurity literature, RFCs, and authoritative
MITRE ATT&CK techniques without any LLM invention.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from app.security.risk.models import Impact, Likelihood
from app.security.threats.models import MitreAttackMapping, ThreatCatalogEntry

THREAT_CATALOG: dict[str, ThreatCatalogEntry] = {
    "THR-001": ThreatCatalogEntry(
        threat_id="THR-001",
        version="1.0.0",
        name="Pre-Computation Diffie-Hellman Discrete Logarithm Break",
        description=(
            "Adversary exploits small Diffie-Hellman prime moduli (MODP-1024 or MODP-768) "
            "to precompute number field sieve logs, solving discrete logarithms in real time (Logjam attack)."
        ),
        affected_asset="IKE SA Key Material & SKEYSEED",
        preconditions="Negotiation of DH Group 1, Group 2, or Group 5.",
        attack_vector="Passive wiretap + precomputed Discrete Logarithm table lookup.",
        cia_impact="Complete loss of confidentiality and integrity for parent IKE and derived Child SAs.",
        default_likelihood=Likelihood.HIGH,
        default_impact=Impact.HIGH,
        mapped_root_cause_keys=("DH_GROUP_WEAK_LOGJAM", "RC_DH_WEAK_GROUP"),
        authoritative_reference="NIST SP 800-77 Rev. 1 Section 5.1.2; RFC 8247 Section 3.2.4",
        mitre_attack=None,  # Intentionally unmapped: pure cryptanalytic weakness, not an adversary execution technique
        mitre_attack_id=None,
    ),
    "THR-002": ThreatCatalogEntry(
        threat_id="THR-002",
        version="1.0.0",
        name="Sweet32 Birthday Collision Attack on 64-bit Block Ciphers",
        description=(
            "Adversary observes high-volume ESP flows encrypted with 64-bit block ciphers (3DES/Blowfish), "
            "recovering plaintext XOR differences after 2^32 ciphertext block collisions."
        ),
        affected_asset="ESP Data Plane Traffic",
        preconditions="Use of 3DES or DES in Child SA with flow volume exceeding birthday bound.",
        attack_vector="Passive wiretap monitoring high-packet volume ESP flow.",
        cia_impact="Partial or complete recovery of sensitive plaintext session data.",
        default_likelihood=Likelihood.MEDIUM,
        default_impact=Impact.HIGH,
        mapped_root_cause_keys=("CIPHER_DEPRECATED_DES", "RC_CIPHER_3DES"),
        authoritative_reference="RFC 9395 Section 2; CVE-2016-2183 (Sweet32)",
        mitre_attack=None,  # Intentionally unmapped: cryptographic block collision property, not an ATT&CK technique
        mitre_attack_id=None,
    ),
    "THR-003": ThreatCatalogEntry(
        threat_id="THR-003",
        version="1.0.0",
        name="Cleartext Protocol Downgrade & Main Mode Identity Interception",
        description=(
            "Legacy IKEv1 deployments expose initiator identities in cleartext during Main Mode negotiations "
            "and are vulnerable to offline dictionary cracking of pre-shared keys in Aggressive Mode."
        ),
        affected_asset="IKE Peer Identity & Authentication Material",
        preconditions="Use of legacy IKEv1 protocol.",
        attack_vector="Passive eavesdropping or Active Man-in-the-Middle handshake manipulation.",
        cia_impact="Identity leakage, offline credential recovery, and gateway impersonation.",
        default_likelihood=Likelihood.HIGH,
        default_impact=Impact.HIGH,
        mapped_root_cause_keys=("PROTOCOL_LEGACY_IKEV1", "RC_PROTOCOL_IKEV1"),
        authoritative_reference="RFC 7296 Section 1.2; RFC 8247 Section 3",
        mitre_attack=MitreAttackMapping(
            technique_id="T1110.002",
            technique_name="Password Cracking",
            domain="Enterprise",
            dataset_version="v15.1",
            mapping_type="EXPLOITS_WEAKNESS",
            rationale=(
                "Adversaries intercept IKEv1 Aggressive Mode authentication exchanges over the wire "
                "and perform offline dictionary or brute-force cracking against pre-shared key (PSK) hashes."
            ),
            source_url="https://attack.mitre.org/techniques/T1110/002/",
            verification_date="2026-09-25",
        ),
    ),
    "THR-004": ThreatCatalogEntry(
        threat_id="THR-004",
        version="1.0.0",
        name="Hash Collision Forgery against Insecure Authentication",
        description=(
            "Broken hash algorithms (MD5 / SHA-1) permit practical collision generation, "
            "allowing attackers to craft forged authentication payloads or falsify IKE integrity checks."
        ),
        affected_asset="IKE Handshake Integrity & Message Authentication",
        preconditions="Negotiation of HMAC-MD5 or HMAC-SHA-1 integrity transforms.",
        attack_vector="Active cryptographic collision generation against handshake messages.",
        cia_impact="Bypass of message authentication and potential unauthorized tunnel establishment.",
        default_likelihood=Likelihood.MEDIUM,
        default_impact=Impact.HIGH,
        mapped_root_cause_keys=("INTEGRITY_DEPRECATED_HASH", "RC_INTEGRITY_WEAK_HASH"),
        authoritative_reference="NIST SP 800-131A Rev. 2; NIST SP 800-77 Rev. 1 Section 5.1.1",
        mitre_attack=None,  # Intentionally unmapped: mathematical hash collision forgery
        mitre_attack_id=None,
    ),
    "THR-005": ThreatCatalogEntry(
        threat_id="THR-005",
        version="1.0.0",
        name="Ciphertext Bit-Flipping Manipulation without Cryptographic Integrity",
        description=(
            "Operating ESP in non-AEAD mode without a cryptographic integrity algorithm "
            "permits active attackers to modify ciphertext in transit without detection (bit-flipping attacks)."
        ),
        affected_asset="Encrypted Payload Integrity",
        preconditions="Negotiation of non-AEAD cipher with integrity set to NONE or NULL.",
        attack_vector="Active in-flight packet modification.",
        cia_impact="Undetected data tampering, packet payload corruption, and route redirection.",
        default_likelihood=Likelihood.HIGH,
        default_impact=Impact.HIGH,
        mapped_root_cause_keys=("INTEGRITY_MISSING_NON_AEAD", "RC_ESP_INTEGRITY_NONE"),
        authoritative_reference="RFC 4303 Section 3.3.2; RFC 7296 Section 3.3.2",
        mitre_attack=MitreAttackMapping(
            technique_id="T1565.002",
            technique_name="Transmitted Data Manipulation",
            domain="Enterprise",
            dataset_version="v15.1",
            mapping_type="EXPLOITS_WEAKNESS",
            rationale=(
                "Active on-path adversaries manipulate ESP ciphertext in transit when CBC encryption is "
                "deployed without cryptographic integrity protection (bit-flipping attack)."
            ),
            source_url="https://attack.mitre.org/techniques/T1565/002/",
            verification_date="2026-09-25",
        ),
    ),
    "THR-006": ThreatCatalogEntry(
        threat_id="THR-006",
        version="1.0.0",
        name="Passive Side-Channel Metadata Traffic Profiling",
        description=(
            "Distinctive packet length distributions, inter-arrival times, and burst dynamics "
            "enable passive observers to probabilistically infer application classes (VoIP, Video, Chat) "
            "without decrypting ESP payloads."
        ),
        affected_asset="Operational Privacy & User Activity Context",
        preconditions="High behavioral metadata distinguishability in unpadded ESP traffic.",
        attack_vector="Passive statistical side-channel analysis of packet size and timing sequences.",
        cia_impact="Reconnaissance, intelligence gathering, and user activity monitoring.",
        default_likelihood=Likelihood.HIGH,
        default_impact=Impact.LOW,
        mapped_root_cause_keys=("METADATA_FINGERPRINTABILITY_HIGH",),
        authoritative_reference="RFC 4303 Section 2.6 (Traffic Flow Confidentiality); NTRO PS 160",
        mitre_attack=None,  # Intentionally unmapped: statistical traffic analysis without specific ATT&CK technique
        mitre_attack_id=None,
    ),
    "THR-007": ThreatCatalogEntry(
        threat_id="THR-007",
        version="1.0.0",
        name="Replay Desynchronization & State Injection",
        description=(
            "Duplicate, inverted, or non-monotonic ESP sequence numbers indicate potential "
            "packet replay attacks or reordering vulnerabilities, allowing adversaries to disrupt state."
        ),
        affected_asset="IPsec Receiver State Machine",
        preconditions="Anti-replay window disabled or bypassed by transmission anomalies.",
        attack_vector="Packet replay injection into established ESP stream.",
        cia_impact="Denial of service, connection teardown, or receiver state corruption.",
        default_likelihood=Likelihood.LOW,
        default_impact=Impact.MEDIUM,
        mapped_root_cause_keys=("REPLAY_SEQUENCE_NON_MONOTONIC", "RC_REPLAY_ANOMALY"),
        authoritative_reference="RFC 4303 Section 3.3.3",
        mitre_attack=None,  # Intentionally unmapped: sequence desynchronization anomaly
        mitre_attack_id=None,
    ),
    "THR-008": ThreatCatalogEntry(
        threat_id="THR-008",
        version="1.0.0",
        name="ESP Cleartext Data Exposure via NULL Encryption",
        description=(
            "Negotiating NULL encryption for ESP flows leaves data payloads in cleartext, "
            "allowing passive network observers to inspect, intercept, and exfiltrate unencrypted application traffic."
        ),
        affected_asset="ESP Data Plane Traffic",
        preconditions="Use of NULL or ENCR_NULL cipher in Child SA.",
        attack_vector="Passive wiretap sniffing unencrypted payload bytes.",
        cia_impact="Complete loss of confidentiality for application payloads.",
        default_likelihood=Likelihood.HIGH,
        default_impact=Impact.HIGH,
        mapped_root_cause_keys=("CIPHER_NULL_CLEARTEXT", "RC_ESP_NULL_CIPHER"),
        authoritative_reference="RFC 8221 Section 4; RFC 4303 Section 3.3",
        mitre_attack=MitreAttackMapping(
            technique_id="T1040",
            technique_name="Network Sniffing",
            domain="Enterprise",
            dataset_version="v15.1",
            mapping_type="EXPLOITS_WEAKNESS",
            rationale=(
                "Passive network observers capture and inspect cleartext application traffic traversing "
                "IPsec tunnels configured with NULL encryption (RFC 8221 non-compliance)."
            ),
            source_url="https://attack.mitre.org/techniques/T1040/",
            verification_date="2026-09-25",
        ),
    ),
}


def compute_catalog_hash() -> str:
    """Compute deterministic canonical SHA-256 hash over all threat catalog entries."""
    canonical_list: list[dict[str, Any]] = []

    for threat_id in sorted(THREAT_CATALOG.keys()):
        entry = THREAT_CATALOG[threat_id]
        mitre_dict = entry.mitre_attack.to_dict() if entry.mitre_attack else None
        canonical_list.append(
            {
                "threat_id": entry.threat_id,
                "version": entry.version,
                "name": entry.name,
                "description": entry.description,
                "affected_asset": entry.affected_asset,
                "preconditions": entry.preconditions,
                "attack_vector": entry.attack_vector,
                "cia_impact": entry.cia_impact,
                "default_likelihood": entry.default_likelihood.value,
                "default_impact": entry.default_impact.value,
                "mapped_root_cause_keys": sorted(entry.mapped_root_cause_keys),
                "authoritative_reference": entry.authoritative_reference,
                "mitre_attack": mitre_dict,
            }
        )

    serialized = json.dumps(canonical_list, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


# Authoritative precomputed hash for quick reference
THREAT_CATALOG_CANONICAL_HASH: str = compute_catalog_hash()


def get_threat_by_id(threat_id: str) -> ThreatCatalogEntry | None:
    """Retrieve catalog entry by ID."""
    return THREAT_CATALOG.get(threat_id)


def find_threat_for_root_cause(root_cause_key: str) -> ThreatCatalogEntry | None:
    """Find catalog entry matching a finding's root-cause key."""
    for entry in THREAT_CATALOG.values():
        if root_cause_key in entry.mapped_root_cause_keys:
            return entry
    return None
