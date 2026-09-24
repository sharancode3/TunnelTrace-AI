"""Canonical Security Fact Field Registry.

Guarantees that Policy-as-Code target_field references only valid, typed,
predefined fact keys, preventing arbitrary attribute querying or runtime injection.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.security.facts.models import SubjectType


@dataclass(frozen=True)
class FactFieldDef:
    """Definition and schema contract for a canonical security fact."""

    key: str
    expected_type: str  # "string", "integer", "float", "boolean", "list_string", "list_int"
    subject_type: SubjectType
    description: str
    allowed_values: tuple[Any, ...] | None = None


FACT_FIELD_REGISTRY: dict[str, FactFieldDef] = {
    # -------------------------------------------------------------------------
    # IKE Session Level Facts
    # -------------------------------------------------------------------------
    "ike_session.ike_version": FactFieldDef(
        key="ike_session.ike_version",
        expected_type="string",
        subject_type=SubjectType.IKE_SESSION,
        description="Negotiated IKE protocol version (e.g. IKEv1, IKEv2)",
        allowed_values=("IKEv1", "IKEv2", "UNKNOWN"),
    ),
    "ike_session.is_nat_detected": FactFieldDef(
        key="ike_session.is_nat_detected",
        expected_type="boolean",
        subject_type=SubjectType.IKE_SESSION,
        description="Whether NAT was detected during NAT-D exchange",
    ),
    "ike_session.retransmission_count": FactFieldDef(
        key="ike_session.retransmission_count",
        expected_type="integer",
        subject_type=SubjectType.IKE_SESSION,
        description="Count of duplicate or retransmitted handshake frames",
    ),
    "ike_session.packet_count": FactFieldDef(
        key="ike_session.packet_count",
        expected_type="integer",
        subject_type=SubjectType.IKE_SESSION,
        description="Total IKE control packets in this session",
    ),
    "ike_session.lifecycle_state": FactFieldDef(
        key="ike_session.lifecycle_state",
        expected_type="string",
        subject_type=SubjectType.IKE_SESSION,
        description="Observed lifecycle state of the IKE session",
        allowed_values=("INIT_SEEN", "AUTH_SEEN", "ACTIVE_INFERRED", "PARTIAL", "TERMINATED", "UNKNOWN"),
    ),

    # -------------------------------------------------------------------------
    # IKE SA (Parent Control Plane) Transform Facts
    # -------------------------------------------------------------------------
    "ike_sa.encryption_algorithm": FactFieldDef(
        key="ike_sa.encryption_algorithm",
        expected_type="string",
        subject_type=SubjectType.IKE_SA,
        description="Responder-selected encryption transform for IKE SA (e.g. AES-GCM-16, AES-CBC, 3DES)",
    ),
    "ike_sa.key_length_bits": FactFieldDef(
        key="ike_sa.key_length_bits",
        expected_type="integer",
        subject_type=SubjectType.IKE_SA,
        description="Key length in bits for selected encryption algorithm (e.g. 128, 256)",
    ),
    "ike_sa.integrity_algorithm": FactFieldDef(
        key="ike_sa.integrity_algorithm",
        expected_type="string",
        subject_type=SubjectType.IKE_SA,
        description="Selected integrity transform for IKE SA (e.g. HMAC-SHA256, HMAC-MD5, NONE/AEAD)",
    ),
    "ike_sa.prf_algorithm": FactFieldDef(
        key="ike_sa.prf_algorithm",
        expected_type="string",
        subject_type=SubjectType.IKE_SA,
        description="Pseudo-Random Function for IKE SA key derivation (e.g. PRF-HMAC-SHA256)",
    ),
    "ike_sa.diffie_hellman_group": FactFieldDef(
        key="ike_sa.diffie_hellman_group",
        expected_type="integer",
        subject_type=SubjectType.IKE_SA,
        description="Selected Diffie-Hellman / Key Exchange group ID (e.g. 2, 5, 14, 19, 20, 21)",
    ),
    "ike_sa.selection_evidence_state": FactFieldDef(
        key="ike_sa.selection_evidence_state",
        expected_type="string",
        subject_type=SubjectType.IKE_SA,
        description="Whether transforms were observed selected by responder vs proposed only",
        allowed_values=("VERIFIED", "PROPOSED_ONLY", "UNKNOWN"),
    ),

    # -------------------------------------------------------------------------
    # Child SA (Data Plane) Facts
    # -------------------------------------------------------------------------
    "child_sa.protocol": FactFieldDef(
        key="child_sa.protocol",
        expected_type="string",
        subject_type=SubjectType.CHILD_SA,
        description="Child SA security protocol (ESP or AH)",
        allowed_values=("ESP", "AH"),
    ),
    "child_sa.mode": FactFieldDef(
        key="child_sa.mode",
        expected_type="string",
        subject_type=SubjectType.CHILD_SA,
        description="Operational IPsec mode (TUNNEL, TRANSPORT, UNKNOWN)",
        allowed_values=("TUNNEL", "TRANSPORT", "UNKNOWN"),
    ),
    "child_sa.encryption_algorithm": FactFieldDef(
        key="child_sa.encryption_algorithm",
        expected_type="string",
        subject_type=SubjectType.CHILD_SA,
        description="Child SA ESP encryption algorithm (e.g. AES-GCM-16, AES-CBC, NULL)",
    ),
    "child_sa.integrity_algorithm": FactFieldDef(
        key="child_sa.integrity_algorithm",
        expected_type="string",
        subject_type=SubjectType.CHILD_SA,
        description="Child SA integrity algorithm (e.g. HMAC-SHA256, NONE for AEAD)",
    ),
    "child_sa.pfs_status": FactFieldDef(
        key="child_sa.pfs_status",
        expected_type="string",
        subject_type=SubjectType.CHILD_SA,
        description="Perfect Forward Secrecy state for Child SA rekeying (ENABLED, DISABLED, UNKNOWN)",
        allowed_values=("ENABLED", "DISABLED", "UNKNOWN"),
    ),
    "child_sa.pfs_dh_group": FactFieldDef(
        key="child_sa.pfs_dh_group",
        expected_type="integer",
        subject_type=SubjectType.CHILD_SA,
        description="Diffie-Hellman group negotiated during CREATE_CHILD_SA rekey",
    ),

    # -------------------------------------------------------------------------
    # ESP Flow Level Facts
    # -------------------------------------------------------------------------
    "esp_flow.is_nat_t": FactFieldDef(
        key="esp_flow.is_nat_t",
        expected_type="boolean",
        subject_type=SubjectType.ESP_FLOW,
        description="Whether ESP flow is encapsulated in UDP port 4500 (NAT-Traversal)",
    ),
    "esp_flow.ip_version": FactFieldDef(
        key="esp_flow.ip_version",
        expected_type="string",
        subject_type=SubjectType.ESP_FLOW,
        description="Outer network layer protocol (IPv4 or IPv6)",
        allowed_values=("IPv4", "IPv6"),
    ),
    "esp_flow.sequence_monotonic": FactFieldDef(
        key="esp_flow.sequence_monotonic",
        expected_type="boolean",
        subject_type=SubjectType.ESP_FLOW,
        description="Whether observed ESP sequence numbers progress monotonically without duplicates",
    ),
    "esp_flow.packet_count": FactFieldDef(
        key="esp_flow.packet_count",
        expected_type="integer",
        subject_type=SubjectType.ESP_FLOW,
        description="Total encrypted packets observed in this ESP flow",
    ),
    "esp_flow.association_state": FactFieldDef(
        key="esp_flow.association_state",
        expected_type="string",
        subject_type=SubjectType.ESP_FLOW,
        description="Association pairing state (PAIRED_BIDIRECTIONAL, UNPAIRED_UNIDIRECTIONAL, ORPHAN)",
        allowed_values=("PAIRED_BIDIRECTIONAL", "UNPAIRED_UNIDIRECTIONAL", "ORPHAN"),
    ),
}


def is_known_fact_field(key: str) -> bool:
    """Return True if the key is registered in the canonical fact field registry."""
    return key in FACT_FIELD_REGISTRY


def get_fact_field_def(key: str) -> FactFieldDef | None:
    """Retrieve field definition for a canonical key, or None if unknown."""
    return FACT_FIELD_REGISTRY.get(key)
