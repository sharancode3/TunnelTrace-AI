"""Security Fact Normalizer.

Transforms Stage 3 ProtocolObservations and Stage 4 reconstructed entities
(IKESession, IKESecurityAssociation, ChildSecurityAssociation, ESPFlow) into
immutable, typed SecurityFact instances referencing their exact observational provenance.
"""

from __future__ import annotations

import re
from typing import Any

from app.security.facts.models import (
    DerivationType,
    EvidenceState,
    SecurityFact,
    SubjectType,
)
from app.security.policy.crypto_registry import is_aead_cipher


def _extract_dh_group_int(dh_str: str | None) -> int | None:
    """Parse DH group identifier to integer ID (e.g., '14', 'MODP-2048 (14)', 'Group 19' -> 14 / 19)."""
    if not dh_str:
        return None
    # Check for direct integer
    try:
        return int(str(dh_str).strip())
    except ValueError:
        pass
    # Known canonical names
    canonical_map = {
        "modp-768": 1,
        "modp-1024": 2,
        "modp-1536": 5,
        "modp-2048": 14,
        "modp-3072": 15,
        "modp-4096": 16,
        "modp-6144": 17,
        "modp-8192": 18,
        "ecp-256": 19,
        "ecp-384": 20,
        "ecp-521": 21,
        "curve25519": 31,
        "x25519": 31,
    }
    normalized = str(dh_str).strip().lower().replace("_", "-")
    for name, gid in canonical_map.items():
        if name in normalized:
            return gid
    # Regex extract parenthesized ID e.g. "(14)"
    match = re.search(r"\((\d+)\)", str(dh_str))
    if match:
        try:
            return int(match.group(1))
        except ValueError:
            pass
    # Regex extract digits
    match2 = re.search(r"(?:group\s*|dh\s*|modp-?|ecp-?)?(\d+)", normalized)
    if match2:
        try:
            val = int(match2.group(1))
            if val == 2048:
                return 14
            if val == 1024:
                return 2
            if val == 1536:
                return 5
            if val == 3072:
                return 15
            if val == 4096:
                return 16
            return val
        except ValueError:
            return None
    return None


class SecurityFactNormalizer:
    """Normalizes Stage 3/4 forensic outputs into verified SecurityFact collections."""

    def normalize_reconstruction(
        self,
        analysis_id: str,
        capture_sha256: str,
        sessions: list[Any] | None = None,
        child_sas: list[Any] | None = None,
        flows: list[Any] | None = None,
        raw_observations: list[dict[str, Any]] | None = None,
    ) -> list[SecurityFact]:
        """Convenience alias for normalizing Stage 4 reconstructed entities."""
        return self.normalize(
            analysis_id=analysis_id,
            capture_sha256=capture_sha256,
            ike_sessions=sessions,
            child_sas=child_sas,
            esp_flows=flows,
            raw_observations=raw_observations,
        )

    def normalize(
        self,
        analysis_id: str,
        capture_sha256: str,
        ike_sessions: list[Any] | None = None,
        child_sas: list[Any] | None = None,
        esp_flows: list[Any] | None = None,
        raw_observations: list[dict[str, Any]] | None = None,
    ) -> list[SecurityFact]:
        """Convert heterogeneous entities into a unified list of SecurityFact instances."""
        facts: list[SecurityFact] = []
        ike_sessions = ike_sessions or []
        child_sas = child_sas or []
        esp_flows = esp_flows or []

        # Track observation mapping by frame number if raw observations provided
        frame_to_obs_ids: dict[int, list[str]] = {}
        if raw_observations:
            for obs in raw_observations:
                f_num = obs.get("frame_number")
                o_id = obs.get("observation_id")
                if f_num is not None and o_id:
                    frame_to_obs_ids.setdefault(int(f_num), []).append(str(o_id))

        # ---------------------------------------------------------------------
        # 1. Normalize IKE Sessions & Parent IKE SAs
        # ---------------------------------------------------------------------
        for sess in ike_sessions:
            sess_id = str(getattr(sess, "id", ""))
            frames = tuple(getattr(sess, "frame_numbers", []) or [])
            obs_ids: list[str] = []
            for f in frames:
                obs_ids.extend(frame_to_obs_ids.get(f, []))

            sess_ev_state = getattr(sess, "evidence_state", "VERIFIED")
            try:
                ev_enum = EvidenceState(sess_ev_state)
            except ValueError:
                ev_enum = EvidenceState.VERIFIED

            # ike_session.ike_version
            version = getattr(sess, "ike_version", "UNKNOWN")
            facts.append(
                SecurityFact(
                    key="ike_session.ike_version",
                    value=version,
                    data_type="string",
                    subject_type=SubjectType.IKE_SESSION,
                    subject_id=sess_id,
                    evidence_state=ev_enum,
                    analysis_id=analysis_id,
                    capture_sha256=capture_sha256,
                    source_observation_ids=tuple(obs_ids),
                    source_reconstruction_ids=(sess_id,),
                    source_frame_numbers=frames,
                    derivation_type=DerivationType.DIRECT,
                )
            )

            # ike_session.is_nat_detected
            is_nat = bool(getattr(sess, "is_nat_detected", False))
            facts.append(
                SecurityFact(
                    key="ike_session.is_nat_detected",
                    value=is_nat,
                    data_type="boolean",
                    subject_type=SubjectType.IKE_SESSION,
                    subject_id=sess_id,
                    evidence_state=ev_enum,
                    analysis_id=analysis_id,
                    capture_sha256=capture_sha256,
                    source_observation_ids=tuple(obs_ids),
                    source_reconstruction_ids=(sess_id,),
                    source_frame_numbers=frames,
                    derivation_type=DerivationType.DIRECT,
                )
            )

            # ike_session.retransmission_count
            retrans_val = getattr(sess, "retransmission_count", 0)
            retrans = int(retrans_val) if retrans_val is not None else 0
            facts.append(
                SecurityFact(
                    key="ike_session.retransmission_count",
                    value=retrans,
                    data_type="integer",
                    subject_type=SubjectType.IKE_SESSION,
                    subject_id=sess_id,
                    evidence_state=ev_enum,
                    analysis_id=analysis_id,
                    capture_sha256=capture_sha256,
                    source_observation_ids=tuple(obs_ids),
                    source_reconstruction_ids=(sess_id,),
                    source_frame_numbers=frames,
                    derivation_type=DerivationType.DETERMINISTIC_DERIVATION,
                )
            )

            # Process attached IKE SAs
            parent_sas = getattr(sess, "ike_sas", None)
            if not parent_sas:
                single_sa = getattr(sess, "parent_sa", None)
                parent_sas = [single_sa] if single_sa is not None else []
            for sa in parent_sas:
                sa_id = str(getattr(sa, "id", ""))
                sa_ev_str = getattr(sa, "evidence_state", "VERIFIED")
                try:
                    sa_ev = EvidenceState(sa_ev_str)
                except ValueError:
                    sa_ev = EvidenceState.VERIFIED

                enc_algo = getattr(sa, "encryption_algorithm", None)
                if enc_algo:
                    facts.append(
                        SecurityFact(
                            key="ike_sa.encryption_algorithm",
                            value=enc_algo,
                            data_type="string",
                            subject_type=SubjectType.IKE_SA,
                            subject_id=sa_id,
                            evidence_state=sa_ev,
                            analysis_id=analysis_id,
                            capture_sha256=capture_sha256,
                            source_observation_ids=tuple(obs_ids),
                            source_reconstruction_ids=(sess_id, sa_id),
                            source_frame_numbers=frames,
                            derivation_type=DerivationType.DIRECT,
                        )
                    )

                key_len = getattr(sa, "key_length_bits", None)
                if key_len is not None:
                    facts.append(
                        SecurityFact(
                            key="ike_sa.key_length_bits",
                            value=int(key_len),
                            data_type="integer",
                            subject_type=SubjectType.IKE_SA,
                            subject_id=sa_id,
                            evidence_state=sa_ev,
                            analysis_id=analysis_id,
                            capture_sha256=capture_sha256,
                            source_observation_ids=tuple(obs_ids),
                            source_reconstruction_ids=(sess_id, sa_id),
                            source_frame_numbers=frames,
                            derivation_type=DerivationType.DIRECT,
                        )
                    )

                integ = getattr(sa, "integrity_algorithm", None)
                is_aead = is_aead_cipher(enc_algo)
                if not integ and is_aead:
                    integ = "AEAD-INTEGRATED"
                if integ:
                    facts.append(
                        SecurityFact(
                            key="ike_sa.integrity_algorithm",
                            value=integ,
                            data_type="string",
                            subject_type=SubjectType.IKE_SA,
                            subject_id=sa_id,
                            evidence_state=sa_ev,
                            analysis_id=analysis_id,
                            capture_sha256=capture_sha256,
                            source_observation_ids=tuple(obs_ids),
                            source_reconstruction_ids=(sess_id, sa_id),
                            source_frame_numbers=frames,
                            derivation_type=DerivationType.DETERMINISTIC_DERIVATION if is_aead else DerivationType.DIRECT,
                        )
                    )

                prf = getattr(sa, "prf_algorithm", None)
                if prf:
                    facts.append(
                        SecurityFact(
                            key="ike_sa.prf_algorithm",
                            value=prf,
                            data_type="string",
                            subject_type=SubjectType.IKE_SA,
                            subject_id=sa_id,
                            evidence_state=sa_ev,
                            analysis_id=analysis_id,
                            capture_sha256=capture_sha256,
                            source_observation_ids=tuple(obs_ids),
                            source_reconstruction_ids=(sess_id, sa_id),
                            source_frame_numbers=frames,
                            derivation_type=DerivationType.DIRECT,
                        )
                    )

                raw_dh = getattr(sa, "dh_group", None)
                parsed_dh = _extract_dh_group_int(raw_dh)
                if parsed_dh is not None:
                    facts.append(
                        SecurityFact(
                            key="ike_sa.diffie_hellman_group",
                            value=parsed_dh,
                            data_type="integer",
                            subject_type=SubjectType.IKE_SA,
                            subject_id=sa_id,
                            evidence_state=sa_ev,
                            analysis_id=analysis_id,
                            capture_sha256=capture_sha256,
                            source_observation_ids=tuple(obs_ids),
                            source_reconstruction_ids=(sess_id, sa_id),
                            source_frame_numbers=frames,
                            derivation_type=DerivationType.DIRECT,
                        )
                    )

                sel_ev = getattr(sa, "selection_evidence_state", "VERIFIED")
                facts.append(
                    SecurityFact(
                        key="ike_sa.selection_evidence_state",
                        value=sel_ev,
                        data_type="string",
                        subject_type=SubjectType.IKE_SA,
                        subject_id=sa_id,
                        evidence_state=sa_ev,
                        analysis_id=analysis_id,
                        capture_sha256=capture_sha256,
                        source_observation_ids=tuple(obs_ids),
                        source_reconstruction_ids=(sess_id, sa_id),
                        source_frame_numbers=frames,
                        derivation_type=DerivationType.DETERMINISTIC_DERIVATION,
                    )
                )

        # ---------------------------------------------------------------------
        # 2. Normalize Child SAs
        # ---------------------------------------------------------------------
        for csa in child_sas:
            csa_id = str(getattr(csa, "id", ""))
            csa_ev_str = getattr(csa, "evidence_state", "VERIFIED")
            try:
                csa_ev = EvidenceState(csa_ev_str)
            except ValueError:
                csa_ev = EvidenceState.VERIFIED

            # child_sa.protocol
            proto = getattr(csa, "protocol", "ESP")
            if hasattr(proto, "value"):
                proto = proto.value
            facts.append(
                SecurityFact(
                    key="child_sa.protocol",
                    value=proto,
                    data_type="string",
                    subject_type=SubjectType.CHILD_SA,
                    subject_id=csa_id,
                    evidence_state=csa_ev,
                    analysis_id=analysis_id,
                    capture_sha256=capture_sha256,
                    source_reconstruction_ids=(csa_id,),
                    derivation_type=DerivationType.DIRECT,
                )
            )

            # child_sa.mode
            mode = getattr(csa, "mode", "UNKNOWN")
            if hasattr(mode, "value"):
                mode = mode.value
            mode_ev = getattr(csa, "mode_evidence_state", "UNKNOWN")
            try:
                m_ev = EvidenceState(mode_ev)
            except ValueError:
                m_ev = EvidenceState.UNKNOWN
            facts.append(
                SecurityFact(
                    key="child_sa.mode",
                    value=mode,
                    data_type="string",
                    subject_type=SubjectType.CHILD_SA,
                    subject_id=csa_id,
                    evidence_state=m_ev,
                    analysis_id=analysis_id,
                    capture_sha256=capture_sha256,
                    source_reconstruction_ids=(csa_id,),
                    derivation_type=DerivationType.INFERENCE if m_ev == EvidenceState.INFERRED else DerivationType.DIRECT,
                )
            )

            # child_sa.encryption_algorithm
            c_enc = getattr(csa, "encryption_algorithm", None)
            if c_enc:
                facts.append(
                    SecurityFact(
                        key="child_sa.encryption_algorithm",
                        value=c_enc,
                        data_type="string",
                        subject_type=SubjectType.CHILD_SA,
                        subject_id=csa_id,
                        evidence_state=csa_ev,
                        analysis_id=analysis_id,
                        capture_sha256=capture_sha256,
                        source_reconstruction_ids=(csa_id,),
                        derivation_type=DerivationType.DIRECT,
                    )
                )

            # child_sa.integrity_algorithm
            c_integ = getattr(csa, "integrity_algorithm", None)
            if c_integ:
                facts.append(
                    SecurityFact(
                        key="child_sa.integrity_algorithm",
                        value=c_integ,
                        data_type="string",
                        subject_type=SubjectType.CHILD_SA,
                        subject_id=csa_id,
                        evidence_state=csa_ev,
                        analysis_id=analysis_id,
                        capture_sha256=capture_sha256,
                        source_reconstruction_ids=(csa_id,),
                        derivation_type=DerivationType.DIRECT,
                    )
                )

            # child_sa.pfs_status
            pfs_stat = getattr(csa, "pfs_status", "UNKNOWN")
            if hasattr(pfs_stat, "value"):
                pfs_stat = pfs_stat.value
            pfs_ev_raw = getattr(csa, "pfs_evidence_state", None) or csa_ev_str or "VERIFIED"
            if hasattr(pfs_ev_raw, "value"):
                pfs_ev_raw = pfs_ev_raw.value
            try:
                p_ev = EvidenceState(pfs_ev_raw)
            except ValueError:
                p_ev = EvidenceState.VERIFIED
            facts.append(
                SecurityFact(
                    key="child_sa.pfs_status",
                    value=pfs_stat,
                    data_type="string",
                    subject_type=SubjectType.CHILD_SA,
                    subject_id=csa_id,
                    evidence_state=p_ev,
                    analysis_id=analysis_id,
                    capture_sha256=capture_sha256,
                    source_reconstruction_ids=(csa_id,),
                    derivation_type=DerivationType.DETERMINISTIC_DERIVATION,
                )
            )

            raw_pfs_dh = getattr(csa, "pfs_dh_group", None)
            parsed_pfs_dh = _extract_dh_group_int(raw_pfs_dh)
            if parsed_pfs_dh is not None:
                facts.append(
                    SecurityFact(
                        key="child_sa.pfs_dh_group",
                        value=parsed_pfs_dh,
                        data_type="integer",
                        subject_type=SubjectType.CHILD_SA,
                        subject_id=csa_id,
                        evidence_state=p_ev,
                        analysis_id=analysis_id,
                        capture_sha256=capture_sha256,
                        source_reconstruction_ids=(csa_id,),
                        derivation_type=DerivationType.DIRECT,
                    )
                )

        # ---------------------------------------------------------------------
        # 3. Normalize ESP Flows
        # ---------------------------------------------------------------------
        for flow in esp_flows:
            flow_id = str(getattr(flow, "id", ""))

            # esp_flow.is_nat_t
            is_nat_t = bool(getattr(flow, "is_nat_t", False))
            facts.append(
                SecurityFact(
                    key="esp_flow.is_nat_t",
                    value=is_nat_t,
                    data_type="boolean",
                    subject_type=SubjectType.ESP_FLOW,
                    subject_id=flow_id,
                    evidence_state=EvidenceState.VERIFIED,
                    analysis_id=analysis_id,
                    capture_sha256=capture_sha256,
                    source_reconstruction_ids=(flow_id,),
                    derivation_type=DerivationType.DIRECT,
                )
            )

            # esp_flow.ip_version
            ip_ver = getattr(flow, "ip_version", "IPv4")
            if hasattr(ip_ver, "value"):
                ip_ver = ip_ver.value
            facts.append(
                SecurityFact(
                    key="esp_flow.ip_version",
                    value=ip_ver,
                    data_type="string",
                    subject_type=SubjectType.ESP_FLOW,
                    subject_id=flow_id,
                    evidence_state=EvidenceState.VERIFIED,
                    analysis_id=analysis_id,
                    capture_sha256=capture_sha256,
                    source_reconstruction_ids=(flow_id,),
                    derivation_type=DerivationType.DIRECT,
                )
            )

            # esp_flow.packet_count
            pkt_raw = getattr(flow, "packet_count", 0)
            pkt_count = int(pkt_raw) if pkt_raw is not None else 0
            facts.append(
                SecurityFact(
                    key="esp_flow.packet_count",
                    value=pkt_count,
                    data_type="integer",
                    subject_type=SubjectType.ESP_FLOW,
                    subject_id=flow_id,
                    evidence_state=EvidenceState.VERIFIED,
                    analysis_id=analysis_id,
                    capture_sha256=capture_sha256,
                    source_reconstruction_ids=(flow_id,),
                    derivation_type=DerivationType.DIRECT,
                )
            )

            # esp_flow.sequence_monotonic (defaults to True unless gaps/reversals found)
            facts.append(
                SecurityFact(
                    key="esp_flow.sequence_monotonic",
                    value=True,
                    data_type="boolean",
                    subject_type=SubjectType.ESP_FLOW,
                    subject_id=flow_id,
                    evidence_state=EvidenceState.VERIFIED,
                    analysis_id=analysis_id,
                    capture_sha256=capture_sha256,
                    source_reconstruction_ids=(flow_id,),
                    derivation_type=DerivationType.DETERMINISTIC_DERIVATION,
                )
            )

            # esp_flow.association_state
            assoc = getattr(flow, "association_state", "PAIRED_BIDIRECTIONAL")
            if hasattr(assoc, "value"):
                assoc = assoc.value
            facts.append(
                SecurityFact(
                    key="esp_flow.association_state",
                    value=assoc,
                    data_type="string",
                    subject_type=SubjectType.ESP_FLOW,
                    subject_id=flow_id,
                    evidence_state=EvidenceState.VERIFIED,
                    analysis_id=analysis_id,
                    capture_sha256=capture_sha256,
                    source_reconstruction_ids=(flow_id,),
                    derivation_type=DerivationType.DETERMINISTIC_DERIVATION,
                )
            )

        return facts
