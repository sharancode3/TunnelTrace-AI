"""Security Association Builder: Constructs Parent IKE SAs and Child SAs with evidence-based invariants."""

from __future__ import annotations

import re
import uuid
from typing import Any

from app.db.models.capture import ProtocolObservation
from app.reconstruction.models import (
    EvidenceState,
    IKEMessageEvent,
    LifecycleState,
    Mode,
    PFSStatus,
    ReconstructedChildSA,
    ReconstructedIKESession,
    ReconstructedParentIKESA,
    ReconstructedTrafficSelector,
)


class SABuilder:
    """Builds parent IKE Security Associations and Child SAs adhering to strict evidence invariants."""

    def __init__(self, analysis_id: uuid.UUID) -> None:
        self.analysis_id = analysis_id

    def build_parent_ike_sa(
        self,
        session: ReconstructedIKESession,
        events: list[IKEMessageEvent],
    ) -> ReconstructedParentIKESA | None:
        """Construct the parent IKE SA from observed negotiation events.

        Invariant: Only selected/negotiated transforms populate the active SA fields.
        Proposals must NOT be mistaken for selected transforms.
        """
        session_events = [
            e for e in events if e.initiator_spi == session.initiator_spi
        ]
        if not session_events:
            return None

        # Aggregate transforms across session events
        selected_transforms: dict[str, dict[str, Any]] = {}
        proposed_transforms: dict[str, list[dict[str, Any]]] = {}

        for ev in session_events:
            for tf in ev.transforms:
                tf_type = tf.get("transform_type") or self._infer_transform_type(tf.get("name", ""))
                is_selected = tf.get("is_selected", False)
                # In IKE_SA_INIT response (message_id=0, has responder_spi, is 2nd frame), transforms are selected
                if not is_selected and ev.responder_spi and ev.message_id == 0 and ev.frame_number > session_events[0].frame_number:
                    is_selected = True

                if is_selected:
                    selected_transforms[tf_type] = tf
                else:
                    proposed_transforms.setdefault(tf_type, []).append(tf)

        # Build parent SA
        parent_sa = ReconstructedParentIKESA(
            id=uuid.uuid4(),
            session_id=session.id,
            evidence_state=EvidenceState.VERIFIED,
        )

        if selected_transforms:
            parent_sa.selection_evidence_state = EvidenceState.VERIFIED

            # Encryption
            if "ENCR" in selected_transforms:
                encr_tf = selected_transforms["ENCR"]
                parent_sa.encryption_algorithm = encr_tf.get("name")
                # Extract key length
                key_len = encr_tf.get("key_length")
                if not key_len and parent_sa.encryption_algorithm:
                    match = re.search(r"-(\d+)$", parent_sa.encryption_algorithm)
                    if match:
                        key_len = int(match.group(1))
                parent_sa.key_length_bits = key_len

            # PRF
            if "PRF" in selected_transforms:
                parent_sa.prf_algorithm = selected_transforms["PRF"].get("name")

            # Integrity (AEAD handling: AES-GCM does not negotiate separate integrity)
            if "INTEG" in selected_transforms:
                parent_sa.integrity_algorithm = selected_transforms["INTEG"].get("name")
            elif parent_sa.encryption_algorithm and "GCM" in parent_sa.encryption_algorithm.upper():
                parent_sa.integrity_algorithm = "NONE / NOT_APPLICABLE"
            else:
                parent_sa.integrity_algorithm = None

            # DH Group
            if "DH" in selected_transforms:
                parent_sa.dh_group = selected_transforms["DH"].get("name")

            parent_sa.established_at = session.last_observed_at
        elif proposed_transforms:
            # Only proposals observed (incomplete/unanswered negotiation)
            parent_sa.selection_evidence_state = EvidenceState.UNKNOWN
            # Active transforms remain None (UNKNOWN)
            parent_sa.encryption_algorithm = None
            parent_sa.integrity_algorithm = None
            parent_sa.prf_algorithm = None
            parent_sa.dh_group = None
        else:
            return None

        return parent_sa

    def build_child_sas(
        self,
        session: ReconstructedIKESession | None,
        parent_sa: ReconstructedParentIKESA | None,
        events: list[IKEMessageEvent],
        esp_observations: list[ProtocolObservation],
    ) -> list[ReconstructedChildSA]:
        """Construct Child SAs from observable IKE notifications and ESP wire traffic.

        Invariants:
        1. Never copy parent IKE SA transforms into Child SA.
        2. Mode evaluates to TRANSPORT only if USE_TRANSPORT_MODE is observed. Never default to Tunnel!
        3. PFS evaluates to ENABLED only if CREATE_CHILD_SA KE payload is observed.
        4. Orphan ESP without IKE creates Child SA with parent = NULL and UNKNOWN crypto.
        """
        # 1. Determine Mode from IKE notifications (Tier 1: Explicit evidence)
        mode = Mode.UNKNOWN
        mode_evidence = EvidenceState.UNKNOWN
        pfs_status = PFSStatus.UNKNOWN
        pfs_dh_group = None
        pfs_evidence = EvidenceState.UNKNOWN

        session_events = []
        if session:
            session_events = [e for e in events if e.initiator_spi == session.initiator_spi]
            for ev in session_events:
                # Check for explicit USE_TRANSPORT_MODE notify
                if "USE_TRANSPORT_MODE" in ev.notifies:
                    mode = Mode.TRANSPORT
                    mode_evidence = EvidenceState.VERIFIED

                # Check for CREATE_CHILD_SA KE / DH transform
                if "CREATE_CHILD_SA" in ev.exchange_type:
                    for tf in ev.transforms:
                        if tf.get("transform_type") == "DH" or "DH" in tf.get("name", ""):
                            pfs_status = PFSStatus.ENABLED
                            pfs_dh_group = tf.get("name")
                            pfs_evidence = EvidenceState.VERIFIED

        # 2. Extract unique directional ESP SPIs and endpoints
        # Group ESP packets by (src_ip, dst_ip, spi)
        directional_spis: dict[tuple[str, str, str], list[ProtocolObservation]] = {}
        for obs in esp_observations:
            if obs.field_name == "esp.spi":
                spi = obs.normalized_value.lower()
                src = obs.src_ip or "0.0.0.0"
                dst = obs.dst_ip or "0.0.0.0"
                directional_spis.setdefault((src, dst, spi), []).append(obs)

        if not directional_spis:
            # No ESP packets; if session exists with CREATE_CHILD_SA, could be an IKE-only session
            return []

        # 3. Pair opposing directional SPIs into Child SAs
        # An IPsec Child SA conversation consists of:
        # Stream 1: (Host A -> Host B, SPI_1)
        # Stream 2: (Host B -> Host A, SPI_2)
        child_sas: list[ReconstructedChildSA] = []
        consumed_keys: set[tuple[str, str, str]] = set()

        keys_list = list(directional_spis.keys())
        for i, key1 in enumerate(keys_list):
            if key1 in consumed_keys:
                continue

            src1, dst1, spi1 = key1
            pkts1 = directional_spis[key1]
            first_time = min(p.packet_time for p in pkts1)
            last_time = max(p.packet_time for p in pkts1)

            # Look for reverse stream: (dst1, src1, spi2)
            paired_key = None
            for j in range(i + 1, len(keys_list)):
                key2 = keys_list[j]
                if key2 in consumed_keys:
                    continue
                src2, dst2, spi2 = key2
                if src2 == dst1 and dst2 == src1:
                    paired_key = key2
                    break

            inbound_spi = spi1
            outbound_spi = None
            if paired_key:
                outbound_spi = paired_key[2]
                consumed_keys.add(paired_key)
                pkts2 = directional_spis[paired_key]
                first_time = min(first_time, min(p.packet_time for p in pkts2))
                last_time = max(last_time, max(p.packet_time for p in pkts2))

            consumed_keys.add(key1)

            # Determine lifecycle
            is_orphan = (parent_sa is None)
            lifecycle = LifecycleState.ORPHAN if is_orphan else LifecycleState.ACTIVE_INFERRED

            # Traffic selectors if observable
            selectors = []
            for ev in session_events:
                for ts in ev.traffic_selectors:
                    selectors.append(
                        ReconstructedTrafficSelector(
                            id=uuid.uuid4(),
                            child_sa_id=uuid.uuid4(),  # updated below
                            direction=ts.get("direction", "INITIATOR"),
                            ip_subnet=ts.get("ip_subnet"),
                            start_ip=ts.get("start_ip"),
                            end_ip=ts.get("end_ip"),
                            ip_protocol=ts.get("ip_protocol", 0),
                            start_port=ts.get("start_port", 0),
                            end_port=ts.get("end_port", 65535),
                            evidence_state=EvidenceState.VERIFIED,
                        )
                    )

            c_sa_id = uuid.uuid4()
            for s in selectors:
                s.child_sa_id = c_sa_id

            child_sa = ReconstructedChildSA(
                id=c_sa_id,
                analysis_id=self.analysis_id,
                ike_sa_id=parent_sa.id if parent_sa else None,
                protocol="ESP",
                inbound_spi=inbound_spi,
                outbound_spi=outbound_spi,
                src_ip=src1,
                dst_ip=dst1,
                mode=mode,
                mode_evidence_state=mode_evidence,
                # Invariant: Passive capture cannot see inner Child-SA cipher without keys!
                encryption_algorithm=None,
                integrity_algorithm=None,
                pfs_status=pfs_status,
                pfs_dh_group=pfs_dh_group,
                pfs_evidence_state=pfs_evidence,
                first_observed_at=first_time,
                last_observed_at=last_time,
                lifecycle_state=lifecycle,
                evidence_state=EvidenceState.VERIFIED,
                traffic_selectors=selectors,
            )
            child_sas.append(child_sa)

        return child_sas

    def _infer_transform_type(self, name: str) -> str:
        """Helper to infer transform type from name if missing."""
        uname = name.upper()
        if "AES" in uname or "3DES" in uname or "CHACHA" in uname:
            return "ENCR"
        if "PRF" in uname:
            return "PRF"
        if "SHA" in uname or "MD5" in uname:
            return "INTEG"
        if "DH" in uname or "MODP" in uname or "ECP" in uname or "CURVE" in uname:
            return "DH"
        return "UNKNOWN"
