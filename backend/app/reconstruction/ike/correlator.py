"""IKE Session Correlator: Reconstructs stateful IKEv1/IKEv2 sessions from protocol observations."""

from __future__ import annotations

import uuid
from typing import Any

from app.db.models.capture import ProtocolObservation
from app.reconstruction.models import (
    EvidenceState,
    IKEMessageEvent,
    LifecycleState,
    ReconstructedIKESession,
)


class IKEEventCorrelator:
    """Extracts, orders, deduplicates, and correlates IKE message events into logical sessions."""

    def __init__(self, analysis_id: uuid.UUID) -> None:
        self.analysis_id = analysis_id

    def extract_events_from_observations(
        self, observations: list[ProtocolObservation]
    ) -> list[IKEMessageEvent]:
        """Aggregate frame-level observations into unified IKEMessageEvents."""
        # 1. Group observations by frame_number
        frames: dict[int, dict[str, Any]] = {}
        for obs in observations:
            if not obs.protocol.startswith("IKE"):
                continue

            fn = obs.frame_number
            if fn not in frames:
                frames[fn] = {
                    "frame_number": fn,
                    "packet_time": obs.packet_time,
                    "ike_version": obs.protocol,
                    "initiator_spi": None,
                    "responder_spi": None,
                    "exchange_type": "UNKNOWN_EXCHANGE",
                    "exchange_id": None,
                    "message_id": 0,
                    "is_response": False,
                    "src_ip": obs.src_ip,
                    "dst_ip": obs.dst_ip,
                    "src_port": obs.src_port,
                    "dst_port": obs.dst_port,
                    "is_natt": False,
                    "transforms": [],
                    "notifies": [],
                    "traffic_selectors": [],
                }

            f = frames[fn]
            # Capture updated endpoint details if available
            if obs.src_ip:
                f["src_ip"] = obs.src_ip
            if obs.dst_ip:
                f["dst_ip"] = obs.dst_ip
            if obs.src_port:
                f["src_port"] = obs.src_port
            if obs.dst_port:
                f["dst_port"] = obs.dst_port

            if obs.field_name == "ike.initiator_spi":
                f["initiator_spi"] = obs.normalized_value.lower()
            elif obs.field_name == "ike.responder_spi":
                val = obs.normalized_value.lower()
                # Exclude all-zero responder SPIs
                if val.replace("0", ""):
                    f["responder_spi"] = val
            elif obs.field_name == "ike.exchange_type":
                f["exchange_type"] = obs.normalized_value
                f["exchange_id"] = obs.raw_numeric_id
            elif obs.field_name == "ike.message_id":
                try:
                    f["message_id"] = int(obs.normalized_value)
                except ValueError:
                    pass
            elif obs.field_name.startswith("ike.transform.") or obs.field_name == "ike.transform":
                tf_type = obs.field_name.split(".")[-1].upper() if "." in obs.field_name else "UNKNOWN"
                tf_info = {
                    "name": obs.normalized_value,
                    "transform_type": tf_type,
                    "raw_id": obs.raw_numeric_id,
                }
                if obs.extra_attributes:
                    tf_info.update(obs.extra_attributes)
                f["transforms"].append(tf_info)
            elif obs.field_name == "ike.ke.dh_group":
                f["transforms"].append({
                    "name": obs.normalized_value,
                    "transform_type": "DH",
                    "raw_id": obs.raw_numeric_id,
                })
            elif obs.field_name.startswith("ike.notify") or obs.category == "IKE_NOTIFY":
                f["notifies"].append(obs.normalized_value)
            elif obs.field_name == "ike.traffic_selector":
                if obs.extra_attributes:
                    f["traffic_selectors"].append(obs.extra_attributes)

            # Check NAT-T (UDP port 4500)
            if f["src_port"] == 4500 or f["dst_port"] == 4500:
                f["is_natt"] = True

        # Convert to IKEMessageEvent objects and stable-sort by (packet_time, frame_number)
        events = []
        for fn in sorted(frames.keys(), key=lambda k: (frames[k]["packet_time"], k)):
            data = frames[fn]
            if not data["initiator_spi"]:
                continue

            events.append(
                IKEMessageEvent(
                    frame_number=data["frame_number"],
                    packet_time=data["packet_time"],
                    ike_version=data["ike_version"],
                    initiator_spi=data["initiator_spi"],
                    responder_spi=data["responder_spi"],
                    exchange_type=data["exchange_type"],
                    exchange_id=data["exchange_id"],
                    message_id=data["message_id"],
                    is_response=data["is_response"],
                    src_ip=data["src_ip"],
                    dst_ip=data["dst_ip"],
                    src_port=data["src_port"],
                    dst_port=data["dst_port"],
                    is_natt=data["is_natt"],
                    transforms=data["transforms"],
                    notifies=data["notifies"],
                    traffic_selectors=data["traffic_selectors"],
                )
            )

        return events

    def correlate_sessions(
        self, events: list[IKEMessageEvent]
    ) -> list[ReconstructedIKESession]:
        """Correlate ordered events into deduplicated logical IKE sessions."""
        sessions_by_ispi: dict[str, ReconstructedIKESession] = {}
        # Track seen (ispi, message_id, exchange_type, src_ip) to detect retransmissions
        seen_messages: set[tuple[str, int, str, str | None]] = set()

        for ev in events:
            ispi = ev.initiator_spi

            # 1. Match or create session by initiator SPI
            if ispi not in sessions_by_ispi:
                sess = ReconstructedIKESession(
                    id=uuid.uuid4(),
                    analysis_id=self.analysis_id,
                    initiator_spi=ispi,
                    responder_spi=ev.responder_spi,
                    ike_version=ev.ike_version,
                    initiator_ip=ev.src_ip,
                    responder_ip=ev.dst_ip,
                    initiator_port=ev.src_port,
                    responder_port=ev.dst_port,
                    first_observed_at=ev.packet_time,
                    last_observed_at=ev.packet_time,
                    lifecycle_state=LifecycleState.INIT_SEEN,
                    is_nat_detected=ev.is_natt,
                    retransmission_count=0,
                    packet_count=1,
                    evidence_state=EvidenceState.VERIFIED,
                    frame_numbers=[ev.frame_number],
                )
                sessions_by_ispi[ispi] = sess
            else:
                sess = sessions_by_ispi[ispi]
                sess.packet_count += 1
                sess.last_observed_at = max(sess.last_observed_at, ev.packet_time)
                sess.frame_numbers.append(ev.frame_number)

                # Upgrade responder SPI if previously unknown/zero and now observed
                if not sess.responder_spi and ev.responder_spi:
                    sess.responder_spi = ev.responder_spi
                    # Assign responder IP/port from this response event
                    if ev.src_ip and ev.src_ip != sess.initiator_ip:
                        sess.responder_ip = ev.src_ip
                        sess.responder_port = ev.src_port

                # Preserve NAT-T port transition
                if ev.is_natt:
                    sess.is_nat_detected = True

                # Update lifecycle state
                if "IKE_AUTH" in ev.exchange_type:
                    sess.lifecycle_state = LifecycleState.AUTH_SEEN
                elif "CREATE_CHILD_SA" in ev.exchange_type and sess.lifecycle_state == LifecycleState.AUTH_SEEN:
                    sess.lifecycle_state = LifecycleState.ACTIVE_INFERRED

            # 2. Retransmission detection
            msg_sig = (ispi, ev.message_id, ev.exchange_type, ev.src_ip)
            if msg_sig in seen_messages:
                sess.retransmission_count += 1
            else:
                seen_messages.add(msg_sig)

        # Final pass: refine lifecycle states
        for sess in sessions_by_ispi.values():
            if sess.lifecycle_state == LifecycleState.AUTH_SEEN:
                sess.lifecycle_state = LifecycleState.ACTIVE_INFERRED
            elif not sess.responder_spi:
                sess.lifecycle_state = LifecycleState.PARTIAL

        return list(sessions_by_ispi.values())
