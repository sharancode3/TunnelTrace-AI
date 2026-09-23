"""Unit tests for Security Association Builder (Stage 4)."""

import uuid

from app.db.models.capture import ProtocolObservation
from app.reconstruction.models import (
    EvidenceState,
    IKEMessageEvent,
    LifecycleState,
    Mode,
    PFSStatus,
    ReconstructedIKESession,
)
from app.reconstruction.sa.builder import SABuilder


def test_parent_ike_sa_selected_vs_proposed():
    """Verify that responder selected transforms populate active parent SA, not proposals alone."""
    analysis_id = uuid.uuid4()
    builder = SABuilder(analysis_id)

    session = ReconstructedIKESession(
        id=uuid.uuid4(),
        analysis_id=analysis_id,
        initiator_spi="1234567890abcdef",
        responder_spi="fedcba0987654321",
    )

    # Frame 1: Proposals from initiator
    ev1 = IKEMessageEvent(
        frame_number=1,
        packet_time=1.0,
        ike_version="IKEv2",
        initiator_spi="1234567890abcdef",
        responder_spi=None,
        exchange_type="IKE_SA_INIT",
        exchange_id=34,
        message_id=0,
        is_response=False,
        src_ip="198.51.100.1",
        dst_ip="198.51.100.2",
        src_port=500,
        dst_port=500,
        transforms=[
            {"name": "AES-CBC-128", "transform_type": "ENCR", "is_proposal": True, "is_selected": False},
            {"name": "AES-GCM-16-256", "transform_type": "ENCR", "is_proposal": True, "is_selected": False},
        ],
    )

    # Frame 2: Responder selection (AES-GCM-16-256 selected)
    ev2 = IKEMessageEvent(
        frame_number=2,
        packet_time=1.05,
        ike_version="IKEv2",
        initiator_spi="1234567890abcdef",
        responder_spi="fedcba0987654321",
        exchange_type="IKE_SA_INIT",
        exchange_id=34,
        message_id=0,
        is_response=True,
        src_ip="198.51.100.2",
        dst_ip="198.51.100.1",
        src_port=500,
        dst_port=500,
        transforms=[
            {"name": "AES-GCM-16-256", "transform_type": "ENCR", "key_length": 256, "is_selected": True},
            {"name": "PRF_HMAC_SHA2_256", "transform_type": "PRF", "is_selected": True},
            {"name": "ECP-256 (DH19)", "transform_type": "DH", "is_selected": True},
        ],
    )

    parent_sa = builder.build_parent_ike_sa(session, [ev1, ev2])
    assert parent_sa is not None
    assert parent_sa.selection_evidence_state == EvidenceState.VERIFIED
    assert parent_sa.encryption_algorithm == "AES-GCM-16-256"
    assert parent_sa.key_length_bits == 256
    assert parent_sa.prf_algorithm == "PRF_HMAC_SHA2_256"
    assert parent_sa.dh_group == "ECP-256 (DH19)"
    # AEAD GCM should set integrity to NOT_APPLICABLE
    assert parent_sa.integrity_algorithm == "NONE / NOT_APPLICABLE"


def test_proposals_only_keeps_transforms_unknown():
    """Verify that an incomplete exchange with only proposals does not populate selected algorithms."""
    analysis_id = uuid.uuid4()
    builder = SABuilder(analysis_id)

    session = ReconstructedIKESession(
        id=uuid.uuid4(),
        analysis_id=analysis_id,
        initiator_spi="abcdef1234567890",
    )

    ev1 = IKEMessageEvent(
        frame_number=1,
        packet_time=1.0,
        ike_version="IKEv2",
        initiator_spi="abcdef1234567890",
        responder_spi=None,
        exchange_type="IKE_SA_INIT",
        exchange_id=34,
        message_id=0,
        is_response=False,
        src_ip="198.51.100.1",
        dst_ip="198.51.100.2",
        src_port=500,
        dst_port=500,
        transforms=[
            {"name": "AES-CBC-256", "transform_type": "ENCR", "is_proposal": True, "is_selected": False},
        ],
    )

    parent_sa = builder.build_parent_ike_sa(session, [ev1])
    assert parent_sa is not None
    assert parent_sa.selection_evidence_state == EvidenceState.UNKNOWN
    assert parent_sa.encryption_algorithm is None


def test_mode_resolution_explicit_transport():
    """Verify explicit USE_TRANSPORT_MODE notify yields VERIFIED TRANSPORT."""
    analysis_id = uuid.uuid4()
    builder = SABuilder(analysis_id)

    session = ReconstructedIKESession(
        id=uuid.uuid4(),
        analysis_id=analysis_id,
        initiator_spi="1111222233334444",
        responder_spi="5555666677778888",
    )

    ev = IKEMessageEvent(
        frame_number=3,
        packet_time=2.0,
        ike_version="IKEv2",
        initiator_spi="1111222233334444",
        responder_spi="5555666677778888",
        exchange_type="IKE_AUTH",
        exchange_id=35,
        message_id=1,
        is_response=False,
        src_ip="198.51.100.1",
        dst_ip="198.51.100.2",
        src_port=4500,
        dst_port=4500,
        notifies=["USE_TRANSPORT_MODE"],
    )

    esp_obs = [
        ProtocolObservation(
            id=uuid.uuid4(),
            analysis_id=analysis_id,
            frame_number=5,
            packet_time=2.5,
            protocol="ESP",
            category="ESP_HEADER",
            field_name="esp.spi",
            normalized_value="0x12345678",
            source_field="esp.spi",
            source_tool_version="4.6.4",
            src_ip="198.51.100.1",
            dst_ip="198.51.100.2",
        )
    ]

    child_sas = builder.build_child_sas(session, None, [ev], esp_obs)
    assert len(child_sas) == 1
    csa = child_sas[0]
    assert csa.mode == Mode.TRANSPORT
    assert csa.mode_evidence_state == EvidenceState.VERIFIED


def test_mode_resolution_unknown_when_absent():
    """Verify that absence of transport notify does NOT automatically assume Tunnel."""
    analysis_id = uuid.uuid4()
    builder = SABuilder(analysis_id)

    session = ReconstructedIKESession(
        id=uuid.uuid4(),
        analysis_id=analysis_id,
        initiator_spi="9999888877776666",
        responder_spi="5555444433332222",
    )

    ev = IKEMessageEvent(
        frame_number=3,
        packet_time=2.0,
        ike_version="IKEv2",
        initiator_spi="9999888877776666",
        responder_spi="5555444433332222",
        exchange_type="IKE_AUTH",
        exchange_id=35,
        message_id=1,
        is_response=False,
        src_ip="198.51.100.1",
        dst_ip="198.51.100.2",
        src_port=4500,
        dst_port=4500,
        notifies=[],  # No transport notify
    )

    esp_obs = [
        ProtocolObservation(
            id=uuid.uuid4(),
            analysis_id=analysis_id,
            frame_number=5,
            packet_time=2.5,
            protocol="ESP",
            category="ESP_HEADER",
            field_name="esp.spi",
            normalized_value="0xabcdef01",
            source_field="esp.spi",
            source_tool_version="4.6.4",
            src_ip="198.51.100.1",
            dst_ip="198.51.100.2",
        )
    ]

    child_sas = builder.build_child_sas(session, None, [ev], esp_obs)
    assert len(child_sas) == 1
    assert child_sas[0].mode == Mode.UNKNOWN
    assert child_sas[0].mode_evidence_state == EvidenceState.UNKNOWN


def test_orphan_child_sa_esp_only():
    """Verify that ESP packets without IKE produce an orphan Child SA with UNKNOWN crypto."""
    analysis_id = uuid.uuid4()
    builder = SABuilder(analysis_id)

    esp_obs = [
        ProtocolObservation(
            id=uuid.uuid4(),
            analysis_id=analysis_id,
            frame_number=1,
            packet_time=1.0,
            protocol="ESP",
            category="ESP_HEADER",
            field_name="esp.spi",
            normalized_value="0xdeadbeef",
            source_field="esp.spi",
            source_tool_version="4.6.4",
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
        )
    ]

    child_sas = builder.build_child_sas(None, None, [], esp_obs)
    assert len(child_sas) == 1
    csa = child_sas[0]
    assert csa.ike_sa_id is None
    assert csa.lifecycle_state == LifecycleState.ORPHAN
    assert csa.inbound_spi == "0xdeadbeef"
    assert csa.encryption_algorithm is None
    assert csa.integrity_algorithm is None
    assert csa.pfs_status == PFSStatus.UNKNOWN
    assert csa.mode == Mode.UNKNOWN
