"""Unit tests for IKE Session Correlator (Stage 4)."""

import uuid

from app.db.models.capture import ProtocolObservation
from app.reconstruction.ike.correlator import IKEEventCorrelator
from app.reconstruction.models import LifecycleState


def _make_obs(
    frame_number: int,
    packet_time: float,
    field_name: str,
    normalized_value: str,
    src_ip: str = "198.51.100.1",
    dst_ip: str = "198.51.100.2",
    src_port: int = 500,
    dst_port: int = 500,
    raw_numeric_id: int | None = None,
    extra_attributes: dict | None = None,
) -> ProtocolObservation:
    return ProtocolObservation(
        id=uuid.uuid4(),
        analysis_id=uuid.uuid4(),
        frame_number=frame_number,
        packet_time=packet_time,
        protocol="IKEv2",
        category="IKE_HEADER",
        field_name=field_name,
        normalized_value=normalized_value,
        raw_numeric_id=raw_numeric_id,
        source_field=field_name,
        source_tool_version="4.6.4",
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        extra_attributes=extra_attributes,
    )


def test_initial_request_responder_spi_upgrade():
    """Verify that an initial request with zero responder SPI is upgraded when response arrives."""
    analysis_id = uuid.uuid4()
    correlator = IKEEventCorrelator(analysis_id)

    # Frame 1: IKE_SA_INIT request (initiator SPI only)
    f1_obs = [
        _make_obs(1, 100.0, "ike.initiator_spi", "a1b2c3d4e5f67890"),
        _make_obs(1, 100.0, "ike.exchange_type", "IKE_SA_INIT", raw_numeric_id=34),
        _make_obs(1, 100.0, "ike.message_id", "0"),
    ]

    # Frame 2: IKE_SA_INIT response (both SPIs present)
    f2_obs = [
        _make_obs(2, 100.05, "ike.initiator_spi", "a1b2c3d4e5f67890", src_ip="198.51.100.2", dst_ip="198.51.100.1"),
        _make_obs(2, 100.05, "ike.responder_spi", "f9e8d7c6b5a43210", src_ip="198.51.100.2", dst_ip="198.51.100.1"),
        _make_obs(2, 100.05, "ike.exchange_type", "IKE_SA_INIT", raw_numeric_id=34, src_ip="198.51.100.2", dst_ip="198.51.100.1"),
        _make_obs(2, 100.05, "ike.message_id", "0", src_ip="198.51.100.2", dst_ip="198.51.100.1"),
    ]

    events = correlator.extract_events_from_observations(f1_obs + f2_obs)
    assert len(events) == 2

    sessions = correlator.correlate_sessions(events)
    assert len(sessions) == 1
    sess = sessions[0]
    assert sess.initiator_spi == "a1b2c3d4e5f67890"
    assert sess.responder_spi == "f9e8d7c6b5a43210"
    assert sess.initiator_ip == "198.51.100.1"
    assert sess.responder_ip == "198.51.100.2"
    assert sess.packet_count == 2
    assert sess.retransmission_count == 0


def test_retransmission_detection():
    """Verify that retransmitted IKE packets increment retransmission_count without duplicating sessions."""
    analysis_id = uuid.uuid4()
    correlator = IKEEventCorrelator(analysis_id)

    # Frame 1: Request
    f1 = [
        _make_obs(1, 10.0, "ike.initiator_spi", "1122334455667788"),
        _make_obs(1, 10.0, "ike.exchange_type", "IKE_AUTH", raw_numeric_id=35),
        _make_obs(1, 10.0, "ike.message_id", "1"),
    ]
    # Frame 2: Retransmission of Request (same message_id, same exchange, same direction)
    f2 = [
        _make_obs(2, 12.0, "ike.initiator_spi", "1122334455667788"),
        _make_obs(2, 12.0, "ike.exchange_type", "IKE_AUTH", raw_numeric_id=35),
        _make_obs(2, 12.0, "ike.message_id", "1"),
    ]

    events = correlator.extract_events_from_observations(f1 + f2)
    sessions = correlator.correlate_sessions(events)

    assert len(sessions) == 1
    sess = sessions[0]
    assert sess.packet_count == 2
    assert sess.retransmission_count == 1


def test_natt_port_continuation():
    """Verify that transitioning from port 500 to port 4500 does NOT split the session."""
    analysis_id = uuid.uuid4()
    correlator = IKEEventCorrelator(analysis_id)

    # Frame 1: Port 500 IKE_SA_INIT
    f1 = [
        _make_obs(1, 1.0, "ike.initiator_spi", "aabbccddeeff0011", src_port=500, dst_port=500),
        _make_obs(1, 1.0, "ike.exchange_type", "IKE_SA_INIT", src_port=500, dst_port=500),
        _make_obs(1, 1.0, "ike.message_id", "0", src_port=500, dst_port=500),
    ]
    # Frame 2: Port 4500 IKE_AUTH (NAT-T flotation)
    f2 = [
        _make_obs(2, 1.2, "ike.initiator_spi", "aabbccddeeff0011", src_port=4500, dst_port=4500),
        _make_obs(2, 1.2, "ike.responder_spi", "1100ffeeddccbbaa", src_port=4500, dst_port=4500),
        _make_obs(2, 1.2, "ike.exchange_type", "IKE_AUTH", src_port=4500, dst_port=4500),
        _make_obs(2, 1.2, "ike.message_id", "1", src_port=4500, dst_port=4500),
    ]

    events = correlator.extract_events_from_observations(f1 + f2)
    sessions = correlator.correlate_sessions(events)

    assert len(sessions) == 1
    sess = sessions[0]
    assert sess.is_nat_detected is True
    assert sess.initiator_spi == "aabbccddeeff0011"
    assert sess.responder_spi == "1100ffeeddccbbaa"
    assert sess.lifecycle_state == LifecycleState.ACTIVE_INFERRED


def test_partial_session_handling():
    """Verify that an unanswered request produces a PARTIAL session."""
    analysis_id = uuid.uuid4()
    correlator = IKEEventCorrelator(analysis_id)

    f1 = [
        _make_obs(1, 5.0, "ike.initiator_spi", "deadbeefcafe0001"),
        _make_obs(1, 5.0, "ike.exchange_type", "IKE_SA_INIT"),
        _make_obs(1, 5.0, "ike.message_id", "0"),
    ]

    events = correlator.extract_events_from_observations(f1)
    sessions = correlator.correlate_sessions(events)

    assert len(sessions) == 1
    assert sessions[0].lifecycle_state == LifecycleState.PARTIAL
    assert sessions[0].responder_spi is None
