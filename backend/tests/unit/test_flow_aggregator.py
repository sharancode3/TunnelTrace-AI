"""Unit tests for ESP Flow Aggregator (Stage 4)."""

import uuid

from app.db.models.capture import ProtocolObservation
from app.reconstruction.flow.aggregator import ESPFlowAggregator
from app.reconstruction.models import FlowAssociationState, ReconstructedChildSA


def _make_esp_obs(
    frame_number: int,
    packet_time: float,
    field_name: str,
    normalized_value: str,
    src_ip: str = "198.51.100.1",
    dst_ip: str = "198.51.100.2",
    src_port: int | None = None,
    dst_port: int | None = None,
) -> ProtocolObservation:
    return ProtocolObservation(
        id=uuid.uuid4(),
        analysis_id=uuid.uuid4(),
        frame_number=frame_number,
        packet_time=packet_time,
        protocol="ESP",
        category="ESP_HEADER",
        field_name=field_name,
        normalized_value=normalized_value,
        source_field=field_name,
        source_tool_version="4.6.4",
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
    )


def test_directional_stream_and_bidirectional_pairing():
    """Verify that opposing directional ESP streams are paired into a single bidirectional flow."""
    analysis_id = uuid.uuid4()
    aggregator = ESPFlowAggregator(analysis_id, idle_timeout_sec=10.0)

    # Stream 1: Host A -> Host B, SPI 0x11111111 (2 packets)
    obs = [
        _make_esp_obs(1, 1.0, "esp.spi", "0x11111111", src_ip="10.1.1.1", dst_ip="10.1.1.2"),
        _make_esp_obs(1, 1.0, "esp.packet_length", "100", src_ip="10.1.1.1", dst_ip="10.1.1.2"),
        _make_esp_obs(2, 1.2, "esp.spi", "0x11111111", src_ip="10.1.1.1", dst_ip="10.1.1.2"),
        _make_esp_obs(2, 1.2, "esp.packet_length", "120", src_ip="10.1.1.1", dst_ip="10.1.1.2"),
    ]

    # Stream 2: Host B -> Host A, SPI 0x22222222 (1 packet)
    obs += [
        _make_esp_obs(3, 1.3, "esp.spi", "0x22222222", src_ip="10.1.1.2", dst_ip="10.1.1.1"),
        _make_esp_obs(3, 1.3, "esp.packet_length", "140", src_ip="10.1.1.2", dst_ip="10.1.1.1"),
    ]

    packets = aggregator.extract_packets(obs)
    assert len(packets) == 3

    streams = aggregator.build_directional_streams(packets)
    assert len(streams) == 2

    # Child SA linking the two SPIs
    child_sa = ReconstructedChildSA(
        id=uuid.uuid4(),
        analysis_id=analysis_id,
        inbound_spi="0x11111111",
        outbound_spi="0x22222222",
        src_ip="10.1.1.1",
        dst_ip="10.1.1.2",
    )

    flows = aggregator.pair_flows(streams, [child_sa])
    assert len(flows) == 1
    flow = flows[0]

    assert flow.association_state == FlowAssociationState.PAIRED_BIDIRECTIONAL
    assert flow.packet_count == 3
    assert flow.byte_count == 360
    assert flow.forward_packets == 2
    assert flow.forward_bytes == 220
    assert flow.reverse_packets == 1
    assert flow.reverse_bytes == 140
    assert flow.spi == "0x11111111"
    assert flow.reverse_spi == "0x22222222"
    assert abs(flow.duration_seconds - 0.3) < 0.001


def test_idle_timeout_splits_streams():
    """Verify that a time gap exceeding idle_timeout_sec splits the stream into a new generation."""
    analysis_id = uuid.uuid4()
    aggregator = ESPFlowAggregator(analysis_id, idle_timeout_sec=5.0)

    obs = [
        # Burst 1
        _make_esp_obs(1, 1.0, "esp.spi", "0x33333333"),
        _make_esp_obs(1, 1.0, "esp.packet_length", "100"),
        _make_esp_obs(2, 2.0, "esp.spi", "0x33333333"),
        _make_esp_obs(2, 2.0, "esp.packet_length", "100"),
        # Burst 2 after 10 seconds gap (gap > 5.0s)
        _make_esp_obs(3, 12.0, "esp.spi", "0x33333333"),
        _make_esp_obs(3, 12.0, "esp.packet_length", "100"),
    ]

    packets = aggregator.extract_packets(obs)
    streams = aggregator.build_directional_streams(packets)

    # Must be split into 2 streams
    assert len(streams) == 2
    assert streams[0].packet_count == 2
    assert streams[0].start_time == 1.0
    assert streams[0].end_time == 2.0

    assert streams[1].packet_count == 1
    assert streams[1].start_time == 12.0


def test_unpaired_unidirectional_stream():
    """Verify that one-sided ESP traffic produces an UNPAIRED_UNIDIRECTIONAL flow."""
    analysis_id = uuid.uuid4()
    aggregator = ESPFlowAggregator(analysis_id)

    obs = [
        _make_esp_obs(1, 5.0, "esp.spi", "0x99999999"),
        _make_esp_obs(1, 5.0, "esp.packet_length", "80"),
    ]

    packets = aggregator.extract_packets(obs)
    streams = aggregator.build_directional_streams(packets)
    flows = aggregator.pair_flows(streams, [])

    assert len(flows) == 1
    f = flows[0]
    assert f.association_state == FlowAssociationState.UNPAIRED_UNIDIRECTIONAL
    assert f.reverse_spi is None
    assert f.packet_count == 1
    assert f.forward_packets == 1
    assert f.reverse_packets == 0


def test_ipv6_and_natt_flow_detection():
    """Verify IPv6 address identification and NAT-T port 4500 flag preservation."""
    analysis_id = uuid.uuid4()
    aggregator = ESPFlowAggregator(analysis_id)

    obs = [
        _make_esp_obs(
            1, 10.0, "esp.spi", "0x55555555",
            src_ip="fd00:ba:1::1", dst_ip="fd00:ba:1::2",
            src_port=4500, dst_port=4500
        ),
        _make_esp_obs(
            1, 10.0, "esp.packet_length", "200",
            src_ip="fd00:ba:1::1", dst_ip="fd00:ba:1::2",
            src_port=4500, dst_port=4500
        ),
    ]

    packets = aggregator.extract_packets(obs)
    streams = aggregator.build_directional_streams(packets)
    flows = aggregator.pair_flows(streams, [])

    assert len(flows) == 1
    f = flows[0]
    assert f.ip_version == "IPv6"
    assert f.is_nat_t is True
    assert f.src_ip == "fd00:ba:1::1"
