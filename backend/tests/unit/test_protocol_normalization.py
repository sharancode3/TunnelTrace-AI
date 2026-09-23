"""Unit tests for protocol normalization (IKEv1, IKEv2, ESP, AH, NAT-T, IPv4, IPv6)."""

from app.protocol.normalization.ah import parse_ah_layer
from app.protocol.normalization.esp import parse_esp_layer
from app.protocol.normalization.ike import normalize_transform, parse_ike_layer
from app.protocol.normalization.ip import parse_ip_layer
from app.protocol.normalization.models import EvidenceState


def test_normalize_transform_encr():
    """Verify encryption transform mapping and key length appending."""
    tf_type, tf_name = normalize_transform(1, 20, 256)
    assert tf_type == "ENCR"
    assert tf_name == "AES-GCM-16-256"

    tf_type, tf_name = normalize_transform(1, 12, 128)
    assert tf_type == "ENCR"
    assert tf_name == "AES-CBC-128"


def test_normalize_transform_dh():
    """Verify Diffie-Hellman group mapping."""
    tf_type, tf_name = normalize_transform(4, 19)
    assert tf_type == "DH"
    assert tf_name == "ECP-256 (DH19)"

    tf_type, tf_name = normalize_transform(4, 14)
    assert tf_type == "DH"
    assert tf_name == "MODP-2048 (DH14)"


def test_normalize_unknown_transform():
    """Verify unknown transform IDs are preserved safely with UNKNOWN label."""
    tf_type, tf_name = normalize_transform(1, 999)
    assert tf_type == "ENCR"
    assert tf_name == "UNKNOWN_ENCR_999"

    tf_type, tf_name = normalize_transform(99, 123)
    assert tf_type == "UNKNOWN_TYPE_99"
    assert tf_name == "UNKNOWN_TRANSFORM_123"


def test_parse_ike_layer_synthetic():
    """Verify IKE layer dictionary parsing produces verified observations."""
    synthetic_ike = {
        "isakmp.ispi": "3b:9b:84:84:4f:a6:b4:37",
        "isakmp.rspi": "f7:62:44:83:b4:2b:91:ad",
        "isakmp.version_tree": {"isakmp.mjver": "0x02", "isakmp.mnver": "0x00"},
        "isakmp.exchangetype": "34",
        "isakmp.messageid": "0x00000000",
        "isakmp.flags_tree": {"isakmp.flag_i": "0", "isakmp.flag_r": "1"},
        "isakmp.typepayload_tree": {
            "isakmp.typepayload": "3",
            "isakmp.typepayload_tree": {
                "isakmp.tf.type": "1",
                "isakmp.tf.id.encr": "20",
                "isakmp.ike2.attr": {"isakmp.ike2.attr.key_length": "256"},
            },
        },
    }

    obs, crypto_obs = parse_ike_layer(
        synthetic_ike,
        frame_number=1,
        packet_time=1700000000.0,
        src_ip="198.51.100.2",
        dst_ip="198.51.100.1",
        src_port=500,
        dst_port=500,
        tool_version="4.6.4",
    )

    field_map = {o.field_name: o for o in obs}
    assert "ike.version" in field_map
    assert field_map["ike.version"].normalized_value == "IKEv2"
    assert field_map["ike.initiator_spi"].normalized_value == "3b9b84844fa6b437"
    assert field_map["ike.responder_spi"].normalized_value == "f7624483b42b91ad"
    assert field_map["ike.exchange_type"].normalized_value == "IKE_SA_INIT"
    assert field_map["ike.role"].normalized_value == "RESPONDER_RESPONSE"

    assert len(crypto_obs) == 1
    assert crypto_obs[0].transform_type == "ENCR"
    assert crypto_obs[0].transform_name == "AES-GCM-16-256"
    assert crypto_obs[0].key_length_bits == 256


def test_parse_esp_layer_synthetic():
    """Verify ESP layer parsing extracts SPI, sequence, encapsulation without decryption."""
    synthetic_esp = {
        "esp.spi": "0xc4f6f980",
        "esp.sequence": "42",
    }

    obs = parse_esp_layer(
        synthetic_esp,
        frame_number=5,
        packet_time=1700000001.0,
        packet_len=154,
        src_ip="198.51.100.1",
        dst_ip="198.51.100.2",
        is_natt=False,
        tool_version="4.6.4",
    )

    field_map = {o.field_name: o for o in obs}
    assert field_map["esp.spi"].normalized_value == "0xc4f6f980"
    assert field_map["esp.sequence"].normalized_value == "42"
    assert field_map["esp.encapsulation"].normalized_value == "NATIVE_ESP"
    assert field_map["esp.spi"].evidence_state == EvidenceState.VERIFIED


def test_parse_esp_natt_layer():
    """Verify UDP-encapsulated ESP is marked UDP_ENCAPSULATED_ESP."""
    synthetic_esp = {"esp.spi": "0xce7e5151", "esp.sequence": "1"}
    obs = parse_esp_layer(
        synthetic_esp,
        frame_number=6,
        packet_time=1700000002.0,
        packet_len=162,
        src_ip="198.51.100.1",
        dst_ip="198.51.100.2",
        is_natt=True,
        tool_version="4.6.4",
    )
    field_map = {o.field_name: o for o in obs}
    assert field_map["esp.encapsulation"].normalized_value == "UDP_ENCAPSULATED_ESP"


def test_parse_ah_layer_synthetic():
    """Verify AH layer parsing extracts SPI and sequence number."""
    synthetic_ah = {
        "ah.spi": "0x12345678",
        "ah.sequence": "100",
        "ah.next_header": "6",
    }
    obs = parse_ah_layer(
        synthetic_ah,
        frame_number=10,
        packet_time=1700000005.0,
        packet_len=80,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        tool_version="4.6.4",
    )
    field_map = {o.field_name: o for o in obs}
    assert field_map["ah.spi"].normalized_value == "0x12345678"
    assert field_map["ah.sequence"].normalized_value == "100"
    assert field_map["ah.next_header"].normalized_value == "6"


def test_parse_ip_layer_ipv4_and_natt():
    """Verify IP layer parsing detects IPv4 and NAT-T on UDP 4500."""
    layers = {
        "frame": {"frame.protocols": "eth:ethertype:ip:udp:udpencap:esp"},
        "ip": {"ip.src": "198.51.100.1", "ip.dst": "198.51.100.2"},
        "udp": {"udp.srcport": "4500", "udp.dstport": "4500"},
        "udpencap": {},
    }
    src_ip, dst_ip, ip_ver, src_port, dst_port, is_natt, obs = parse_ip_layer(
        layers, frame_number=1, packet_time=100.0, tool_version="4.6.4"
    )
    assert src_ip == "198.51.100.1"
    assert dst_ip == "198.51.100.2"
    assert ip_ver == "IPv4"
    assert src_port == 4500
    assert dst_port == 4500
    assert is_natt is True
    assert any(o.protocol == "NAT-T" for o in obs)


def test_parse_ip_layer_ipv6():
    """Verify IP layer parsing detects IPv6."""
    layers = {
        "frame": {"frame.protocols": "eth:ethertype:ipv6:esp"},
        "ipv6": {"ipv6.src": "fd00:ba::1", "ipv6.dst": "fd00:ba::2"},
    }
    src_ip, dst_ip, ip_ver, src_port, dst_port, is_natt, obs = parse_ip_layer(
        layers, frame_number=1, packet_time=100.0, tool_version="4.6.4"
    )
    assert src_ip == "fd00:ba::1"
    assert dst_ip == "fd00:ba::2"
    assert ip_ver == "IPv6"
    assert is_natt is False
