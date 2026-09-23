"""Deterministic normalization for IPv4, IPv6, UDP, and NAT-Traversal."""

import logging
from typing import Any

from app.protocol.normalization.models import (
    EvidenceState,
    NormalizedObservation,
    ObservationCategory,
)

logger = logging.getLogger(__name__)


def parse_ip_layer(
    layers: dict[str, Any],
    frame_number: int,
    packet_time: float,
    tool_version: str,
) -> tuple[str | None, str | None, str | None, int | None, int | None, bool, list[NormalizedObservation]]:
    """Parse outer IP and UDP/NAT-T layers from TShark layers dictionary.

    Returns:
        tuple of (src_ip, dst_ip, ip_version, src_port, dst_port, is_natt, observations)
    """
    observations: list[NormalizedObservation] = []
    src_ip: str | None = None
    dst_ip: str | None = None
    ip_version: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    is_natt = False

    # 1. IPv4 Check
    if "ip" in layers:
        ip_data = layers["ip"]
        ip_version = "IPv4"
        src_ip = ip_data.get("ip.src") or ip_data.get("ip.addr")
        dst_ip = ip_data.get("ip.dst")

        observations.append(
            NormalizedObservation(
                frame_number=frame_number,
                packet_time=packet_time,
                protocol="IPv4",
                category=ObservationCategory.IPV4,
                field_name="ip.version",
                normalized_value="IPv4",
                source_field="ip.version",
                source_tool_version=tool_version,
                src_ip=src_ip,
                dst_ip=dst_ip,
            )
        )

    # 2. IPv6 Check
    elif "ipv6" in layers:
        ipv6_data = layers["ipv6"]
        ip_version = "IPv6"
        src_ip = ipv6_data.get("ipv6.src") or ipv6_data.get("ipv6.addr")
        dst_ip = ipv6_data.get("ipv6.dst")

        observations.append(
            NormalizedObservation(
                frame_number=frame_number,
                packet_time=packet_time,
                protocol="IPv6",
                category=ObservationCategory.IPV6,
                field_name="ipv6.version",
                normalized_value="IPv6",
                source_field="ipv6.version",
                source_tool_version=tool_version,
                src_ip=src_ip,
                dst_ip=dst_ip,
            )
        )

    # 3. UDP & NAT-T Check
    if "udp" in layers:
        udp_data = layers["udp"]
        s_port_raw = udp_data.get("udp.srcport")
        d_port_raw = udp_data.get("udp.dstport")
        try:
            src_port = int(str(s_port_raw)) if s_port_raw else None
            dst_port = int(str(d_port_raw)) if d_port_raw else None
        except (ValueError, TypeError):
            pass

        # Check NAT-Traversal port 4500 or udpencap
        proto_str = str(layers.get("frame", {}).get("frame.protocols", ""))
        if (
            src_port == 4500
            or dst_port == 4500
            or "udpencap" in layers
            or "udpencap" in proto_str
        ):
            is_natt = True
            observations.append(
                NormalizedObservation(
                    frame_number=frame_number,
                    packet_time=packet_time,
                    protocol="NAT-T",
                    category=ObservationCategory.NAT_T,
                    field_name="natt.detected",
                    normalized_value="UDP_PORT_4500_ENCAPSULATION",
                    raw_value=f"src={src_port},dst={dst_port}",
                    source_field="udp.port / udpencap",
                    source_tool_version=tool_version,
                    evidence_state=EvidenceState.VERIFIED,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                )
            )

    return src_ip, dst_ip, ip_version, src_port, dst_port, is_natt, observations
