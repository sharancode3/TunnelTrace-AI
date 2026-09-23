"""Deterministic normalization for Authentication Header (AH) packets."""

import logging
from typing import Any

from app.protocol.normalization.models import (
    EvidenceState,
    NormalizedObservation,
    ObservationCategory,
)

logger = logging.getLogger(__name__)


def parse_ah_layer(
    ah_data: dict[str, Any],
    frame_number: int,
    packet_time: float,
    packet_len: int,
    src_ip: str | None,
    dst_ip: str | None,
    tool_version: str,
) -> list[NormalizedObservation]:
    """Parse TShark JSON AH layer dictionary into normalized observations."""
    observations: list[NormalizedObservation] = []

    # 1. AH SPI
    spi_raw = ah_data.get("ah.spi")
    if spi_raw is not None:
        spi_str = str(spi_raw).lower()
        if not spi_str.startswith("0x"):
            spi_str = f"0x{spi_str}"

        observations.append(
            NormalizedObservation(
                frame_number=frame_number,
                packet_time=packet_time,
                protocol="AH",
                category=ObservationCategory.AH_HEADER,
                field_name="ah.spi",
                normalized_value=spi_str,
                raw_value=str(spi_raw),
                source_field="ah.spi",
                source_tool_version=tool_version,
                evidence_state=EvidenceState.VERIFIED,
                src_ip=src_ip,
                dst_ip=dst_ip,
                extra_attributes={"packet_len_bytes": packet_len},
            )
        )

    # 2. AH Sequence Number
    seq_raw = ah_data.get("ah.sequence")
    if seq_raw is not None:
        try:
            seq_num = int(str(seq_raw))
        except (ValueError, TypeError):
            seq_num = 0

        observations.append(
            NormalizedObservation(
                frame_number=frame_number,
                packet_time=packet_time,
                protocol="AH",
                category=ObservationCategory.AH_HEADER,
                field_name="ah.sequence",
                normalized_value=str(seq_num),
                raw_value=str(seq_raw),
                raw_numeric_id=seq_num,
                source_field="ah.sequence",
                source_tool_version=tool_version,
                evidence_state=EvidenceState.VERIFIED,
                src_ip=src_ip,
                dst_ip=dst_ip,
            )
        )

    # 3. Next Header
    next_hdr = ah_data.get("ah.next_header")
    if next_hdr is not None:
        observations.append(
            NormalizedObservation(
                frame_number=frame_number,
                packet_time=packet_time,
                protocol="AH",
                category=ObservationCategory.AH_HEADER,
                field_name="ah.next_header",
                normalized_value=str(next_hdr),
                raw_value=str(next_hdr),
                source_field="ah.next_header",
                source_tool_version=tool_version,
                evidence_state=EvidenceState.VERIFIED,
                src_ip=src_ip,
                dst_ip=dst_ip,
            )
        )

    return observations
