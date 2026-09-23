"""Deterministic normalization for Encapsulating Security Payload (ESP) packets."""

import logging
from typing import Any

from app.protocol.normalization.models import (
    EvidenceState,
    NormalizedObservation,
    ObservationCategory,
)

logger = logging.getLogger(__name__)


def parse_esp_layer(
    esp_data: dict[str, Any],
    frame_number: int,
    packet_time: float,
    packet_len: int,
    src_ip: str | None,
    dst_ip: str | None,
    is_natt: bool,
    tool_version: str,
) -> list[NormalizedObservation]:
    """Parse TShark JSON ESP layer dictionary into normalized observations.

    Strict Invariants:
    - Never decodes or inspects ciphertext.
    - Never infers encryption algorithm or key size from ESP headers alone.
    - Never concludes replay protection is enabled solely from packet sequence numbers.
    - Extracts observable wire facts: SPI, sequence number, endpoints, and encapsulation mode.
    """
    observations: list[NormalizedObservation] = []

    # 1. ESP SPI
    spi_raw = esp_data.get("esp.spi")
    if spi_raw is not None:
        spi_str = str(spi_raw).lower()
        if not spi_str.startswith("0x"):
            spi_str = f"0x{spi_str}"

        observations.append(
            NormalizedObservation(
                frame_number=frame_number,
                packet_time=packet_time,
                protocol="ESP",
                category=ObservationCategory.ESP_HEADER,
                field_name="esp.spi",
                normalized_value=spi_str,
                raw_value=str(spi_raw),
                source_field="esp.spi",
                source_tool_version=tool_version,
                evidence_state=EvidenceState.VERIFIED,
                src_ip=src_ip,
                dst_ip=dst_ip,
                extra_attributes={"packet_len_bytes": packet_len},
            )
        )

    # 2. ESP Sequence Number
    seq_raw = esp_data.get("esp.sequence")
    if seq_raw is not None:
        try:
            seq_num = int(str(seq_raw))
        except (ValueError, TypeError):
            seq_num = 0

        observations.append(
            NormalizedObservation(
                frame_number=frame_number,
                packet_time=packet_time,
                protocol="ESP",
                category=ObservationCategory.ESP_HEADER,
                field_name="esp.sequence",
                normalized_value=str(seq_num),
                raw_value=str(seq_raw),
                raw_numeric_id=seq_num,
                source_field="esp.sequence",
                source_tool_version=tool_version,
                evidence_state=EvidenceState.VERIFIED,
                src_ip=src_ip,
                dst_ip=dst_ip,
            )
        )

    # 3. Encapsulation Type
    encap_type = "UDP_ENCAPSULATED_ESP" if is_natt else "NATIVE_ESP"
    observations.append(
        NormalizedObservation(
            frame_number=frame_number,
            packet_time=packet_time,
            protocol="ESP",
            category=ObservationCategory.ESP_HEADER,
            field_name="esp.encapsulation",
            normalized_value=encap_type,
            raw_value="17/4500" if is_natt else "50",
            source_field="ip.proto / frame.protocols",
            source_tool_version=tool_version,
            evidence_state=EvidenceState.VERIFIED,
            src_ip=src_ip,
            dst_ip=dst_ip,
        )
    )

    return observations
