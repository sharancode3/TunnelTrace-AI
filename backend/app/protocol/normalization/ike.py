"""Deterministic normalization for IKEv1 and IKEv2 packets and cryptographic transforms."""

import logging
from typing import Any

from app.protocol.normalization.models import (
    CryptoObservationDTO,
    NormalizedObservation,
    ObservationCategory,
)

logger = logging.getLogger(__name__)

# RFC 7296 / IANA IKEv2 Exchange Types
IKEV2_EXCHANGE_TYPES: dict[int, str] = {
    34: "IKE_SA_INIT",
    35: "IKE_AUTH",
    36: "CREATE_CHILD_SA",
    37: "INFORMATIONAL",
    38: "IKE_SESSION_RESUME",
}

# RFC 2409 / IANA IKEv1 Exchange Types
IKEV1_EXCHANGE_TYPES: dict[int, str] = {
    2: "IDENTITY_PROTECTION",
    4: "AGGRESSIVE",
    5: "INFORMATIONAL",
    32: "QUICK_MODE",
    33: "NEW_GROUP_MODE",
}

# RFC 7296 Transform Types
TRANSFORM_TYPES: dict[int, str] = {
    1: "ENCR",
    2: "PRF",
    3: "INTEG",
    4: "DH",
    5: "ESN",
}

# RFC 7296 Encryption Algorithm Transform IDs
ENCR_TRANSFORMS: dict[int, str] = {
    1: "DES_IV64",
    2: "DES",
    3: "3DES",
    4: "RC5",
    5: "IDEA",
    6: "CAST",
    7: "BLOWFISH",
    8: "3IDEA",
    9: "DES_IV32",
    11: "NULL",
    12: "AES-CBC",
    13: "AES-CTR",
    14: "AES-CCM-8",
    15: "AES-CCM-12",
    16: "AES-CCM-16",
    18: "AES-GCM-8",
    19: "AES-GCM-12",
    20: "AES-GCM-16",
    28: "CHACHA20_POLY1305",
}

# RFC 7296 Pseudorandom Function Transform IDs
PRF_TRANSFORMS: dict[int, str] = {
    1: "PRF_HMAC_MD5",
    2: "PRF_HMAC_SHA1",
    3: "PRF_HMAC_TIGER",
    4: "PRF_HMAC_SHA2_256",
    5: "PRF_HMAC_SHA2_256",
    6: "PRF_HMAC_SHA2_384",
    7: "PRF_HMAC_SHA2_512",
    8: "PRF_AES128_XCBC",
}

# RFC 7296 Integrity Algorithm Transform IDs
INTEG_TRANSFORMS: dict[int, str] = {
    1: "AUTH_HMAC_MD5_96",
    2: "AUTH_HMAC_SHA1_96",
    3: "AUTH_DES_MAC",
    4: "AUTH_KPDK_MD5",
    5: "AUTH_AES_XCBC_96",
    12: "AUTH_HMAC_SHA2_256_128",
    13: "AUTH_HMAC_SHA2_384_192",
    14: "AUTH_HMAC_SHA2_512_256",
}

# RFC 7296 / RFC 5903 Diffie-Hellman Group Transform IDs
DH_TRANSFORMS: dict[int, str] = {
    1: "MODP-768 (DH1)",
    2: "MODP-1024 (DH2)",
    5: "MODP-1536 (DH5)",
    14: "MODP-2048 (DH14)",
    15: "MODP-3072 (DH15)",
    16: "MODP-4096 (DH16)",
    17: "MODP-6144 (DH17)",
    18: "MODP-8192 (DH18)",
    19: "ECP-256 (DH19)",
    20: "ECP-384 (DH20)",
    21: "ECP-521 (DH21)",
    31: "Curve25519 (DH31)",
    32: "Curve448 (DH32)",
}

# RFC 7296 Notify Messages
NOTIFY_TYPES: dict[int, str] = {
    16384: "INITIAL_CONTACT",
    16388: "NAT_DETECTION_SOURCE_IP",
    16389: "NAT_DETECTION_DESTINATION_IP",
    16393: "USE_TRANSPORT_MODE",
    16404: "REDIRECT_SUPPORTED",
    16418: "COOKIE2",
    16430: "IKEV2_MESSAGE_ID_SYNC",
    16431: "SIGNATURE_HASH_ALGORITHMS",
}


def normalize_transform(
    tf_type_id: int, tf_id: int, key_length: int | None = None
) -> tuple[str, str]:
    """Normalize a transform type ID and transform numeric ID into canonical names.

    Returns:
        tuple of (type_name, transform_name)
    """
    type_name = TRANSFORM_TYPES.get(tf_type_id, f"UNKNOWN_TYPE_{tf_type_id}")

    if type_name == "ENCR":
        name = ENCR_TRANSFORMS.get(tf_id, f"UNKNOWN_ENCR_{tf_id}")
        if key_length:
            name = f"{name}-{key_length}"
    elif type_name == "PRF":
        name = PRF_TRANSFORMS.get(tf_id, f"UNKNOWN_PRF_{tf_id}")
    elif type_name == "INTEG":
        name = INTEG_TRANSFORMS.get(tf_id, f"UNKNOWN_INTEG_{tf_id}")
    elif type_name == "DH":
        name = DH_TRANSFORMS.get(tf_id, f"UNKNOWN_DH_{tf_id}")
    else:
        name = f"UNKNOWN_TRANSFORM_{tf_id}"

    return type_name, name


def parse_ike_layer(
    isakmp_data: dict[str, Any],
    frame_number: int,
    packet_time: float,
    src_ip: str | None,
    dst_ip: str | None,
    src_port: int | None,
    dst_port: int | None,
    tool_version: str,
) -> tuple[list[NormalizedObservation], list[CryptoObservationDTO]]:
    """Parse TShark JSON isakmp/IKE layer dictionary into normalized observations.

    Extracts:
    - IKE Version (IKEv1 / IKEv2)
    - Initiator SPI & Responder SPI
    - Exchange Type (normalized name and numeric value)
    - Message ID
    - Direction (Initiator request vs Responder response)
    - SA Proposals & Transforms (ENCR, PRF, INTEG, DH) with key lengths
    - Key Exchange payload (DH group)
    - Notify Payloads (e.g. USE_TRANSPORT_MODE, NAT_DETECTION_*)
    """
    observations: list[NormalizedObservation] = []
    crypto_observations: list[CryptoObservationDTO] = []

    # 1. Version
    ver_tree = isakmp_data.get("isakmp.version_tree", {})
    mjver_raw = ver_tree.get("isakmp.mjver") or isakmp_data.get("isakmp.version")
    ike_version = "IKEv2"
    if mjver_raw is not None:
        try:
            ver_int = int(str(mjver_raw), 16) if str(mjver_raw).startswith("0x") else int(str(mjver_raw))
            if ver_int == 1:
                ike_version = "IKEv1"
            elif ver_int == 2:
                ike_version = "IKEv2"
        except (ValueError, TypeError):
            pass

    observations.append(
        NormalizedObservation(
            frame_number=frame_number,
            packet_time=packet_time,
            protocol=ike_version,
            category=ObservationCategory.IKE_HEADER,
            field_name="ike.version",
            normalized_value=ike_version,
            raw_value=str(mjver_raw),
            source_field="isakmp.version_tree.isakmp.mjver",
            source_tool_version=tool_version,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
        )
    )

    # 2. SPIs
    ispi = isakmp_data.get("isakmp.ispi")
    if ispi:
        ispi_clean = str(ispi).replace(":", "").lower()
        observations.append(
            NormalizedObservation(
                frame_number=frame_number,
                packet_time=packet_time,
                protocol=ike_version,
                category=ObservationCategory.IKE_HEADER,
                field_name="ike.initiator_spi",
                normalized_value=ispi_clean,
                raw_value=str(ispi),
                source_field="isakmp.ispi",
                source_tool_version=tool_version,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
            )
        )

    rspi = isakmp_data.get("isakmp.rspi")
    if rspi:
        rspi_clean = str(rspi).replace(":", "").lower()
        observations.append(
            NormalizedObservation(
                frame_number=frame_number,
                packet_time=packet_time,
                protocol=ike_version,
                category=ObservationCategory.IKE_HEADER,
                field_name="ike.responder_spi",
                normalized_value=rspi_clean,
                raw_value=str(rspi),
                source_field="isakmp.rspi",
                source_tool_version=tool_version,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
            )
        )

    # 3. Exchange Type
    exch_raw = isakmp_data.get("isakmp.exchangetype")
    exch_name = "UNKNOWN_EXCHANGE"
    exch_id: int | None = None
    if exch_raw is not None:
        try:
            exch_id = int(str(exch_raw), 16) if str(exch_raw).startswith("0x") else int(str(exch_raw))
            if ike_version == "IKEv2":
                exch_name = IKEV2_EXCHANGE_TYPES.get(exch_id, f"UNKNOWN_IKEV2_EXCHANGE_{exch_id}")
            else:
                exch_name = IKEV1_EXCHANGE_TYPES.get(exch_id, f"UNKNOWN_IKEV1_EXCHANGE_{exch_id}")
        except (ValueError, TypeError):
            pass

        observations.append(
            NormalizedObservation(
                frame_number=frame_number,
                packet_time=packet_time,
                protocol=ike_version,
                category=ObservationCategory.IKE_EXCHANGE,
                field_name="ike.exchange_type",
                normalized_value=exch_name,
                raw_value=str(exch_raw),
                raw_numeric_id=exch_id,
                source_field="isakmp.exchangetype",
                source_tool_version=tool_version,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
            )
        )

    # 4. Message ID
    msg_id_raw = isakmp_data.get("isakmp.messageid")
    if msg_id_raw is not None:
        try:
            msg_id = int(str(msg_id_raw), 16) if str(msg_id_raw).startswith("0x") else int(str(msg_id_raw))
        except (ValueError, TypeError):
            msg_id = 0
        observations.append(
            NormalizedObservation(
                frame_number=frame_number,
                packet_time=packet_time,
                protocol=ike_version,
                category=ObservationCategory.IKE_HEADER,
                field_name="ike.message_id",
                normalized_value=str(msg_id),
                raw_value=str(msg_id_raw),
                raw_numeric_id=msg_id,
                source_field="isakmp.messageid",
                source_tool_version=tool_version,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
            )
        )

    # 5. Flags (Initiator / Response direction)
    flags_tree = isakmp_data.get("isakmp.flags_tree", {})
    flag_r = flags_tree.get("isakmp.flag_r")
    flag_i = flags_tree.get("isakmp.flag_i")
    role = "INITIATOR_REQUEST"
    if flag_r == "1" or flag_r is True:
        role = "RESPONDER_RESPONSE"
    elif flag_i == "1" or flag_i is True:
        role = "INITIATOR_REQUEST"

    observations.append(
        NormalizedObservation(
            frame_number=frame_number,
            packet_time=packet_time,
            protocol=ike_version,
            category=ObservationCategory.IKE_HEADER,
            field_name="ike.role",
            normalized_value=role,
            raw_value=str(flags_tree),
            source_field="isakmp.flags_tree",
            source_tool_version=tool_version,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
        )
    )

    # Recursive traversal to extract SA Proposals, Transforms, Notifies, and Key Exchange payloads
    _extract_ike_payloads(
        isakmp_data,
        frame_number,
        packet_time,
        ike_version,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        tool_version,
        observations,
        crypto_observations,
    )

    return observations, crypto_observations


def _extract_ike_payloads(
    data: Any,
    frame_number: int,
    packet_time: float,
    ike_version: str,
    src_ip: str | None,
    dst_ip: str | None,
    src_port: int | None,
    dst_port: int | None,
    tool_version: str,
    observations: list[NormalizedObservation],
    crypto_observations: list[CryptoObservationDTO],
) -> None:
    """Recursively search for IKE payloads in the TShark dictionary tree."""
    if isinstance(data, dict):
        # Check for Key Exchange DH Group
        if "isakmp.key_exchange.dh_group" in data:
            dh_val = data["isakmp.key_exchange.dh_group"]
            try:
                dh_int = int(str(dh_val))
                dh_name = DH_TRANSFORMS.get(dh_int, f"UNKNOWN_DH_{dh_int}")
                observations.append(
                    NormalizedObservation(
                        frame_number=frame_number,
                        packet_time=packet_time,
                        protocol=ike_version,
                        category=ObservationCategory.IKE_KEY_EXCHANGE,
                        field_name="ike.ke.dh_group",
                        normalized_value=dh_name,
                        raw_value=str(dh_val),
                        raw_numeric_id=dh_int,
                        source_field="isakmp.key_exchange.dh_group",
                        source_tool_version=tool_version,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        src_port=src_port,
                        dst_port=dst_port,
                    )
                )
            except (ValueError, TypeError):
                pass

        # Check for Notify message type
        if "isakmp.notify.msgtype" in data:
            msg_type_raw = data["isakmp.notify.msgtype"]
            try:
                msg_type_int = int(str(msg_type_raw))
                msg_name = NOTIFY_TYPES.get(msg_type_int, f"NOTIFY_{msg_type_int}")
                observations.append(
                    NormalizedObservation(
                        frame_number=frame_number,
                        packet_time=packet_time,
                        protocol=ike_version,
                        category=ObservationCategory.IKE_NOTIFY,
                        field_name="ike.notify.type",
                        normalized_value=msg_name,
                        raw_value=str(msg_type_raw),
                        raw_numeric_id=msg_type_int,
                        source_field="isakmp.notify.msgtype",
                        source_tool_version=tool_version,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        src_port=src_port,
                        dst_port=dst_port,
                    )
                )
            except (ValueError, TypeError):
                pass

        # Check for Transform payload
        if "isakmp.tf.type" in data:
            try:
                tf_type_int = int(str(data["isakmp.tf.type"]))
                tf_id: int | None = None
                key_len: int | None = None

                # Check ENCR
                if "isakmp.tf.id.encr" in data:
                    tf_id = int(str(data["isakmp.tf.id.encr"]))
                    # Check key length in ike2.attr
                    attr = data.get("isakmp.ike2.attr", {})
                    if isinstance(attr, dict) and "isakmp.ike2.attr.key_length" in attr:
                        try:
                            key_len = int(str(attr["isakmp.ike2.attr.key_length"]))
                        except (ValueError, TypeError):
                            pass
                elif "isakmp.tf.id.prf" in data:
                    tf_id = int(str(data["isakmp.tf.id.prf"]))
                elif "isakmp.tf.id.integ" in data:
                    tf_id = int(str(data["isakmp.tf.id.integ"]))
                elif "isakmp.tf.id.dh" in data:
                    tf_id = int(str(data["isakmp.tf.id.dh"]))

                if tf_id is not None:
                    tf_type_name, tf_name = normalize_transform(tf_type_int, tf_id, key_len)
                    observations.append(
                        NormalizedObservation(
                            frame_number=frame_number,
                            packet_time=packet_time,
                            protocol=ike_version,
                            category=ObservationCategory.IKE_TRANSFORM,
                            field_name=f"ike.transform.{tf_type_name.lower()}",
                            normalized_value=tf_name,
                            raw_value=str(tf_id),
                            raw_numeric_id=tf_id,
                            source_field=f"isakmp.tf.id.{tf_type_name.lower()}",
                            source_tool_version=tool_version,
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            src_port=src_port,
                            dst_port=dst_port,
                            extra_attributes={"key_length_bits": key_len} if key_len else {},
                        )
                    )
                    crypto_observations.append(
                        CryptoObservationDTO(
                            frame_number=frame_number,
                            transform_type=tf_type_name,
                            transform_id=tf_id,
                            transform_name=tf_name,
                            key_length_bits=key_len,
                            evidence_state="VERIFIED",
                        )
                    )
            except (ValueError, TypeError) as exc:
                logger.debug(f"Failed to parse transform in frame {frame_number}: {exc}")

        # Recurse children
        for v in data.values():
            _extract_ike_payloads(
                v,
                frame_number,
                packet_time,
                ike_version,
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                tool_version,
                observations,
                crypto_observations,
            )

    elif isinstance(data, list):
        for item in data:
            _extract_ike_payloads(
                item,
                frame_number,
                packet_time,
                ike_version,
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                tool_version,
                observations,
                crypto_observations,
            )
