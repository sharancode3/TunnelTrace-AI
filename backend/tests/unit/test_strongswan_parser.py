"""Unit tests for the safe, bounded strongSwan swanctl.conf parser."""

import pytest
from app.inventory.strongswan_parser import (
    ConfigurationParseError,
    SafeSwanctlParser,
    parse_proposal_string,
    parse_proposals_list,
)

SAMPLE_SWANCTL_CONF = """
# Sample strongSwan configuration
connections {
    gw-to-gw {
        version = 2
        local_addrs = 192.0.2.1
        remote_addrs = 198.51.100.1
        proposals = aes256gcm16-prfsha256-ecp256,aes128gcm16-prfsha256-ecp256
        encap = yes
        rekey_time = 14400s

        local {
            auth = psk
            id = gw-a.example.com
        }

        remote {
            auth = psk
            id = gw-b.example.com
        }

        children {
            net-to-net {
                mode = tunnel
                local_ts = 10.1.0.0/24
                remote_ts = 10.2.0.0/24
                esp_proposals = aes256gcm16-ecp256,aes128gcm16
                start_action = start
                rekey_time = 3600s
                replay_window = 128
            }
        }
    }
}

secrets {
    ike-psk-1 {
        id = gw-a.example.com
        secret = "ultra_confidential_shared_key_12345"
    }
}
"""


def test_parse_proposal_string():
    p1 = parse_proposal_string("aes256gcm16-prfsha256-ecp256")
    assert p1.encryption == "aes256gcm16"
    assert p1.key_length == 256
    assert p1.prf == "prfsha256"
    assert p1.dh_group == "ecp256"

    p2 = parse_proposal_string("3des-sha1-modp1024")
    assert p2.encryption == "3des"
    assert p2.integrity == "sha1"
    assert p2.dh_group == "modp1024"


def test_parse_valid_configuration():
    result = SafeSwanctlParser.parse(SAMPLE_SWANCTL_CONF)
    ir = result["normalized_ir"]
    assert ir["format"] == "SWANCTL"
    assert "gw-to-gw" in ir["connections"]

    conn = ir["connections"]["gw-to-gw"]
    assert conn["version"] == 2
    assert conn["local_addrs"] == "192.0.2.1"
    assert conn["remote_addrs"] == "198.51.100.1"
    assert conn["encap"] is True
    assert conn["local"]["id"] == "gw-a.example.com"
    assert conn["remote"]["id"] == "gw-b.example.com"

    child = conn["children"]["net-to-net"]
    assert child["mode"] == "tunnel"
    assert child["local_ts"] == "10.1.0.0/24"
    assert child["remote_ts"] == "10.2.0.0/24"
    assert child["replay_window"] == 128
    assert len(child["esp_proposals"]) == 2


def test_secrets_strictly_redacted():
    result = SafeSwanctlParser.parse(SAMPLE_SWANCTL_CONF)
    secrets = result["normalized_ir"]["secrets"]
    assert "ike-psk-1" in secrets
    psk_entry = secrets["ike-psk-1"]
    assert psk_entry["secret"] == "[REDACTED_SECRET]"
    assert psk_entry["is_redacted"] is True
    assert "ultra_confidential_shared_key_12345" not in str(result)


def test_canonical_digest_determinism():
    result1 = SafeSwanctlParser.parse(SAMPLE_SWANCTL_CONF)
    # Configuration with different formatting/comments but same semantics
    equivalent_conf = """
    # Different comment
    connections {
        gw-to-gw {
            remote_addrs = 198.51.100.1
            local_addrs = 192.0.2.1
            version = 2
            proposals = aes256gcm16-prfsha256-ecp256,aes128gcm16-prfsha256-ecp256
            rekey_time = 14400s
            encap = yes

            children {
                net-to-net {
                    mode = tunnel
                    local_ts = 10.1.0.0/24
                    remote_ts = 10.2.0.0/24
                    esp_proposals = aes256gcm16-ecp256,aes128gcm16
                    start_action = start
                    rekey_time = 3600s
                    replay_window = 128
                }
            }

            local {
                auth = psk
                id = gw-a.example.com
            }

            remote {
                auth = psk
                id = gw-b.example.com
            }
        }
    }
    """
    result2 = SafeSwanctlParser.parse(equivalent_conf)
    assert result1["canonical_digest"] == result2["canonical_digest"]

    # Modified configuration must produce distinct digest
    modified_conf = SAMPLE_SWANCTL_CONF.replace("aes256gcm16", "3des")
    result3 = SafeSwanctlParser.parse(modified_conf)
    assert result1["canonical_digest"] != result3["canonical_digest"]


def test_bounds_empty_text():
    with pytest.raises(ConfigurationParseError, match="empty"):
        SafeSwanctlParser.parse("")


def test_bounds_oversized_content():
    oversized = "connections { a { " + ("x" * 1_000_001) + " } }"
    with pytest.raises(ConfigurationParseError, match="exceeds maximum size"):
        SafeSwanctlParser.parse(oversized)


def test_bounds_excessive_nesting():
    nested = "a { b { c { d { e { f { g { h { i { } } } } } } } } }"
    with pytest.raises(ConfigurationParseError, match="Nesting depth"):
        SafeSwanctlParser.parse(nested)


def test_malformed_unclosed_block():
    unclosed = "connections { gw-a { local { auth = psk } }"
    with pytest.raises(ConfigurationParseError, match="Unclosed blocks"):
        SafeSwanctlParser.parse(unclosed)


def test_unsupported_directives_recorded():
    custom_conf = """
    connections {
        gw-test {
            custom_unsupported_knob = aggressive_optimization
            local {
                id = test.gw
            }
        }
    }
    """
    result = SafeSwanctlParser.parse(custom_conf)
    unsupported = result["unsupported_directives"]
    assert len(unsupported) == 1
    assert unsupported[0]["path"] == "connections.gw-test.custom_unsupported_knob"
    assert unsupported[0]["value"] == "aggressive_optimization"
