"""Unit tests for IKE-scan stdout parsing with realistic canned fixtures."""

from app.protocol.ike_scan.parser import parse_ike_scan_output

FIXTURE_IKEV1_HANDSHAKE = """Starting ike-scan 1.9 with 1 hosts (http://www.nta-monitor.com/ike-scan/)
192.168.1.50	Main Mode Handshake returned
	HDR=(CKY-R=8b9c0d1e2f3a4b5c)
	SA=(Enc=3DES Hash=SHA1 Auth=PSK Group=2:modp1024 LifeType=Seconds LifeDuration=28800)
	VID=1234567890abcdef (Cisco Unity)
	VID=090026895d000000 (XAUTH)

Ending ike-scan 1.9: 1 hosts scanned in 0.048 seconds (20.83 hosts/sec). 1 returned handshake; 0 returned notify
"""

FIXTURE_IKEV1_NOTIFY_NO_PROPOSAL = """Starting ike-scan 1.9 with 1 hosts (http://www.nta-monitor.com/ike-scan/)
192.168.1.50	Notify message 14 (NO-PROPOSAL-CHOSEN)
	HDR=(CKY-R=0000000000000000)

Ending ike-scan 1.9: 1 hosts scanned in 0.032 seconds (31.25 hosts/sec). 0 returned handshake; 1 returned notify
"""

FIXTURE_NO_RESPONSE = """Starting ike-scan 1.9 with 1 hosts (http://www.nta-monitor.com/ike-scan/)

Ending ike-scan 1.9: 1 hosts scanned in 2.005 seconds (0.50 hosts/sec). 0 returned handshake; 0 returned notify
"""

FIXTURE_IKEV2_EXPERIMENTAL_HANDSHAKE = """Starting ike-scan 1.9 with 1 hosts (http://www.nta-monitor.com/ike-scan/)
192.168.1.50	IKEv2 SA_INIT Handshake returned
	HDR=(InitiatorSPI=1122334455667788 ResponderSPI=99aabbccddeeff00)
	SA=(Enc=AES-CBC-128 Hash=SHA1 Auth=PSK Group=2:modp1024)
	VID=4048b7d56ebce0e0 (strongSwan 5.9.8)

Ending ike-scan 1.9: 1 hosts scanned in 0.041 seconds (24.39 hosts/sec). 1 returned handshake; 0 returned notify
"""


def test_parse_ikev1_handshake():
    """Verify parsing of valid IKEv1 Main Mode handshake response."""
    res = parse_ike_scan_output(FIXTURE_IKEV1_HANDSHAKE, target_ip="192.168.1.50", target_port=500)
    assert res.response_category == "RESPONDED_HANDSHAKE"
    assert res.ike_version == "IKEv1"
    assert res.handshake_type == "Main Mode Handshake returned"
    assert not res.is_experimental
    assert res.rtt_ms == 48.0

    # Transforms
    assert len(res.transforms_returned) == 1
    tf = res.transforms_returned[0]
    assert tf.get("encr") == "3DES"
    assert tf.get("hash") == "SHA1"
    assert tf.get("auth") == "PSK"
    assert tf.get("dh_group") == "2:modp1024"

    # Vendor IDs
    assert len(res.vendor_ids) == 2
    assert any("Cisco Unity" in vid for vid in res.vendor_ids)
    assert any("XAUTH" in vid for vid in res.vendor_ids)


def test_parse_ikev1_notify_message():
    """Verify parsing of IKEv1 notify message (e.g. NO-PROPOSAL-CHOSEN)."""
    res = parse_ike_scan_output(FIXTURE_IKEV1_NOTIFY_NO_PROPOSAL, target_ip="192.168.1.50", target_port=500)
    assert res.response_category == "RESPONDED_NOTIFY"
    assert res.ike_version == "IKEv1"
    assert res.notify_code == 14
    assert res.notify_message == "NO-PROPOSAL-CHOSEN"
    assert len(res.transforms_returned) == 0


def test_parse_no_response():
    """Verify parsing when target sends 0 handshakes and 0 notifies within timeout."""
    res = parse_ike_scan_output(FIXTURE_NO_RESPONSE, target_ip="192.168.1.50", target_port=500)
    assert res.response_category == "NO_RESPONSE"
    assert len(res.transforms_returned) == 0
    assert len(res.vendor_ids) == 0


def test_parse_ikev2_experimental():
    """Verify parsing of experimental IKEv2 default proposal response."""
    res = parse_ike_scan_output(
        FIXTURE_IKEV2_EXPERIMENTAL_HANDSHAKE,
        target_ip="192.168.1.50",
        target_port=500,
        is_experimental=True,
    )
    assert res.response_category == "RESPONDED_HANDSHAKE"
    assert res.ike_version == "IKEv2"
    assert res.is_experimental is True
    assert len(res.transforms_returned) == 1
    assert res.transforms_returned[0].get("encr") == "AES-CBC-128"
    assert any("strongSwan" in vid for vid in res.vendor_ids)


def test_parse_error_output():
    """Verify error output results in TOOL_ERROR."""
    error_text = "ERROR: Failed to send packet: Operation not permitted\nEnding ike-scan: 0 returned handshake"
    res = parse_ike_scan_output(error_text, target_ip="192.168.1.50", target_port=500)
    assert res.response_category == "TOOL_ERROR"
