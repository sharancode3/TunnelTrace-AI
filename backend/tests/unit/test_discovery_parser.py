"""Unit tests for safe Nmap XML parsing, entity expansion defense, and ambiguity preservation."""

import pytest
from app.discovery.parser import NmapParseError, parse_nmap_xml

CANNED_UDP_IKE_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sU -Pn -n -p 500,4500 192.168.1.1" start="1700000000" version="7.94">
<scaninfo type="udp" protocol="udp" numservices="2" services="500,4500"/>
<host starttime="1700000001" endtime="1700000005">
  <status state="up" reason="user-set"/>
  <address addr="192.168.1.1" addrtype="ipv4"/>
  <hostnames/>
  <ports>
    <port protocol="udp" portid="500">
      <state state="open|filtered" reason="no-response" reason_ttl="0"/>
      <service name="isakmp" method="table" conf="3"/>
    </port>
    <port protocol="udp" portid="4500">
      <state state="open|filtered" reason="no-response" reason_ttl="0"/>
      <service name="ipsec-msft" method="table" conf="3"/>
    </port>
  </ports>
  <times srtt="0" rttvar="0" to="1000000"/>
</host>
<runstats>
  <finished time="1700000005" exit="success"/>
  <hosts up="1" down="0" total="1"/>
</runstats>
</nmaprun>
"""

CANNED_TCP_VPN_MGMT_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sT -Pn -n -p 22,80,443,8443 10.0.0.1" start="1700000010" version="7.94">
<scaninfo type="connect" protocol="tcp" numservices="4" services="22,80,443,8443"/>
<host starttime="1700000011" endtime="1700000015">
  <status state="up" reason="syn-ack"/>
  <address addr="10.0.0.1" addrtype="ipv4"/>
  <hostnames>
    <hostname name="vpn-gw.corp.local" type="PTR"/>
  </hostnames>
  <ports>
    <port protocol="tcp" portid="443">
      <state state="open" reason="syn-ack"/>
      <service name="https" product="Apache httpd" version="2.4.52" extrainfo="(Ubuntu)" conf="10"/>
    </port>
    <port protocol="tcp" portid="80">
      <state state="closed" reason="reset"/>
      <service name="http" method="table" conf="3"/>
    </port>
    <port protocol="tcp" portid="8443">
      <state state="filtered" reason="no-response"/>
    </port>
  </ports>
</host>
<runstats>
  <finished time="1700000015" exit="success"/>
  <hosts up="1" down="0" total="1"/>
</runstats>
</nmaprun>
"""

CANNED_MULTI_HOST_XML = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" version="7.94">
<host>
  <status state="up"/>
  <address addr="10.0.0.5" addrtype="ipv4"/>
  <ports>
    <port protocol="tcp" portid="22">
      <state state="open"/>
      <service name="ssh" product="OpenSSH" version="8.9p1"/>
    </port>
  </ports>
</host>
<host>
  <status state="down" reason="no-response"/>
  <address addr="10.0.0.6" addrtype="ipv4"/>
  <ports/>
</host>
</nmaprun>
"""

HOSTILE_ENTITY_EXPANSION_XML = """<?xml version="1.0"?>
<!DOCTYPE lolz [
 <!ENTITY lol "lol">
 <!ELEMENT lolz (#PCDATA)>
 <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
 <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
 <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<lolz>&lol3;</lolz>
"""


def test_parser_empty_xml_rejected():
    with pytest.raises(NmapParseError, match="empty"):
        parse_nmap_xml("")


def test_parser_oversized_xml_rejected():
    large_payload = "<nmaprun>" + (" " * 2000) + "</nmaprun>"
    with pytest.raises(NmapParseError, match="exceeds maximum limit"):
        parse_nmap_xml(large_payload, max_bytes=1000)


def test_parser_non_nmaprun_root_rejected():
    xml = "<?xml version='1.0'?><report><item>data</item></report>"
    with pytest.raises(NmapParseError, match="Unexpected XML root element '<report>'"):
        parse_nmap_xml(xml)


def test_parser_entity_expansion_attack_prevented():
    """Ensure billion-laughs entity expansion attacks are neutralized by defusedxml."""
    with pytest.raises(NmapParseError):
        parse_nmap_xml(HOSTILE_ENTITY_EXPANSION_XML)


def test_parser_udp_ike_ambiguity_preserved():
    """Verify open|filtered UDP state maps to OPEN_OR_FILTERED and has_ambiguity=True."""
    result = parse_nmap_xml(CANNED_UDP_IKE_XML)
    assert result.tool_version == "7.94"
    assert result.hosts_up_count == 1
    assert result.services_discovered_count == 2
    assert result.has_ambiguity is True

    host = result.hosts[0]
    assert host.ip_address == "192.168.1.1"
    assert host.state == "UP"
    assert len(host.services) == 2

    # Port 500
    svc500 = next(s for s in host.services if s.port == 500)
    assert svc500.protocol == "UDP"
    assert svc500.state == "OPEN_OR_FILTERED"
    assert svc500.state_reason == "no-response"
    assert svc500.service_name == "isakmp"

    # Port 4500
    svc4500 = next(s for s in host.services if s.port == 4500)
    assert svc4500.protocol == "UDP"
    assert svc4500.state == "OPEN_OR_FILTERED"
    assert svc4500.service_name == "ipsec-msft"


def test_parser_tcp_vpn_management_observations():
    """Verify TCP service evidence extraction with confidence, product, and version."""
    result = parse_nmap_xml(CANNED_TCP_VPN_MGMT_XML)
    assert result.hosts_up_count == 1
    assert result.services_discovered_count == 3
    assert result.has_ambiguity is False  # Definite states: open, closed, filtered

    host = result.hosts[0]
    assert host.ip_address == "10.0.0.1"
    assert host.hostnames == ["vpn-gw.corp.local"]

    p443 = next(s for s in host.services if s.port == 443)
    assert p443.state == "OPEN"
    assert p443.product == "Apache httpd"
    assert p443.version == "2.4.52"
    assert p443.confidence == 10.0

    p80 = next(s for s in host.services if s.port == 80)
    assert p80.state == "CLOSED"
    assert p80.state_reason == "reset"

    p8443 = next(s for s in host.services if s.port == 8443)
    assert p8443.state == "FILTERED"


def test_parser_multiple_hosts_state_tracking():
    """Verify handling of up and down hosts without dropping evidence."""
    result = parse_nmap_xml(CANNED_MULTI_HOST_XML)
    assert len(result.hosts) == 2
    assert result.hosts_up_count == 1

    h1 = result.hosts[0]
    assert h1.ip_address == "10.0.0.5"
    assert h1.state == "UP"
    assert len(h1.services) == 1

    h2 = result.hosts[1]
    assert h2.ip_address == "10.0.0.6"
    assert h2.state == "DOWN"
    assert len(h2.services) == 0
