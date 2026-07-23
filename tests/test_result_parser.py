import pytest
from scanner.result_parser import NmapResultParser, ParsedScanResult

# XML Fixture 1: Complete Nmap Output with Host, Ports, Service Details & OS Detection
SAMPLE_NMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sS -sV -O -p 22,80,443 192.168.1.1" start="1680000000" version="7.94">
  <host starttime="1680000001" endtime="1680000010">
    <status state="up" reason="echo-reply"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <hostnames>
      <hostname name="router.local" type="PTR"/>
    </hostnames>
    <times srtt="15200" rttvar="5000" to="100000"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="8.9p1" extrainfo="Ubuntu Linux" method="probed">
          <cpe>cpe:/a:openbsd:openssh:8.9p1</cpe>
        </service>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="nginx" version="1.18.0" extrainfo="Unix" method="probed">
          <cpe>cpe:/a:nginx:nginx:1.18.0</cpe>
        </service>
      </port>
      <port protocol="tcp" portid="443">
        <state state="closed" reason="reset"/>
      </port>
    </ports>
    <os>
      <osmatch name="Linux 5.4.0 - 5.15.0" accuracy="98">
        <osclass type="general purpose" vendor="Linux" osfamily="Linux" osgen="5.X">
          <cpe>cpe:/o:linux:linux_kernel:5</cpe>
        </osclass>
      </osmatch>
    </os>
  </host>
</nmaprun>
"""

# XML Fixture 2: Minimal Host XML with Missing Fields
MINIMAL_NMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap">
  <host>
    <address addr="10.0.0.5" addrtype="ipv4"/>
  </host>
</nmaprun>
"""

# 1. Test Valid Full XML Parsing
def test_parse_valid_nmap_xml():
    parsed: ParsedScanResult = NmapResultParser.parse_xml(SAMPLE_NMAP_XML, raw_text_fallback="Nmap output text")

    assert parsed.parsing_error is None
    assert parsed.raw_text == "Nmap output text"
    
    # Host Validation
    assert len(parsed.hosts) == 1
    host = parsed.hosts[0]
    assert host.address == "192.168.1.1"
    assert host.hostname == "router.local"
    assert host.state == "up"
    assert host.reason == "echo-reply"
    assert host.latency == "15.20ms"

    # Ports Validation
    assert len(parsed.ports) == 3
    port22 = parsed.ports[0]
    assert port22.port == 22
    assert port22.protocol == "tcp"
    assert port22.state == "open"
    assert port22.service == "ssh"
    assert port22.product == "OpenSSH"
    assert port22.version == "8.9p1"
    assert port22.extra_info == "Ubuntu Linux"
    assert port22.cpe == ["cpe:/a:openbsd:openssh:8.9p1"]

    # OS Validation
    assert len(parsed.os_matches) == 1
    os_match = parsed.os_matches[0]
    assert os_match.name == "Linux 5.4.0 - 5.15.0"
    assert os_match.accuracy == "98"
    assert os_match.device_type == "general purpose"
    assert "cpe:/o:linux:linux_kernel:5" in os_match.cpe

    # Services Validation
    assert len(parsed.services) == 2
    assert parsed.services[0].service_name == "ssh"
    assert parsed.services[1].service_name == "http"

# 2. Test Minimal XML with Missing Optional Fields
def test_parse_minimal_xml():
    parsed = NmapResultParser.parse_xml(MINIMAL_NMAP_XML)
    assert parsed.parsing_error is None
    assert len(parsed.hosts) == 1
    host = parsed.hosts[0]
    assert host.address == "10.0.0.5"
    assert host.hostname == ""
    assert host.state == "unknown"
    assert len(parsed.ports) == 0
    assert len(parsed.os_matches) == 0

# 3. Test Empty Input XML
def test_parse_empty_xml():
    parsed = NmapResultParser.parse_xml("")
    assert parsed.parsing_error == "Empty XML input."
    assert len(parsed.hosts) == 0

# 4. Test Malformed XML (Parse Error)
def test_parse_malformed_xml():
    parsed = NmapResultParser.parse_xml("<nmaprun><host>unclosed tag")
    assert parsed.parsing_error is not None
    assert "Malformed XML" in parsed.parsing_error
    assert len(parsed.hosts) == 0

# 5. Test Non-Nmap XML Document Root
def test_parse_invalid_root_tag():
    parsed = NmapResultParser.parse_xml("<html><body>Not Nmap</body></html>")
    assert parsed.parsing_error is not None
    assert "Invalid Nmap XML document root tag" in parsed.parsing_error

# 6. Test Data Model Export to Dict
def test_to_dict_export():
    parsed = NmapResultParser.parse_xml(SAMPLE_NMAP_XML)
    data_dict = parsed.to_dict()
    assert isinstance(data_dict, dict)
    assert "hosts" in data_dict
    assert "ports" in data_dict
    assert data_dict["hosts"][0]["address"] == "192.168.1.1"
