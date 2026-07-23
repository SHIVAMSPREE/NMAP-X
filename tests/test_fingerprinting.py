import pytest
from unittest.mock import patch
from app import create_app
from scanner.nmap_engine import ScanExecutionResult

@pytest.fixture
def client():
    app = create_app('testing')
    with app.test_client() as client:
        yield client

MOCK_VERSION_XML = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sV -p 80 192.168.1.1">
  <host>
    <status state="up"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="Apache httpd" version="2.4.52" extrainfo="(Ubuntu)">
          <cpe>cpe:/a:apache:http_server:2.4.52</cpe>
        </service>
      </port>
    </ports>
  </host>
</nmaprun>
"""

MOCK_OS_XML = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -O 192.168.1.1">
  <host>
    <status state="up"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <os>
      <osmatch name="Linux 5.4.0" accuracy="96">
        <osclass type="general purpose">
          <cpe>cpe:/o:linux:linux_kernel:5.4</cpe>
        </osclass>
      </osmatch>
    </os>
  </host>
</nmaprun>
"""

MOCK_BANNER_XML = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sV --script=banner 192.168.1.1">
  <host>
    <status state="up"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9p1" extrainfo="SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1">
          <cpe>cpe:/a:openbsd:openssh:8.9p1</cpe>
        </service>
      </port>
    </ports>
  </host>
</nmaprun>
"""

# Route Rendering Tests
def test_version_detection_route_render(client):
    res = client.get('/version-detection')
    assert res.status_code == 200
    assert b'Service Version Detection' in res.data

def test_os_detection_route_render(client):
    res = client.get('/os-detection')
    assert res.status_code == 200
    assert b'Operating System Fingerprinting' in res.data

def test_banner_grabbing_route_render(client):
    res = client.get('/banner-grabbing')
    assert res.status_code == 200
    assert b'Banner Grabbing Engine' in res.data

# API Endpoint Tests
@patch('scanner.nmap_engine.NmapExecutionEngine.execute')
def test_api_version_detection_success(mock_execute, client):
    mock_execute.return_value = ScanExecutionResult(
        command=["nmap", "-sV", "-p", "80", "192.168.1.1"],
        return_code=0,
        stdout=MOCK_VERSION_XML,
        stderr="",
        status="SUCCESS",
        duration=0.25
    )

    payload = {"target": "192.168.1.1", "version_flag": "-sV", "ports": "80"}
    res = client.post('/api/v1/scan/version-detection', json=payload)
    assert res.status_code == 200
    data = res.get_json()
    assert data['scan_type'] == "VERSION_DETECTION"
    assert len(data['parsed']['ports']) == 1
    assert data['parsed']['ports'][0]['product'] == "Apache httpd"
    assert data['parsed']['ports'][0]['version'] == "2.4.52"

@patch('scanner.nmap_engine.NmapExecutionEngine.execute')
def test_api_os_detection_success(mock_execute, client):
    mock_execute.return_value = ScanExecutionResult(
        command=["nmap", "-O", "192.168.1.1"],
        return_code=0,
        stdout=MOCK_OS_XML,
        stderr="",
        status="SUCCESS",
        duration=0.3
    )

    payload = {"target": "192.168.1.1", "os_options": ["--osscan-limit"]}
    res = client.post('/api/v1/scan/os-detection', json=payload)
    assert res.status_code == 200
    data = res.get_json()
    assert data['scan_type'] == "OS_DETECTION"
    assert len(data['parsed']['os_matches']) == 1
    assert data['parsed']['os_matches'][0]['name'] == "Linux 5.4.0"
    assert data['parsed']['os_matches'][0]['accuracy'] == "96"

@patch('scanner.nmap_engine.NmapExecutionEngine.execute')
def test_api_banner_grabbing_success(mock_execute, client):
    mock_execute.return_value = ScanExecutionResult(
        command=["nmap", "-sV", "--script=banner", "192.168.1.1"],
        return_code=0,
        stdout=MOCK_BANNER_XML,
        stderr="",
        status="SUCCESS",
        duration=0.2
    )

    payload = {"target": "192.168.1.1", "ports": "22"}
    res = client.post('/api/v1/scan/banner-grabbing', json=payload)
    assert res.status_code == 200
    data = res.get_json()
    assert data['scan_type'] == "BANNER_GRABBING"
    assert len(data['parsed']['ports']) == 1
    assert "SSH-2.0-OpenSSH" in data['parsed']['ports'][0]['extra_info']

def test_api_version_detection_invalid_target(client):
    payload = {"target": "invalid_target_!@#$"}
    res = client.post('/api/v1/scan/version-detection', json=payload)
    assert res.status_code == 400
    assert "Invalid" in res.get_json()['error']
