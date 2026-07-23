import pytest
from unittest.mock import patch
from app import create_app
from scanner.nmap_engine import ScanExecutionResult

@pytest.fixture
def client():
    app = create_app('testing')
    with app.test_client() as client:
        yield client

MOCK_TCP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sS -p 80,443 192.168.1.1">
  <host>
    <status state="up" reason="arp-response"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/><service name="http"/></port>
      <port protocol="tcp" portid="443"><state state="closed" reason="reset"/><service name="https"/></port>
    </ports>
  </host>
</nmaprun>
"""

MOCK_UDP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sU -p 53 192.168.1.1">
  <host>
    <status state="up" reason="udp-response"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <ports>
      <port protocol="udp" portid="53"><state state="open|filtered" reason="no-response"/><service name="domain"/></port>
    </ports>
  </host>
</nmaprun>
"""

MOCK_ICMP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -PE -sn 192.168.1.1">
  <host>
    <status state="up" reason="echo-reply"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <times srtt="12000"/>
  </host>
</nmaprun>
"""

# Route Rendering Tests
def test_tcp_scans_route_render(client):
    res = client.get('/tcp-scans')
    assert res.status_code == 200
    assert b'TCP Packet Scans' in res.data

def test_udp_scans_route_render(client):
    res = client.get('/udp-scans')
    assert res.status_code == 200
    assert b'UDP Service Scans' in res.data

def test_icmp_scans_route_render(client):
    res = client.get('/icmp-scans')
    assert res.status_code == 200
    assert b'ICMP Ping Scans' in res.data

# API Endpoint Tests
@patch('scanner.nmap_engine.NmapExecutionEngine.execute')
def test_api_tcp_scan_success(mock_execute, client):
    mock_execute.return_value = ScanExecutionResult(
        command=["nmap", "-sS", "-p", "80,443", "192.168.1.1"],
        return_code=0,
        stdout=MOCK_TCP_XML,
        stderr="",
        status="SUCCESS",
        duration=0.15
    )

    payload = {"target": "192.168.1.1", "scan_type": "-sS", "ports": "80,443"}
    res = client.post('/api/v1/scan/tcp', json=payload)
    assert res.status_code == 200
    data = res.get_json()
    assert data['scan_type'] == "TCP"
    assert len(data['parsed']['ports']) == 2
    assert data['parsed']['ports'][0]['state'] == "open"
    assert data['parsed']['ports'][1]['state'] == "closed"

@patch('scanner.nmap_engine.NmapExecutionEngine.execute')
def test_api_udp_scan_success(mock_execute, client):
    mock_execute.return_value = ScanExecutionResult(
        command=["nmap", "-sU", "-p", "53", "192.168.1.1"],
        return_code=0,
        stdout=MOCK_UDP_XML,
        stderr="",
        status="SUCCESS",
        duration=0.2
    )

    payload = {"target": "192.168.1.1", "ports": "53"}
    res = client.post('/api/v1/scan/udp', json=payload)
    assert res.status_code == 200
    data = res.get_json()
    assert data['scan_type'] == "UDP"
    assert len(data['parsed']['ports']) == 1
    assert data['parsed']['ports'][0]['state'] == "open|filtered"

@patch('scanner.nmap_engine.NmapExecutionEngine.execute')
def test_api_icmp_scan_success(mock_execute, client):
    mock_execute.return_value = ScanExecutionResult(
        command=["nmap", "-PE", "-sn", "192.168.1.1"],
        return_code=0,
        stdout=MOCK_ICMP_XML,
        stderr="",
        status="SUCCESS",
        duration=0.05
    )

    payload = {"target": "192.168.1.1", "icmp_flags": ["-PE"]}
    res = client.post('/api/v1/scan/icmp', json=payload)
    assert res.status_code == 200
    data = res.get_json()
    assert data['scan_type'] == "ICMP"
    assert len(data['parsed']['hosts']) == 1
    assert data['parsed']['hosts'][0]['state'] == "up"
    assert data['parsed']['hosts'][0]['latency'] == "12.00ms"

def test_api_tcp_scan_invalid_target(client):
    payload = {"target": "invalid_target_!@#$"}
    res = client.post('/api/v1/scan/tcp', json=payload)
    assert res.status_code == 400
    assert "Invalid" in res.get_json()['error']
