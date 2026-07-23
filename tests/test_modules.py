import pytest
from unittest.mock import patch, MagicMock
from app import create_app
from scanner.nmap_engine import ScanExecutionResult

@pytest.fixture
def client():
    app = create_app('testing')
    with app.test_client() as client:
        yield client

# Sample Nmap XML for mocking
MOCK_NMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sS -p 80 127.0.0.1">
  <host>
    <status state="up" reason="localhost-response"/>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <hostnames>
      <hostname name="localhost"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="Apache" version="2.4.52"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

# 1. UI Routes Rendering Tests
def test_host_discovery_route_render(client):
    res = client.get('/host-discovery')
    assert res.status_code == 200
    assert b'Host Discovery Engine' in res.data
    assert b'btn-start-scan' in res.data

def test_port_scanning_route_render(client):
    res = client.get('/port-scanning')
    assert res.status_code == 200
    assert b'Port Scanning Engine' in res.data
    assert b'btn-start-scan' in res.data

# 2. Host Discovery API Test (Valid Target)
@patch('scanner.nmap_engine.NmapExecutionEngine.execute')
def test_api_host_discovery_success(mock_execute, client):
    mock_execute.return_value = ScanExecutionResult(
        command=["nmap", "-sn", "127.0.0.1"],
        return_code=0,
        stdout=MOCK_NMAP_XML,
        stderr="",
        status="SUCCESS",
        duration=0.1
    )

    payload = {"target": "127.0.0.1", "flags": ["-sn", "-PE"], "timing": "-T4"}
    res = client.post('/api/v1/scan/host-discovery', json=payload)
    
    assert res.status_code == 200
    json_data = res.get_json()
    assert json_data['target'] == "127.0.0.1"
    assert json_data['execution']['status'] == "SUCCESS"
    assert len(json_data['parsed']['hosts']) == 1
    assert json_data['parsed']['hosts'][0]['address'] == "127.0.0.1"

# 3. Host Discovery API Test (Invalid Target)
def test_api_host_discovery_invalid_target(client):
    payload = {"target": "invalid_target_!@#$", "flags": ["-sn"]}
    res = client.post('/api/v1/scan/host-discovery', json=payload)
    assert res.status_code == 400
    json_data = res.get_json()
    assert "Invalid" in json_data['error']

# 4. Port Scanning API Test (Valid Target & Ports)
@patch('scanner.nmap_engine.NmapExecutionEngine.execute')
def test_api_port_scanning_success(mock_execute, client):
    mock_execute.return_value = ScanExecutionResult(
        command=["nmap", "-sS", "-p", "80", "127.0.0.1"],
        return_code=0,
        stdout=MOCK_NMAP_XML,
        stderr="",
        status="SUCCESS",
        duration=0.2
    )

    payload = {
        "target": "127.0.0.1",
        "scan_type": "-sS",
        "port_selection_type": "specific",
        "ports": "80",
        "timing": "-T4"
    }
    res = client.post('/api/v1/scan/port-scanning', json=payload)

    assert res.status_code == 200
    json_data = res.get_json()
    assert json_data['target'] == "127.0.0.1"
    assert json_data['execution']['status'] == "SUCCESS"
    assert len(json_data['parsed']['ports']) == 1
    assert json_data['parsed']['ports'][0]['port'] == 80
    assert json_data['parsed']['ports'][0]['service'] == "http"

# 5. Port Scanning API Test (Invalid Ports)
def test_api_port_scanning_invalid_ports(client):
    payload = {
        "target": "127.0.0.1",
        "scan_type": "-sS",
        "port_selection_type": "specific",
        "ports": "70000"
    }
    res = client.post('/api/v1/scan/port-scanning', json=payload)
    assert res.status_code == 400
    json_data = res.get_json()
    assert "Port number 70000 out of allowed range" in json_data['error']

# 6. Missing Nmap Handling
@patch('scanner.nmap_engine.NmapExecutionEngine.execute')
def test_api_missing_nmap(mock_execute, client):
    mock_execute.return_value = ScanExecutionResult(
        command=["nmap", "-sn", "127.0.0.1"],
        return_code=-1,
        stdout="",
        stderr="",
        status="NOT_INSTALLED",
        duration=0.0,
        error="Nmap executable 'nmap' was not found on the system PATH."
    )

    payload = {"target": "127.0.0.1"}
    res = client.post('/api/v1/scan/host-discovery', json=payload)
    assert res.status_code == 200
    json_data = res.get_json()
    assert json_data['execution']['status'] == "NOT_INSTALLED"
    assert "not found on the system PATH" in json_data['execution']['error']

# 7. Execution Timeout Handling
@patch('scanner.nmap_engine.NmapExecutionEngine.execute')
def test_api_execution_timeout(mock_execute, client):
    mock_execute.return_value = ScanExecutionResult(
        command=["nmap", "-sn", "127.0.0.1"],
        return_code=-1,
        stdout="",
        stderr="",
        status="TIMEOUT",
        duration=300.0,
        error="Scan execution exceeded maximum timeout limit."
    )

    payload = {"target": "127.0.0.1"}
    res = client.post('/api/v1/scan/host-discovery', json=payload)
    assert res.status_code == 200
    json_data = res.get_json()
    assert json_data['execution']['status'] == "TIMEOUT"
    assert "timeout" in json_data['execution']['error']

# 8. Malformed Output Handling
@patch('scanner.nmap_engine.NmapExecutionEngine.execute')
def test_api_malformed_xml_output(mock_execute, client):
    mock_execute.return_value = ScanExecutionResult(
        command=["nmap", "-sn", "127.0.0.1"],
        return_code=0,
        stdout="<nmaprun><host>unclosed tag",
        stderr="",
        status="SUCCESS",
        duration=0.1
    )

    payload = {"target": "127.0.0.1"}
    res = client.post('/api/v1/scan/host-discovery', json=payload)
    assert res.status_code == 200
    json_data = res.get_json()
    assert "Malformed XML" in json_data['parsed']['parsing_error']
