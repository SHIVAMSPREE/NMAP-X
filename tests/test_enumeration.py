import pytest
from unittest.mock import patch, MagicMock
from app import create_app
from modules.enumeration import EnumerationService

@pytest.fixture
def client():
    app = create_app('testing')
    with app.test_client() as client:
        yield client

def test_enumeration_route_render(client):
    res = client.get('/enumeration')
    assert res.status_code == 200
    assert b'Domain &amp; DNS Enumeration Suite' in res.data or b'Domain & DNS Enumeration Suite' in res.data
    assert b'btn-start-scan' in res.data

@patch.object(EnumerationService, 'check_tool_availability')
@patch('subprocess.run')
def test_api_enumeration_success(mock_subproc_run, mock_check_avail, client):
    mock_check_avail.return_value = True
    
    mock_res = MagicMock()
    mock_res.returncode = 0
    mock_res.stdout = "Sample tool enumeration output for example.com"
    mock_res.stderr = ""
    mock_subproc_run.return_value = mock_res

    payload = {
        "domain": "example.com",
        "modules": ["dnsmap", "whois"]
    }
    res = client.post('/api/v1/scan/enumeration', json=payload)
    assert res.status_code == 200
    data = res.get_json()
    assert data['domain'] == "example.com"
    assert "dnsmap" in data['module_results']
    assert "whois" in data['module_results']
    assert data['module_results']['dnsmap']['success'] is True
    assert "Sample tool enumeration output" in data['combined_report']

@patch.object(EnumerationService, 'check_tool_availability')
def test_api_enumeration_missing_tool(mock_check_avail, client):
    # Mock tool as missing
    mock_check_avail.return_value = False

    payload = {
        "domain": "example.com",
        "modules": ["dnsmap"]
    }
    res = client.post('/api/v1/scan/enumeration', json=payload)
    assert res.status_code == 200
    data = res.get_json()
    assert "dnsmap (dnsmap)" in data['missing_tools']
    assert data['module_results']['dnsmap']['status'] == "NOT_INSTALLED"
    assert "not installed or not found" in data['module_results']['dnsmap']['error']

def test_api_enumeration_invalid_domain(client):
    payload = {
        "domain": "invalid_domain_!@#$",
        "modules": ["whois"]
    }
    res = client.post('/api/v1/scan/enumeration', json=payload)
    assert res.status_code == 400
    assert "Invalid" in res.get_json()['error']
