import pytest
from unittest.mock import patch, MagicMock
from app import create_app

@pytest.fixture
def client():
    app = create_app('testing')
    with app.test_client() as client:
        yield client

def test_website_footprinting_route_render(client):
    res = client.get('/website-footprinting')
    assert res.status_code == 200
    assert b'Website Footprinting Suite' in res.data
    assert b'btn-start-scan' in res.data

@patch('requests.get')
def test_api_website_footprinting_success(mock_get, client):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {"Server": "nginx/1.18.0", "X-Powered-By": "PHP/8.1"}
    mock_resp.text = "<html><head><title>Test Target</title><meta name='description' content='Security Test'></head><body>Hello</body></html>"
    mock_get.return_value = mock_resp

    payload = {
        "url": "http://example.com",
        "operations": ["headers", "server_tech", "metadata", "html"]
    }
    res = client.post('/api/v1/scan/website-footprinting', json=payload)
    assert res.status_code == 200
    data = res.get_json()
    assert data['url'] == "http://example.com"
    assert "headers" in data['operation_results']
    assert "server_tech" in data['operation_results']
    assert data['operation_results']['server_tech']['server'] == "nginx/1.18.0"

def test_api_website_footprinting_mirroring_opt_in_required(client):
    payload = {
        "url": "http://example.com",
        "operations": ["mirror"],
        "mirror_opt_in": False
    }
    res = client.post('/api/v1/scan/website-footprinting', json=payload)
    assert res.status_code == 200
    data = res.get_json()
    assert data['operation_results']['mirror']['status'] == "REQUIRES_OPT_IN"
    assert "explicit user confirmation" in data['operation_results']['mirror']['output']

def test_api_website_footprinting_invalid_url(client):
    payload = {
        "url": "invalid_url_not_http",
        "operations": ["headers"]
    }
    res = client.post('/api/v1/scan/website-footprinting', json=payload)
    assert res.status_code == 400
    assert "Invalid" in res.get_json()['error']
