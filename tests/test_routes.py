import pytest
from app import create_app

@pytest.fixture
def client():
    app = create_app('testing')
    with app.test_client() as client:
        yield client

def test_health_check(client):
    response = client.get('/health')
    assert response.status_code == 200
    data = response.get_json()
    assert data['status'] == 'healthy'
    assert 'NMAP-X' in data['app']

def test_dashboard_route(client):
    response = client.get('/dashboard')
    assert response.status_code == 200
    assert b'Command Dashboard' in response.data

def test_root_route_redirect_or_dashboard(client):
    response = client.get('/')
    assert response.status_code == 200
    assert b'Command Dashboard' in response.data

def test_all_navigation_routes(client):
    implemented_routes = [
        '/host-discovery',
        '/port-scanning',
        '/tcp-scans',
        '/udp-scans',
        '/icmp-scans',
        '/version-detection',
        '/os-detection',
        '/banner-grabbing',
        '/enumeration',
        '/website-footprinting',
        '/reports'
    ]
    for route in implemented_routes:
        res = client.get(route)
        assert res.status_code == 200

    pending_routes = [
        '/settings'
    ]
    for route in pending_routes:
        res = client.get(route)
        assert res.status_code == 200
        assert b'MODULE UNDER IMPLEMENTATION' in res.data

def test_404_error_handler(client):
    res = client.get('/non-existent-route-vector')
    assert res.status_code == 404
    assert b'404' in res.data
