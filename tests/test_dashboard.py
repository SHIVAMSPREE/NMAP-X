import pytest
from app import create_app
from models.db import db, Scan, Host, Port
from models.persistence import ScanPersistenceManager
from scanner.tool_checker import ToolCheckerService

@pytest.fixture
def app():
    app = create_app('testing')
    with app.app_context():
        db.drop_all()
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()

@pytest.fixture
def client(app):
    return app.test_client()

def test_tool_checker_service():
    statuses = ToolCheckerService.get_all_tool_statuses()
    required_tools = ['nmap', 'dnsmap', 'urlcrazy', 'whois', 'dnsrecon', 'dig', 'wafw00f', 'wget']
    
    valid_statuses = [
        'ONLINE', 'NOT INSTALLED', 'ERROR',
        'UNSUPPORTED ON OS', 'UNSUPPORTED ON CURRENT OS',
        'INSTALLED BUT NOT ON PATH', 'RUNTIME MISSING',
        'PACKAGE INSTALLED BUT EXECUTABLE NOT FOUND',
        'INSTALLED BUT EXECUTION FAILED', 'INSTALLATION METHOD UNAVAILABLE'
    ]
    for tool in required_tools:
        assert tool in statuses
        assert statuses[tool]['status'] in valid_statuses
        assert 'label' in statuses[tool]

def test_dashboard_route_and_metrics(client, app):
    with app.app_context():
        # Seed test scans
        s1 = Scan(target="192.168.1.1", scan_type="TCP", status="SUCCESS", duration=1.5)
        s2 = Scan(target="10.0.0.1", scan_type="HOST_DISCOVERY", status="COMPLETED", duration=2.0)
        s3 = Scan(target="example.com", scan_type="UDP", status="ERROR", duration=0.5)
        db.session.add_all([s1, s2, s3])
        db.session.commit()

        # Seed host and port
        h1 = Host(scan_id=s1.id, address="192.168.1.1", state="up")
        db.session.add(h1)
        db.session.flush()

        p1 = Port(host_id=h1.id, port=80, protocol="tcp", state="open", service="http")
        db.session.add(p1)
        db.session.commit()

        metrics = ScanPersistenceManager.get_dashboard_metrics()
        assert metrics['total_scans'] == 3
        assert metrics['completed_scans'] == 2
        assert metrics['failed_scans'] == 1
        assert metrics['hosts_discovered'] == 1
        assert metrics['open_ports'] == 1
        assert metrics['last_scan']['target'] == "example.com"

    response = client.get('/dashboard')
    assert response.status_code == 200
    assert b'Command Dashboard' in response.data
    assert b'EXTERNAL TOOL STATUS' in response.data
    assert b'RECENT SCAN JOBS' in response.data
    assert b'192.168.1.1' in response.data
    assert b'example.com' in response.data
