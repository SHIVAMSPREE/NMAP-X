import pytest
from app import create_app
from models.db import db, Scan, Host, Port, OSDetection
from models.persistence import ScanPersistenceManager

@pytest.fixture
def app():
    app = create_app('testing')
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    with app.app_context():
        db.drop_all()
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()

@pytest.fixture
def client(app):
    return app.test_client()

def test_database_models_creation(app):
    with app.app_context():
        scan = Scan(target="192.168.1.1", scan_type="PORT_SCAN", command="nmap -sS 192.168.1.1", status="SUCCESS", duration=1.5)
        db.session.add(scan)
        db.session.commit()

        host = Host(scan_id=scan.id, address="192.168.1.1", hostname="router.local", state="up", latency="1.2ms")
        db.session.add(host)
        db.session.commit()

        port = Port(host_id=host.id, port=80, protocol="tcp", state="open", service="http", product="nginx", version="1.18.0")
        db.session.add(port)

        os = OSDetection(host_id=host.id, name="Linux 5.X", accuracy="95", device_type="general purpose")
        db.session.add(os)
        db.session.commit()

        assert Scan.query.count() == 1
        assert Host.query.count() == 1
        assert Port.query.count() == 1
        assert OSDetection.query.count() == 1

        saved_scan = Scan.query.first()
        assert saved_scan.target == "192.168.1.1"
        assert len(saved_scan.hosts) == 1
        assert saved_scan.hosts[0].ports[0].port == 80
        assert saved_scan.hosts[0].os_matches[0].name == "Linux 5.X"

def test_persistence_manager_save_and_metrics(app):
    with app.app_context():
        result_dict = {
            "target": "10.0.0.1",
            "scan_type": "TCP",
            "execution": {
                "status": "SUCCESS",
                "duration": 2.4,
                "command": ["nmap", "-sS", "-p", "80,443", "10.0.0.1"],
                "stdout": "Nmap scan report for 10.0.0.1...",
                "error": None
            },
            "parsed": {
                "hosts": [
                    {"address": "10.0.0.1", "hostname": "gateway", "state": "up", "reason": "echo-reply", "latency": "5.0ms"}
                ],
                "ports": [
                    {"host": "10.0.0.1", "port": 80, "protocol": "tcp", "state": "open", "service": "http", "product": "Apache"},
                    {"host": "10.0.0.1", "port": 443, "protocol": "tcp", "state": "open", "service": "https", "product": "OpenSSL"}
                ],
                "os_matches": [
                    {"host": "10.0.0.1", "name": "Linux 4.X", "accuracy": "90", "device_type": "router"}
                ]
            }
        }

        scan = ScanPersistenceManager.save_scan_result(None, result_dict)
        assert scan.id is not None
        assert scan.status == "SUCCESS"

        metrics = ScanPersistenceManager.get_dashboard_metrics()
        assert metrics['total_scans'] == 1
        assert metrics['completed_scans'] == 1
        assert metrics['hosts_discovered'] == 1
        assert metrics['open_ports'] == 2
        assert metrics['last_scan']['target'] == "10.0.0.1"

def test_reports_history_and_detail_routes(client, app):
    with app.app_context():
        scan = Scan(target="example.com", scan_type="DOMAIN_ENUM", status="SUCCESS", duration=0.5)
        db.session.add(scan)
        db.session.commit()
        scan_id = scan.id

    res_history = client.get('/reports')
    assert res_history.status_code == 200
    assert b'example.com' in res_history.data

    res_detail = client.get(f'/scans/{scan_id}')
    assert res_detail.status_code == 200
    assert b'Detailed Scan Report #' in res_detail.data
    assert b'example.com' in res_detail.data
