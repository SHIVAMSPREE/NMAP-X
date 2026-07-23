import pytest
from app import create_app
from models.db import db, Scan, Host, Port, OSDetection
from modules.report_exporter import ReportExportService

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

def test_report_export_service_sanitization():
    unsafe_name = "../../etc/passwd/test?target=127.0.0.1"
    safe = ReportExportService.sanitize_filename(unsafe_name)
    assert ".." not in safe
    assert "/" not in safe
    assert "\\" not in safe
    assert safe == "etc_passwd_test_target_127_0_0_1"

def test_report_exporter_formats(app):
    with app.app_context():
        scan = Scan(target="192.168.1.100", scan_type="PORT_SCANNING", command="nmap -sS 192.168.1.100", status="SUCCESS", duration=3.2)
        db.session.add(scan)
        db.session.commit()

        host = Host(scan_id=scan.id, address="192.168.1.100", hostname="target-host", state="up")
        db.session.add(host)
        db.session.commit()

        port = Port(host_id=host.id, port=443, protocol="tcp", state="open", service="https", product="OpenSSL", version="1.1.1")
        db.session.add(port)
        db.session.commit()

        json_out = ReportExportService.export_json(scan)
        assert "192.168.1.100" in json_out
        assert "PORT_SCANNING" in json_out

        csv_out = ReportExportService.export_csv(scan)
        assert "192.168.1.100" in csv_out
        assert "https" in csv_out

        txt_out = ReportExportService.export_text(scan)
        assert "NMAP-X RECONNAISSANCE SCAN REPORT" in txt_out
        assert "Port 443/tcp: OPEN" in txt_out

def test_reports_filtering_and_export_route(client, app):
    with app.app_context():
        s1 = Scan(target="192.168.1.1", scan_type="TCP", status="SUCCESS")
        s2 = Scan(target="10.0.0.5", scan_type="UDP", status="ERROR")
        db.session.add_all([s1, s2])
        db.session.commit()
        s1_id = s1.id

    # Filter search target
    res_search = client.get('/reports?search=10.0.0.5')
    assert res_search.status_code == 200
    assert b'10.0.0.5' in res_search.data
    assert b'192.168.1.1' not in res_search.data

    # Filter scan type
    res_type = client.get('/reports?scan_type=TCP')
    assert res_type.status_code == 200
    assert b'192.168.1.1' in res_type.data

    # Filter status
    res_status = client.get('/reports?status=ERROR')
    assert res_status.status_code == 200
    assert b'10.0.0.5' in res_status.data

    # Test JSON Export route
    res_exp_json = client.get(f'/reports/{s1_id}/export?format=json')
    assert res_exp_json.status_code == 200
    assert res_exp_json.headers['Content-Type'] == 'application/json'
    assert b'192.168.1.1' in res_exp_json.data

    # Test CSV Export route
    res_exp_csv = client.get(f'/reports/{s1_id}/export?format=csv')
    assert res_exp_csv.status_code == 200
    assert res_exp_csv.headers['Content-Type'] == 'text/csv'

    # Test TXT Export route
    res_exp_txt = client.get(f'/reports/{s1_id}/export?format=txt')
    assert res_exp_txt.status_code == 200
    assert res_exp_txt.headers['Content-Type'] == 'text/plain'
