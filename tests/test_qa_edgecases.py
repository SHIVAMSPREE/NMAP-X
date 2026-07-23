"""
Comprehensive Quality Assurance Edge-Case Test Suite for NMAP-X Platform.
Tests edge cases including empty inputs, invalid targets/ports/URLs/domains,
missing dependencies, permission errors, timeout errors, malformed Nmap XML/output,
duplicate submissions, and route/button endpoint integrity.
"""

import pytest
import subprocess
from unittest.mock import patch, MagicMock
from app import create_app
from models.db import db, Scan
from scanner.validators import (
    ValidationError,
    validate_target_host,
    validate_ports_input,
    validate_url,
    validate_domain,
    check_shell_metacharacters
)
from scanner.result_parser import NmapResultParser
from scanner.nmap_engine import NmapExecutionEngine
from modules.enumeration import EnumerationService
from modules.footprinting import WebFootprintingService

@pytest.fixture
def app():
    app = create_app('testing')
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()

@pytest.fixture
def client(app):
    return app.test_client()

# -------------------------------------------------------------------
# 1. Empty Inputs & Input Validation Edge Cases
# -------------------------------------------------------------------

def test_empty_inputs_validation():
    with pytest.raises(ValidationError, match="cannot be empty"):
        validate_target_host("")

    with pytest.raises(ValidationError, match="cannot be empty"):
        validate_ports_input("")

    with pytest.raises(ValidationError, match="cannot be empty"):
        validate_url("")

    with pytest.raises(ValidationError, match="cannot be empty"):
        validate_domain("")

def test_api_empty_post_payloads(client):
    endpoints = [
        '/api/v1/scan/host-discovery',
        '/api/v1/scan/port-scanning',
        '/api/v1/scan/tcp',
        '/api/v1/scan/udp',
        '/api/v1/scan/icmp',
        '/api/v1/scan/version-detection',
        '/api/v1/scan/os-detection',
        '/api/v1/scan/banner-grabbing',
        '/api/v1/scan/enumeration',
        '/api/v1/scan/website-footprinting',
    ]

    for ep in endpoints:
        res = client.post(ep, json={})
        assert res.status_code == 400
        data = res.get_json()
        assert 'error' in data

# -------------------------------------------------------------------
# 2. Invalid Targets & Shell Metacharacters
# -------------------------------------------------------------------

@pytest.mark.parametrize("invalid_target", [
    "256.1.1.1",
    "1.2.3.4.5",
    "192.168.1.1; cat /etc/passwd",
    "example.com && dir",
    "$(whoami)",
    "192.168.1.1/33",
    "invalid_host_label_$$$"
])
def test_invalid_target_hosts(invalid_target):
    with pytest.raises(ValidationError):
        validate_target_host(invalid_target)

@pytest.mark.parametrize("dangerous_str", [
    "target; id",
    "target|ls",
    "target`whois`",
    "target\nreboot",
    "target&calc"
])
def test_shell_metacharacter_checks(dangerous_str):
    with pytest.raises(ValidationError):
        check_shell_metacharacters(dangerous_str)

# -------------------------------------------------------------------
# 3. Invalid Ports & Ranges
# -------------------------------------------------------------------

@pytest.mark.parametrize("invalid_port", [
    "0",
    "65536",
    "-1",
    "abc",
    "8080-8000",   # Inverted range
    "80-90-100",   # Multiple hyphens
    "80,,443"      # Empty item
])
def test_invalid_ports_and_ranges(invalid_port):
    with pytest.raises(ValidationError):
        validate_ports_input(invalid_port)

# -------------------------------------------------------------------
# 4. Invalid URLs & Schemes
# -------------------------------------------------------------------

@pytest.mark.parametrize("invalid_url", [
    "ftp://example.com",
    "gopher://127.0.0.1",
    "file:///etc/passwd",
    "http://",
    "http://invalid_domain_$$$"
])
def test_invalid_urls(invalid_url):
    with pytest.raises(ValidationError):
        validate_url(invalid_url)

# -------------------------------------------------------------------
# 5. Invalid Domains
# -------------------------------------------------------------------

@pytest.mark.parametrize("invalid_domain", [
    "localhost",         # Missing TLD
    "domain_without_tld",
    "example..com",      # Consecutive dots
    "-example.com",      # Leading hyphen
    "a" * 254 + ".com"   # Exceeds max length
])
def test_invalid_domains(invalid_domain):
    with pytest.raises(ValidationError):
        validate_domain(invalid_domain)

# -------------------------------------------------------------------
# 6. Malformed Nmap XML & Output Parsing
# -------------------------------------------------------------------

@pytest.mark.parametrize("xml_str", [
    "",
    "Not XML content at all",
    "<nmaprun><host><status state='up'/></host>",  # Unclosed XML tag
    "<?xml version='1.0'?><root></root>"
])
def test_malformed_xml_parsing(xml_str):
    result = NmapResultParser.parse_xml(xml_str)
    assert result.parsing_error is not None

# -------------------------------------------------------------------
# 7. Missing Dependencies, Permission Errors, and Timeouts
# -------------------------------------------------------------------

@patch('shutil.which', return_value=None)
def test_missing_dependency_handling(mock_which):
    service = EnumerationService()
    res = service.run_subdomain_enum("example.com")
    assert res['status'] == "NOT_INSTALLED"
    assert "not installed" in res['error']

    wf_service = WebFootprintingService()
    whois_res = wf_service.run_whois("http://example.com")
    assert whois_res['status'] == "NOT_INSTALLED"

@patch('subprocess.Popen')
def test_nmap_engine_permission_denied(mock_popen):
    mock_proc = MagicMock()
    mock_proc.communicate.return_value = ("", "Permission denied: requires root raw sockets")
    mock_proc.returncode = 1
    mock_popen.return_value = mock_proc

    engine = NmapExecutionEngine()
    result = engine.execute(["nmap", "-sS", "192.168.1.1"])
    assert result.status == "PERMISSION_DENIED"
    assert "Permission denied" in result.error

@patch('subprocess.Popen')
def test_nmap_engine_timeout(mock_popen):
    mock_proc = MagicMock()
    mock_proc.communicate.side_effect = [subprocess.TimeoutExpired(cmd=["nmap"], timeout=1), ("", "")]
    mock_proc.kill = MagicMock()
    mock_popen.return_value = mock_proc

    engine = NmapExecutionEngine(timeout=1)
    result = engine.execute(["nmap", "-sS", "192.168.1.1"])
    assert result.status == "TIMEOUT"

# -------------------------------------------------------------------
# 8. Duplicate Submissions & Database Persistence
# -------------------------------------------------------------------

def test_duplicate_submissions(client, app):
    payload = {
        "target": "192.168.1.50",
        "flags": ["-sn"],
        "timing": "-T4"
    }

    # First submission
    res1 = client.post('/api/v1/scan/host-discovery', json=payload)
    assert res1.status_code == 200

    # Second identical submission
    res2 = client.post('/api/v1/scan/host-discovery', json=payload)
    assert res2.status_code == 200

    with app.app_context():
        scans = Scan.query.filter_by(target="192.168.1.50").all()
        assert len(scans) == 2

# -------------------------------------------------------------------
# 9. Complete Navigation & View Routes Integrity
# -------------------------------------------------------------------

def test_all_navigation_routes_render(client):
    routes = [
        '/',
        '/dashboard',
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
        '/reports',
        '/settings',
        '/health'
    ]

    for route in routes:
        res = client.get(route)
        assert res.status_code == 200
