import pytest
from scanner.validators import (
    ValidationError,
    validate_ipv4,
    validate_ipv6,
    validate_ip,
    validate_cidr,
    validate_hostname,
    validate_domain,
    validate_url,
    validate_target_host,
    validate_port,
    validate_port_range,
    validate_ports_input,
    check_shell_metacharacters
)

# 1. IPv4 Validation Tests
def test_valid_ipv4():
    assert validate_ipv4("192.168.1.1") == "192.168.1.1"
    assert validate_ipv4("8.8.8.8") == "8.8.8.8"
    assert validate_ipv4("127.0.0.1") == "127.0.0.1"

def test_invalid_ipv4():
    with pytest.raises(ValidationError):
        validate_ipv4("256.1.1.1")
    with pytest.raises(ValidationError):
        validate_ipv4("1.2.3")
    with pytest.raises(ValidationError):
        validate_ipv4("abc")
    with pytest.raises(ValidationError):
        validate_ipv4("")

# 2. IPv6 Validation Tests
def test_valid_ipv6():
    assert validate_ipv6("2001:db8::1") == "2001:db8::1"
    assert validate_ipv6("::1") == "::1"
    assert validate_ipv6("fe80::1") == "fe80::1"

def test_invalid_ipv6():
    with pytest.raises(ValidationError):
        validate_ipv6("2001:xyz::1")
    with pytest.raises(ValidationError):
        validate_ipv6("127.0.0.1")

# 3. Combined IP Tests
def test_validate_ip():
    assert validate_ip("192.168.1.100") == "192.168.1.100"
    assert validate_ip("::1") == "::1"
    with pytest.raises(ValidationError):
        validate_ip("not-an-ip")

# 4. CIDR Validation Tests
def test_valid_cidr():
    assert validate_cidr("192.168.1.0/24") == "192.168.1.0/24"
    assert validate_cidr("10.0.0.0/16") == "10.0.0.0/16"
    assert validate_cidr("2001:db8::/32") == "2001:db8::/32"

def test_invalid_cidr():
    with pytest.raises(ValidationError):
        validate_cidr("192.168.1.0/33")
    with pytest.raises(ValidationError):
        validate_cidr("10.0.0.0/abc")
    with pytest.raises(ValidationError):
        validate_cidr("192.168.1.1")  # Missing slash

# 5. Hostname & Domain Validation Tests
def test_valid_hostname():
    assert validate_hostname("example.com") == "example.com"
    assert validate_hostname("sub.domain.co.uk") == "sub.domain.co.uk"
    assert validate_hostname("scan-target") == "scan-target"

def test_invalid_hostname():
    with pytest.raises(ValidationError):
        validate_hostname("-invalid.com")
    with pytest.raises(ValidationError):
        validate_hostname("example..com")
    with pytest.raises(ValidationError):
        validate_hostname("")

def test_valid_domain():
    assert validate_domain("example.com") == "example.com"
    with pytest.raises(ValidationError):
        validate_domain("singlelabel")  # Needs TLD

# 6. URL Validation Tests
def test_valid_url():
    assert validate_url("http://example.com") == "http://example.com"
    assert validate_url("https://sub.domain.org/path?query=1") == "https://sub.domain.org/path?query=1"

def test_invalid_url():
    with pytest.raises(ValidationError):
        validate_url("ftp://example.com")
    with pytest.raises(ValidationError):
        validate_url("not-a-url")

# 7. Port Validation Tests
def test_valid_ports():
    assert validate_port(80) == 80
    assert validate_port("443") == 443
    assert validate_port("65535") == 65535
    assert validate_port(1) == 1

def test_invalid_ports():
    with pytest.raises(ValidationError):
        validate_port(0)
    with pytest.raises(ValidationError):
        validate_port(65536)
    with pytest.raises(ValidationError):
        validate_port(-1)
    with pytest.raises(ValidationError):
        validate_port("abc")
    with pytest.raises(ValidationError):
        validate_port("")

# 8. Port Range & List Validation Tests
def test_valid_port_range():
    assert validate_port_range("1-100") == "1-100"
    assert validate_port_range("80-80") == "80-80"

def test_invalid_port_range():
    with pytest.raises(ValidationError):
        validate_port_range("100-10")  # Start > End
    with pytest.raises(ValidationError):
        validate_port_range("1-")
    with pytest.raises(ValidationError):
        validate_port_range("-100")

def test_valid_ports_input():
    assert validate_ports_input("80,443,8000-8080") == "80,443,8000-8080"
    assert validate_ports_input("80") == "80"

def test_invalid_ports_input():
    with pytest.raises(ValidationError):
        validate_ports_input("80,abc,443")
    with pytest.raises(ValidationError):
        validate_ports_input("80,70000")

# 9. Shell Injection Prevention Tests
def test_shell_injection_attempts():
    injection_payloads = [
        "example.com; id",
        "example.com && cat /etc/passwd",
        "127.0.0.1\ncat /etc/shadow",
        "127.0.0.1\r\nwhoami",
        "`whoami`",
        "192.168.1.1|nc",
        "$(whoami)",
        "example.com>out.txt",
        "example.com<in.txt",
        "example.com;ls"
    ]
    for payload in injection_payloads:
        with pytest.raises(ValidationError):
            check_shell_metacharacters(payload)
        with pytest.raises(ValidationError):
            validate_target_host(payload)
