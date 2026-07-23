"""
Safe Nmap Command Builder for NMAP-X Cybersecurity Reconnaissance Platform.
Generates structured argument arrays for subprocess execution without using shell execution.
Validates targets, port specifications, and flags against strict allowlists.
"""

from typing import List, Optional, Set
from scanner.validators import (
    ValidationError,
    validate_target_host,
    validate_ports_input,
    check_shell_metacharacters
)
from scanner.security_config import ALLOWED_NMAP_FLAGS

# Explicit option allowlists per scan category
HOST_DISCOVERY_FLAGS = {
    '-Pn', '-sn', '-PE', '-PP', '-PM', '-PS', '-PA', '-PU', '-PR', '-n'
}

TCP_SCAN_FLAGS = {
    '-sS', '-sT', '-sA', '-sW', '-sM', '-Pn', '-n', '-F'
}

UDP_SCAN_FLAGS = {
    '-sU', '-Pn', '-n', '-F'
}

ICMP_SCAN_FLAGS = {
    '-PE', '-PP', '-PM', '-sn', '-Pn', '-n'
}

VERSION_DETECTION_FLAGS = {
    '-sV', '--version-light', '--version-all', '-Pn', '-n'
}

OS_DETECTION_FLAGS = {
    '-O', '--osscan-limit', '--osscan-guess', '-Pn', '-n'
}

BANNER_GRABBING_FLAGS = {
    '-sV', '--script=banner', '-Pn', '-n'
}

TIMING_TEMPLATES = {'-T0', '-T1', '-T2', '-T3', '-T4', '-T5'}

class NmapCommandBuilder:
    """
    Builder for constructing safe Nmap CLI argument vectors.
    Strictly validates input targets, ports, and options against allowlists.
    Returns list of arguments, e.g. ["nmap", "-sS", "-p", "80,443", "192.168.1.1"]
    """

    def __init__(self, target: str, nmap_binary: str = "nmap"):
        if not target or not isinstance(target, str) or not target.strip():
            raise ValidationError("Target cannot be empty.")
        
        check_shell_metacharacters(target)
        self.target = validate_target_host(target)
        self.nmap_binary = nmap_binary
        self._flags: Set[str] = set()
        self._ports: Optional[str] = None
        self._top_ports: Optional[int] = None
        self._custom_args: List[str] = []

    def set_timing(self, timing_flag: str) -> "NmapCommandBuilder":
        if timing_flag not in TIMING_TEMPLATES:
            raise ValidationError(f"Invalid timing flag '{timing_flag}'. Must be one of {sorted(TIMING_TEMPLATES)}.")
        # Remove any existing timing flags
        self._flags = {f for f in self._flags if f not in TIMING_TEMPLATES}
        self._flags.add(timing_flag)
        return self

    def set_ports(self, ports: str) -> "NmapCommandBuilder":
        if self._top_ports is not None:
            raise ValidationError("Cannot set both explicit ports and --top-ports.")
        validated = validate_ports_input(ports)
        self._ports = validated
        return self

    def set_top_ports(self, count: int) -> "NmapCommandBuilder":
        if self._ports is not None:
            raise ValidationError("Cannot set both explicit ports and --top-ports.")
        try:
            val = int(count)
            if val <= 0 or val > 65535:
                raise ValueError()
        except (ValueError, TypeError):
            raise ValidationError(f"Invalid --top-ports value '{count}'. Must be a positive integer between 1 and 65535.")
        self._top_ports = val
        return self

    def add_flags(self, flags: List[str], allowed_subset: Optional[Set[str]] = None) -> "NmapCommandBuilder":
        if not flags:
            return self

        for flag in flags:
            if not flag or not isinstance(flag, str):
                raise ValidationError("Invalid flag specification.")
            
            cleaned = flag.strip()
            check_shell_metacharacters(cleaned)

            if allowed_subset is not None and cleaned not in allowed_subset:
                raise ValidationError(f"Flag '{cleaned}' is not permitted for this scan type.")
            elif allowed_subset is None and cleaned not in ALLOWED_NMAP_FLAGS:
                raise ValidationError(f"Flag '{cleaned}' is not in the global allowed Nmap flags whitelist.")

            self._flags.add(cleaned)
        return self

    def add_version_intensity(self, intensity: int) -> "NmapCommandBuilder":
        try:
            val = int(intensity)
            if not (0 <= val <= 9):
                raise ValueError()
        except (ValueError, TypeError):
            raise ValidationError("Version intensity must be an integer between 0 and 9.")
        self._custom_args.extend(["--version-intensity", str(val)])
        return self

    def build(self) -> List[str]:
        cmd = [self.nmap_binary]

        # Add flags sorted for deterministic order
        for flag in sorted(self._flags):
            cmd.append(flag)

        # Custom arguments (e.g. --version-intensity 5)
        cmd.extend(self._custom_args)

        # Port specifications
        if self._ports:
            cmd.extend(["-p", self._ports])
        elif self._top_ports:
            cmd.extend(["--top-ports", str(self._top_ports)])

        # Target argument always appended at the end
        cmd.append(self.target)
        return cmd


# Helper functions for each required scan builder

def build_host_discovery_command(target: str, options: Optional[List[str]] = None, timing: Optional[str] = None) -> List[str]:
    """Builds a safe Host Discovery Nmap command vector."""
    builder = NmapCommandBuilder(target)
    if timing:
        builder.set_timing(timing)
    
    default_flags = ['-sn', '-PE', '-PA'] if not options else options
    builder.add_flags(default_flags, allowed_subset=HOST_DISCOVERY_FLAGS.union(TIMING_TEMPLATES))
    return builder.build()

def build_port_scan_command(target: str, ports: Optional[str] = None, scan_type: str = "-sS", timing: Optional[str] = None) -> List[str]:
    """Builds a generic Port Scanning command vector."""
    builder = NmapCommandBuilder(target)
    if timing:
        builder.set_timing(timing)
    if ports:
        builder.set_ports(ports)
    
    allowed = TCP_SCAN_FLAGS.union(UDP_SCAN_FLAGS).union(TIMING_TEMPLATES)
    builder.add_flags([scan_type], allowed_subset=allowed)
    return builder.build()

def build_tcp_scan_command(target: str, ports: Optional[str] = None, tcp_flag: str = "-sS", options: Optional[List[str]] = None, timing: Optional[str] = None) -> List[str]:
    """Builds a TCP scan command vector (-sS, -sT, -sA, -sW, -sM)."""
    builder = NmapCommandBuilder(target)
    if timing:
        builder.set_timing(timing)
    if ports:
        builder.set_ports(ports)

    flags = [tcp_flag] + (options or [])
    builder.add_flags(flags, allowed_subset=TCP_SCAN_FLAGS.union(TIMING_TEMPLATES))
    return builder.build()

def build_udp_scan_command(target: str, ports: Optional[str] = None, options: Optional[List[str]] = None, timing: Optional[str] = None) -> List[str]:
    """Builds a UDP scan command vector (-sU)."""
    builder = NmapCommandBuilder(target)
    if timing:
        builder.set_timing(timing)
    if ports:
        builder.set_ports(ports)

    flags = ['-sU'] + (options or [])
    builder.add_flags(flags, allowed_subset=UDP_SCAN_FLAGS.union(TIMING_TEMPLATES))
    return builder.build()

def build_icmp_scan_command(target: str, options: Optional[List[str]] = None) -> List[str]:
    """Builds an ICMP scan command vector."""
    builder = NmapCommandBuilder(target)
    flags = options or ['-PE', '-PP', '-sn']
    builder.add_flags(flags, allowed_subset=ICMP_SCAN_FLAGS)
    return builder.build()

def build_version_detection_command(target: str, ports: Optional[str] = None, version_flag: str = "-sV", intensity: Optional[int] = None) -> List[str]:
    """Builds a Version Detection scan command vector (-sV, --version-light, etc.)."""
    builder = NmapCommandBuilder(target)
    if ports:
        builder.set_ports(ports)

    builder.add_flags([version_flag], allowed_subset=VERSION_DETECTION_FLAGS)
    if intensity is not None:
        builder.add_version_intensity(intensity)
    return builder.build()

def build_os_detection_command(target: str, ports: Optional[str] = None, options: Optional[List[str]] = None) -> List[str]:
    """Builds an OS Detection scan command vector (-O, --osscan-limit, etc.)."""
    builder = NmapCommandBuilder(target)
    if ports:
        builder.set_ports(ports)

    flags = ['-O'] + (options or [])
    builder.add_flags(flags, allowed_subset=OS_DETECTION_FLAGS)
    return builder.build()

def build_banner_grabbing_command(target: str, ports: Optional[str] = None) -> List[str]:
    """Builds a Banner Grabbing scan command vector (-sV --script=banner)."""
    builder = NmapCommandBuilder(target)
    if ports:
        builder.set_ports(ports)
    else:
        builder.set_ports("21,22,25,80,110,143,443,3306,8080")

    builder.add_flags(['-sV', '--script=banner'], allowed_subset=BANNER_GRABBING_FLAGS)
    return builder.build()
