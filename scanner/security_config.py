"""
Security and Execution Configuration for Scanner Operations.
Enforces limits, whitelists, and timeouts to prevent misuse and resource exhaustion.
"""

# Execution Timeouts and Resource Quotas
DEFAULT_SCAN_TIMEOUT = 300        # 5 minutes default timeout per scan task
MAX_SCAN_TIMEOUT = 3600          # 1 hour maximum hard limit
MAX_OUTPUT_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB maximum scan output size limit

# Allowed High-Level Scan Profiles
ALLOWED_SCAN_TYPES = {
    'ping_sweep',
    'host_discovery',
    'port_scan_syn',
    'port_scan_tcp',
    'port_scan_udp',
    'port_scan_icmp',
    'version_detection',
    'os_detection',
    'banner_grabbing',
    'subdomain_enum',
    'dns_recon',
    'whois_lookup',
    'web_footprint'
}

# Whitelist of Permitted Nmap Command Flags (Strictly No Arbitrary Script Execution or Outfile Flags)
ALLOWED_NMAP_FLAGS = {
    '-PE', '-PP', '-PS', '-PA', '-PU',
    '-sS', '-sT', '-sU', '-sV', '-O',
    '-F', '-Pn', '-n', '-A', '-v',
    '-p', '--top-ports',
    '-T0', '-T1', '-T2', '-T3', '-T4', '-T5'
}

# Prohibited Shell Metacharacters
PROHIBITED_SHELL_CHARS = {'', ';', '&', '|', '$', '`', '>', '<', '\n', '\r', '\\', '(', ')', '{', '}', '[', ']'}
