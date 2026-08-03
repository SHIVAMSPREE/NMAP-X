"""
Security and Execution Configuration for Scanner Operations.
Enforces limits, whitelists, and timeouts to prevent misuse and resource exhaustion.
"""

import os

# ------------------------------------------------------------------
# Cloud / Render Environment Detection
# Render sets the RENDER environment variable automatically.
# When running on cloud platforms (no CAP_NET_RAW), raw socket scans
# like -sS, -sU, -O, -PE will fail. We fall back to -sT + -Pn which
# uses TCP Connect (no raw sockets needed).
# ------------------------------------------------------------------
IS_CLOUD_ENV = bool(os.environ.get('RENDER') or os.environ.get('CLOUD_ENV'))

# Execution Timeouts and Resource Quotas
# On Render, HTTP gateway cuts off at ~30s so we use a tighter default.
DEFAULT_SCAN_TIMEOUT = 25 if IS_CLOUD_ENV else 300   # 25s on cloud, 5 min locally
MAX_SCAN_TIMEOUT = 25 if IS_CLOUD_ENV else 3600       # Hard limit matches gateway on cloud
MAX_OUTPUT_SIZE_BYTES = 10 * 1024 * 1024              # 10 MB maximum scan output size limit

# Cloud-safe scan defaults (no raw sockets required)
# -sT  = TCP Connect scan (works without CAP_NET_RAW)
# -Pn  = Skip host discovery ping (ICMP also needs raw sockets)
CLOUD_SAFE_SCAN_TYPE = '-sT'
CLOUD_SAFE_EXTRA_FLAGS = ['-Pn']

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
