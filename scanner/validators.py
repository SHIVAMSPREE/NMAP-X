"""
Validation module for NMAP-X Cybersecurity Reconnaissance Platform.
Provides rigorous input validation and sanitization for IP addresses, hostnames,
CIDR blocks, domain names, URLs, port numbers, and port lists to eliminate
command injection and unexpected input vulnerabilities.
"""

import ipaddress
import re
from urllib.parse import urlparse
from scanner.security_config import PROHIBITED_SHELL_CHARS

class ValidationError(ValueError):
    """Custom exception raised when input validation fails."""
    pass

def check_shell_metacharacters(value: str) -> None:
    """
    Checks if a string contains any dangerous shell metacharacters or newline characters.
    Raises ValidationError if any prohibited character is detected.
    """
    if not isinstance(value, str):
        raise ValidationError("Input must be a string.")

    for char in PROHIBITED_SHELL_CHARS:
        if char and char in value:
            raise ValidationError(f"Invalid input: contains prohibited character '{repr(char)}'")

def is_private_or_loopback_ip(ip_str: str) -> bool:
    """
    Checks if an IP address string is private (RFC 1918), loopback, link-local (169.254.x.x), or reserved.
    Returns True if private/loopback/link-local/reserved, False otherwise.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved
    except ValueError:
        return False

def validate_ipv4(ip_str: str) -> str:
    """
    Validates an IPv4 address.
    Returns sanitized IPv4 address string if valid.
    Raises ValidationError if invalid or malformed.
    """
    if not ip_str or not isinstance(ip_str, str) or not ip_str.strip():
        raise ValidationError("IPv4 address cannot be empty.")

    cleaned = ip_str.strip()
    check_shell_metacharacters(cleaned)

    try:
        ip = ipaddress.IPv4Address(cleaned)
        return str(ip)
    except ValueError as e:
        raise ValidationError(f"Invalid IPv4 address '{cleaned}': {e}")

def validate_ipv6(ip_str: str) -> str:
    """
    Validates an IPv6 address.
    Returns sanitized IPv6 address string if valid.
    Raises ValidationError if invalid or malformed.
    """
    if not ip_str or not isinstance(ip_str, str) or not ip_str.strip():
        raise ValidationError("IPv6 address cannot be empty.")

    cleaned = ip_str.strip()
    check_shell_metacharacters(cleaned)

    try:
        ip = ipaddress.IPv6Address(cleaned)
        return str(ip)
    except ValueError as e:
        raise ValidationError(f"Invalid IPv6 address '{cleaned}': {e}")

def validate_ip(ip_str: str) -> str:
    """
    Validates an IP address (IPv4 or IPv6).
    Returns sanitized IP string if valid.
    Raises ValidationError if invalid.
    """
    try:
        return validate_ipv4(ip_str)
    except ValidationError:
        try:
            return validate_ipv6(ip_str)
        except ValidationError:
            raise ValidationError(f"'{ip_str}' is neither a valid IPv4 nor a valid IPv6 address.")

def validate_cidr(cidr_str: str) -> str:
    """
    Validates a CIDR network range (e.g. 192.168.1.0/24 or 2001:db8::/32).
    Returns sanitized CIDR string if valid.
    Raises ValidationError if invalid.
    """
    if not cidr_str or not isinstance(cidr_str, str) or not cidr_str.strip():
        raise ValidationError("CIDR range cannot be empty.")

    cleaned = cidr_str.strip()
    check_shell_metacharacters(cleaned)

    if '/' not in cleaned:
        raise ValidationError(f"Invalid CIDR notation '{cleaned}': Missing prefix length slash '/'.")

    try:
        net = ipaddress.ip_network(cleaned, strict=False)
        return str(net)
    except ValueError as e:
        raise ValidationError(f"Invalid CIDR range '{cleaned}': {e}")

def validate_hostname(hostname_str: str) -> str:
    """
    Validates a hostname per RFC 1123 standards.
    Total length <= 253 chars, each label 1-63 chars, alphanumeric + hyphens, no leading/trailing hyphen.
    Raises ValidationError if invalid.
    """
    if not hostname_str or not isinstance(hostname_str, str) or not hostname_str.strip():
        raise ValidationError("Hostname cannot be empty.")

    cleaned = hostname_str.strip().lower()
    check_shell_metacharacters(cleaned)

    if len(cleaned) > 253:
        raise ValidationError("Hostname exceeds maximum allowed length of 253 characters.")

    # Remove trailing dot if present for FQDN
    if cleaned.endswith('.'):
        cleaned = cleaned[:-1]

    labels = cleaned.split('.')
    label_regex = re.compile(r'^(?!-)[a-z0-9-]{1,63}(?<!-)$')

    for label in labels:
        if not label:
            raise ValidationError(f"Invalid hostname '{hostname_str}': Contains consecutive dots or empty label.")
        if not label_regex.match(label):
            raise ValidationError(f"Invalid hostname label '{label}' in '{hostname_str}'.")

    return cleaned

def validate_domain(domain_str: str) -> str:
    """
    Validates a domain name (must contain at least one dot separating labels, e.g. example.com).
    Raises ValidationError if invalid.
    """
    hostname = validate_hostname(domain_str)
    if '.' not in hostname:
        raise ValidationError(f"Invalid domain name '{domain_str}': Must include a TLD (e.g. example.com).")
    return hostname

def validate_url(url_str: str) -> str:
    """
    Validates an HTTP/HTTPS URL.
    Returns normalized URL string.
    Raises ValidationError if invalid.
    """
    if not url_str or not isinstance(url_str, str) or not url_str.strip():
        raise ValidationError("URL cannot be empty.")

    cleaned = url_str.strip()
    check_shell_metacharacters(cleaned)

    try:
        parsed = urlparse(cleaned)
    except Exception as e:
        raise ValidationError(f"Malformed URL '{cleaned}': {e}")

    if parsed.scheme not in ('http', 'https'):
        raise ValidationError(f"Invalid URL scheme '{parsed.scheme}'. Only 'http' and 'https' are supported.")

    if not parsed.hostname:
        raise ValidationError(f"Invalid URL '{cleaned}': Hostname is missing.")

    # Validate extracted hostname or IP
    try:
        validate_target_host(parsed.hostname)
    except ValidationError as e:
        raise ValidationError(f"Invalid host in URL '{cleaned}': {e}")

    return cleaned

def validate_target_host(target_str: str) -> str:
    """
    Validates a target host string which can be an IPv4, IPv6, CIDR, or Hostname/Domain.
    Returns sanitized target string.
    Raises ValidationError if input matches none of the allowed formats.
    """
    if not target_str or not isinstance(target_str, str) or not target_str.strip():
        raise ValidationError("Target host cannot be empty.")

    cleaned = target_str.strip()
    check_shell_metacharacters(cleaned)

    # If input consists entirely of numeric dot-separated parts, validate strictly as 4-octet IPv4
    parts = cleaned.split('.')
    if all(p.isdigit() for p in parts):
        if len(parts) != 4:
            raise ValidationError(f"Invalid IP target '{cleaned}': Numeric IP addresses must contain exactly 4 octets.")
        return validate_ipv4(cleaned)

    # Try IP
    try:
        return validate_ip(cleaned)
    except ValidationError:
        pass

    # Try CIDR
    try:
        return validate_cidr(cleaned)
    except ValidationError:
        pass

    # Try Hostname
    try:
        return validate_hostname(cleaned)
    except ValidationError:
        pass

    raise ValidationError(f"Invalid target specification '{cleaned}'. Must be an IPv4, IPv6, CIDR range, or valid hostname.")


def validate_port(port: int | str) -> int:
    """
    Validates a single port number (1-65535).
    Returns integer port.
    Raises ValidationError if invalid.
    """
    if port is None or (isinstance(port, str) and not port.strip()):
        raise ValidationError("Port number cannot be empty.")

    if isinstance(port, str):
        check_shell_metacharacters(port)

    try:
        port_num = int(port)
    except (ValueError, TypeError):
        raise ValidationError(f"Invalid port value '{port}': Must be an integer.")

    if not (1 <= port_num <= 65535):
        raise ValidationError(f"Port number {port_num} out of allowed range (1-65535).")

    return port_num

def validate_port_range(port_range_str: str) -> str:
    """
    Validates a port range string (e.g. '80-100' or '1-65535').
    Returns sanitized range string 'START-END'.
    Raises ValidationError if invalid.
    """
    if not port_range_str or not isinstance(port_range_str, str) or not port_range_str.strip():
        raise ValidationError("Port range cannot be empty.")

    cleaned = port_range_str.strip()
    check_shell_metacharacters(cleaned)

    if '-' not in cleaned:
        raise ValidationError(f"Invalid port range '{cleaned}': Expected hyphen format 'START-END'.")

    parts = cleaned.split('-')
    if len(parts) != 2:
        raise ValidationError(f"Invalid port range '{cleaned}': Multiple hyphens detected.")

    start_port = validate_port(parts[0].strip())
    end_port = validate_port(parts[1].strip())

    if start_port > end_port:
        raise ValidationError(f"Invalid port range '{cleaned}': Start port {start_port} is greater than end port {end_port}.")

    return f"{start_port}-{end_port}"

def validate_ports_input(ports_str: str) -> str:
    """
    Validates a comma-separated list of individual ports and/or port ranges.
    Example: '80,443,8000-8080'
    Returns normalized sanitized string.
    Raises ValidationError if any part is invalid.
    """
    if not ports_str or not isinstance(ports_str, str) or not ports_str.strip():
        raise ValidationError("Port input cannot be empty.")

    cleaned = ports_str.strip()
    check_shell_metacharacters(cleaned)

    if ',,' in cleaned or cleaned.startswith(',') or cleaned.endswith(','):
        raise ValidationError(f"Invalid port specification '{cleaned}': Contains empty or consecutive comma definitions.")

    items = [item.strip() for item in cleaned.split(',') if item.strip()]
    if not items:
        raise ValidationError("Port list contains no valid port definitions.")

    validated_items = []
    for item in items:
        if '-' in item:
            validated_items.append(validate_port_range(item))
        else:
            validated_items.append(str(validate_port(item)))

    return ",".join(validated_items)
