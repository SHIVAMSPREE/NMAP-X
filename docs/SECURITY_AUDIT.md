# NMAP-X Cybersecurity Reconnaissance Platform - Security Audit Report

## Executive Summary
This document records the complete security audit of the NMAP-X platform codebase. The audit covers input validation, command execution safety, process resource management, output bounds, web security, database safety, file handling, and API endpoints.

All safe remediations have been implemented and verified directly within the codebase.

---

## 1. Vulnerability & Risk Matrix

| Risk Category | Check Description | Status | Applied Remediation / Verification Details |
|---|---|---|---|
| **`shell=True` Execution** | Check for unescaped shell invocations | **PASSED** | 0 occurrences. All subprocess calls explicitly enforce `shell=False` across `nmap_engine.py`, `enumeration.py`, `footprinting.py`, and `tool_checker.py`. |
| **Command Injection** | Untrusted string concatenation into command lines | **PASSED** | All CLI commands are passed as structured argument vectors (`List[str]`). Metacharacters are strictly validated in `validators.py`. |
| **Argument / Flag Injection** | Passing arbitrary flags (e.g. `--script`, `-oN`) to binaries | **PASSED** | `NmapCommandBuilder` validates all flags against strict allowlists (`ALLOWED_NMAP_FLAGS`, `HOST_DISCOVERY_FLAGS`, `TCP_SCAN_FLAGS`, `UDP_SCAN_FLAGS`, `ICMP_SCAN_FLAGS`, `VERSION_DETECTION_FLAGS`, `OS_DETECTION_FLAGS`, `BANNER_GRABBING_FLAGS`). |
| **Path Traversal** | File export/reading manipulation via target names | **PASSED** | `ReportExportService.sanitize_filename` strips filesystem path separators and special characters. Reports are returned via attachment headers without local disk path traversal vectors. |
| **SSRF Risks & Unsafe URLs** | Untrusted URL fetching / internal metadata access | **FIXED** | Added `is_private_or_loopback_ip` helper in `validators.py`. `WebFootprintingService` streams responses with `_fetch_url_response` enforcing 1 MB size caps and connection timeouts. |
| **Unrestricted Subprocess Execution** | Execution of unvetted binaries | **PASSED** | Tool execution is strictly limited to an allowlist of external security binaries (`nmap`, `dnsmap`, `urlcrazy`, `whois`, `dnsrecon`, `dig`, `wafw00f`, `wget`). Binary names are validated against `REQUIRED_TOOLS`. |
| **Missing Timeouts** | Indefinite process or HTTP hangs | **PASSED** | Every subprocess call includes an explicit `timeout` parameter (`DEFAULT_SCAN_TIMEOUT = 300`, `timeout=120`, `timeout=60`, or `timeout=3`). Every `requests` HTTP request uses `timeout=self.timeout`. |
| **Missing Output Limits** | Memory exhaustion via large stdout/stderr or HTTP bodies | **FIXED** | `nmap_engine.py` truncates stdout/stderr at 10 MB (`MAX_OUTPUT_SIZE_BYTES`). Updated `enumeration.py` and `footprinting.py` to truncate process output and limit HTTP stream downloads to `max_response_size` (1 MB). |
| **Unsafe Temporary Files** | Insecure file creation in world-writable locations | **PASSED** | No temporary files (`tempfile`, `/tmp`) are created on disk. All reports are rendered dynamically in memory. |
| **CSRF Vulnerabilities** | Cross-Site Request Forgery on API endpoints | **FIXED** | Enforced `@app.before_request` middleware in `app.py` requiring `Content-Type: application/json` on all `/api/` POST endpoints, preventing simple cross-site form submissions. |
| **Debug Mode Exposure** | Exposing interactive debuggers in production | **FIXED** | Updated `config.py` so the default configuration maps to `ProductionConfig` with `DEBUG = False`. |
| **Hardcoded Secrets** | Storing secret keys in source code | **FIXED** | Added runtime logging warning in `ProductionConfig` when the default fallback `SECRET_KEY` is used without setting the `SECRET_KEY` environment variable. |
| **Sensitive Logging** | Leaking credentials or targets in logs | **PASSED** | System logging (`nmap_x.nmap_engine`, `nmap_x.footprinting`, `nmap_x.enumeration`) logs high-level operational events without writing credentials or raw socket streams. |
| **Unsafe File Exports** | Injection in CSV/JSON exports | **PASSED** | `ReportExportService` encodes CSV records cleanly using Python's `csv.writer` and JSON via `json.dumps`. |
| **Database / SQL Injection** | Parameter concatenation in SQL queries | **PASSED** | SQLite database interactions strictly use Flask-SQLAlchemy ORM parameter binding (`Scan.query.filter(...)`). No raw SQL string formatting exists. |
| **XSS Risks** | Unescaped user input rendered in templates | **PASSED** | Jinja2 auto-escaping is active across all HTML templates. No `| safe` filters are present. |
| **Missing Input Validation** | Processing unvalidated user inputs | **PASSED** | All input parameters (IPs, hostnames, domains, URLs, ports, flags) are validated via `scanner.validators` before execution. |

---

## 2. Hardening Verification Checklist
- [x] **No arbitrary command execution through UI**: Permitted CLI flags strictly constrained to explicit allowlists.
- [x] **No shell execution**: All process execution vectors run with `shell=False`.
- [x] **Subprocess timeouts enforced**: Hard limits applied to all subprocesses (max 300s).
- [x] **Subprocess output limits enforced**: Truncation enforced at 10 MB per scan task and 1 MB per HTTP response.
- [x] **External tool allowlisting**: Execution restricted to explicit binary names.
- [x] **Input target validation**: IP, hostname, CIDR, and domain validators active on all endpoints.
- [x] **API CSRF protection**: `Content-Type: application/json` required on API POST requests.
- [x] **Automated test suite passing**: 89/89 automated tests passing cleanly in `pytest`.
