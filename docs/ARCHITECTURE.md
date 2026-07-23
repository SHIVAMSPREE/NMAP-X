# Architecture Document: NMAP Web Scanner & Cybersecurity Reconnaissance Platform

## 1. Project Overview

The **NMAP Web Scanner & Cybersecurity Reconnaissance Platform** is a modular, web-based platform designed to convert legacy CLI and standalone Python/Bash reconnaissance scripts into a unified Flask application. 

The goal of this architecture is to provide an enterprise-ready, scalable, and secure interface for network recon, domain enumeration, and web footprinting while adhering to security best practices, strict input validation, safe process execution, and asynchronous task management.

---

## 2. Existing Script Analysis

The existing codebase consists of three foundational scripts:

1. **`RECON.txt`** (Python)
   - Uses `python-nmap` and `socket`.
   - Performs DNS resolution, host discovery (`-PE -PP -PS -PA -PU`), SYN/UDP port scanning (`-sS -sU`), service version detection (`-sV`), and OS detection (`-O`).
   - Saves results into a static flat file (`scan_results.txt`).

2. **`ENUMERATION.txt`** (Bash)
   - Executes CLI tools sequentially: `dnsmap`, `urlcrazy`, `whois`, `dnsrecon`, and `dig` (AXFR zone transfers).
   - Relies on direct command invocations and prints raw text output to standard out.

3. **`WEBSITE FOOTPRINTING.txt`** (Python)
   - Uses `requests`, `socket`, `subprocess`, `python-whois`, and `bs4` (BeautifulSoup).
   - Performs WHOIS lookups, HTML parsing, header analysis, server technology detection, website mirroring (`wget`), sitemap parsing, wordlist extraction, metadata extraction, WAF detection (`wafw00f`), load balancer detection, HTTP OPTIONS discovery, banner grabbing via raw sockets, directory enumeration, and local proxy testing.
   - Appends all output sequentially to `Information_Gathered.txt`.

### Key Deficiencies & Flaws Identified

- **Duplicated Functionality**:
  - DNS resolution is duplicated across `RECON.txt` (`socket.gethostbyname`), `WEBSITE FOOTPRINTING.txt` (`website_enumeration`), and `ENUMERATION.txt` (`dig`/`dnsrecon`).
  - WHOIS queries are duplicated between `ENUMERATION.txt` (`whois` CLI) and `WEBSITE FOOTPRINTING.txt` (`python-whois`).
  - HTTP header inspection is split across `check_http_processing`, `identify_server_tech`, and `http_service_discovery`.

- **Unsafe Subprocess & OS Execution**:
  - `ENUMERATION.txt` uses unquoted bash variables `$TARGET`, making it vulnerable to shell parameter and command injection if invoked dynamically.
  - `WEBSITE FOOTPRINTING.txt` invokes `subprocess.run(["wget", ...])` and `subprocess.run(["wafw00f", url])`. Passing untrusted inputs directly can lead to parameter injection or disk exhaustion (e.g., unlimited recursive website mirroring).
  - Privileged Nmap scans (`-sS`, `-O`) require elevated permissions (root/sudo capabilities).

- **Missing Validation & Error Handling**:
  - Naive domain parsing (`url.split("//")[-1].split("/")[0]`) fails on complex URLs, custom ports, or malformed schemes.
  - No check for scope/target constraints, creating risks of Server-Side Request Forgery (SSRF) or unauthorized internal scanning.
  - Generic `except Exception as e` catches swallow diagnostic details without proper logging or recovery.
  - Hardcoded proxy endpoints (`127.0.0.1:8080`) and static output filenames.

- **External Tool Dependencies**:
  - Python packages: `python-nmap`, `requests`, `beautifulsoup4`, `python-whois`.
  - Binary utilities: `nmap`, `dnsmap`, `urlcrazy`, `whois`, `dnsrecon`, `dig` (`bind-utils`), `wget`, `wafw00f`.

---

## 3. Function-to-Module Mapping

| Existing Function / Script Block | Source File | Proposed Flask Backend Module | Purpose & Refactoring Plan |
| :--- | :--- | :--- | :--- |
| DNS Resolution (`socket.gethostbyname`) | `RECON.txt`, `WEBSITE FOOTPRINTING.txt` | `app.services.dns_service` | Centralized async DNS lookup with IPv4/IPv6 support & validation. |
| Host Discovery (`nmap -PE -PP -PS...`) | `RECON.txt` | `app.services.nmap_service` | Modular Nmap ping sweep wrapper returning structured JSON. |
| Port Scanning (`nmap -sS -sU`) | `RECON.txt` | `app.services.nmap_service` | Configurable port scanner with customizable port ranges & timing. |
| Service & OS Detection (`nmap -sV -O`) | `RECON.txt` | `app.services.nmap_service` | Async Nmap service fingerprinting; requires explicit authorization flag. |
| Subdomain Enumeration (`dnsmap`) | `ENUMERATION.txt` | `app.services.subdomain_service` | Wrapper for subdomain discovery with fallback to python-native resolvers. |
| Typosquatting / Domain Check (`urlcrazy`) | `ENUMERATION.txt` | `app.services.subdomain_service` | Domain permutation and squatting analysis service. |
| WHOIS Lookup | `ENUMERATION.txt`, `WEBSITE FOOTPRINTING.txt` | `app.services.whois_service` | Python-native WHOIS parser returning normalized structured record JSON. |
| DNS Record & Zone Transfer (`dnsrecon`, `dig AXFR`)| `ENUMERATION.txt` | `app.services.dns_service` | Native Python `dnspython` library implementation for record lookup & AXFR check. |
| HTML & Metadata Analysis (`bs4`) | `WEBSITE FOOTPRINTING.txt` | `app.services.web_footprint_service` | HTML parser for meta tags, page titles, scripts, links, and text extraction. |
| HTTP Headers & Tech ID | `WEBSITE FOOTPRINTING.txt` | `app.services.web_footprint_service` | Header analyzer checking security headers, Server, and `X-Powered-By`. |
| Website Mirroring (`wget`) | `WEBSITE FOOTPRINTING.txt` | `app.services.crawler_service` | Safe sandboxed crawler with strict depth, rate, and disk quota limits. |
| Sitemap Parsing | `WEBSITE FOOTPRINTING.txt` | `app.services.web_footprint_service` | XML sitemap resolver and link parser. |
| WAF Detection (`wafw00f`) | `WEBSITE FOOTPRINTING.txt` | `app.services.security_check_service` | Native or safe subprocess execution of WAF identification tools. |
| Load Balancer Detection | `WEBSITE FOOTPRINTING.txt` | `app.services.security_check_service` | Multi-request cookie/header drift detector. |
| Banner Grabbing | `WEBSITE FOOTPRINTING.txt` | `app.services.network_service` | Asynchronous socket banner retrieval with strict timeouts. |
| Directory Enumeration | `WEBSITE FOOTPRINTING.txt` | `app.services.web_footprint_service` | Configurable directory bruteforce with customizable wordlists. |
| Proxy Testing | `WEBSITE FOOTPRINTING.txt` | `app.services.network_service` | Diagnostic proxy checker with configurable target endpoints. |

---

## 4. Proposed Project Structure

```
NMAP-X/
├── app/
│   ├── __init__.py              # Flask app factory
│   ├── config.py                # Environment configuration & security policies
│   ├── models/                  # Database models (SQLAlchemy)
│   │   ├── __init__.py
│   │   ├── scan.py              # Scan job metadata and status
│   │   ├── target.py            # Validated scan targets
│   │   └── result.py            # Structured scan results & logs
│   ├── api/                     # REST API blueprints
│   │   ├── __init__.py
│   │   ├── v1/
│   │   │   ├── recon.py         # Network recon & Nmap endpoints
│   │   │   ├── enumeration.py   # DNS & subdomain endpoints
│   │   │   ├── footprinting.py  # Web footprinting & crawling endpoints
│   │   │   └── jobs.py         # Async job management & streaming
│   ├── services/                # Core business logic & tool wrappers
│   │   ├── __init__.py
│   │   ├── nmap_service.py      # Nmap wrapper & output parser
│   │   ├── dns_service.py       # DNS & AXFR zone transfer logic
│   │   ├── whois_service.py     # WHOIS lookup & normalization
│   │   ├── subdomain_service.py # Subdomain enumeration & permutation
│   │   ├── web_footprint_service.py # HTTP analysis, HTML parsing, metadata
│   │   ├── crawler_service.py   # Sandboxed web crawling logic
│   │   └── security_check_service.py # WAF & load balancer detection
│   ├── tasks/                   # Celery/RQ background task definitions
│   │   ├── __init__.py
│   │   └── scan_tasks.py        # Async scan execution tasks
│   ├── utils/                   # Shared helpers
│   │   ├── validation.py        # Target URL/IP scope validators
│   │   ├── process_runner.py    # Safe subprocess execution handler
│   │   └── parsers.py           # XML/JSON output parsers
│   └── templates/               # Flask HTML templates (Jinja2/Vanilla CSS)
│       ├── base.html
│       ├── dashboard.html
│       ├── new_scan.html
│       └── scan_detail.html
├── static/                      # Static web assets
│   ├── css/
│   │   └── main.css             # Custom theme (Vanilla CSS design system)
│   └── js/
│       ├── app.js               # Frontend interaction logic
│       └── realtime.js          # WebSockets / SSE log stream reader
├── docs/
│   └── ARCHITECTURE.md          # Architecture specification document
├── tests/
│   ├── unit/                    # Unit tests for services and validators
│   └── integration/             # Integration tests for API blueprints
├── migrations/                  # Alembic DB migration scripts
├── scripts/                     # Helper setup & deployment scripts
├── requirement.txt              # Python dependencies
└── run.py                       # Application entry point
```

---

## 5. Backend Architecture

- **Framework**: Flask (Application Factory pattern via `create_app()`).
- **Async Execution**: Long-running scans (Nmap, directory bruteforce, subdomain discovery) must run out-of-band using **Celery** or **Redis Queue (RQ)** to avoid blocking HTTP worker threads.
- **IPC & Real-time Logs**: Redis as message broker; Server-Sent Events (SSE) or WebSockets (`Flask-SocketIO`) for streaming scan logs live to the web dashboard.
- **Process Execution**: Abstracted via `utils.process_runner.py` using `subprocess.Popen` with non-shell execution (`shell=False`), explicit argument vectors, time limits, and memory/disk resource caps.

---

## 6. Frontend Architecture

- **Interface**: Clean, responsive modern dashboard built with HTML5, Vanilla JavaScript (ES6+), and custom CSS (Dark Mode theme with sleek glassmorphism aesthetic).
- **Components**:
  - **Scan Launcher**: Target input field, scan profile selection (Quick, Full Recon, Web Footprint, Custom), and explicit Scope Authorization Checkboxes.
  - **Live Monitor**: Console output viewer streaming real-time stdout/stderr from background tools.
  - **Results Viewer**: Categorized tabs for Open Ports, Subdomains, Web Technologies, WHOIS Metadata, and Security Alerts.
  - **Export Engine**: One-click download of scan reports in JSON, CSV, or PDF formats.

---

## 7. Security Architecture

1. **Target & Scope Validation**:
   - Every input URL/IP is sanitized using `ipaddress` and `urllib.parse`.
   - Default restriction blocking private/loopback/RFC 1918 ranges (`127.0.0.1`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.169.254`) to prevent SSRF, unless explicit "Internal Lab Mode" is toggled in configuration.

2. **Subprocess Isolation**:
   - `shell=False` enforced across all subprocess executions to eliminate Command Injection vectors.
   - Arguments passed as strict sanitized string arrays.

3. **Privilege Management**:
   - Avoid running the web application as `root`.
   - Standard Nmap raw socket scans (`-sS`) require `CAP_NET_RAW` capability assigned to the Nmap binary or dedicated worker process via Linux capabilities rather than full root rights.

4. **Rate Limiting & Warnings**:
   - Intrusive operations (directory brute-forcing, SYN scans, AXFR zone transfer attempts) require explicit user consent checkboxes with warning disclaimers.
   - Global rate limiters using `Flask-Limiter`.

---

## 8. Database Architecture

- **ORM**: SQLAlchemy with SQLite (development) / PostgreSQL (production).
- **Core Entities**:
  - **`Target`**: ID, host string, resolved IP, created date, scope approval status.
  - **`ScanJob`**: ID, target_id, scan_type, status (`PENDING`, `RUNNING`, `COMPLETED`, `FAILED`), started_at, finished_at, error_log.
  - **`PortResult`**: ID, scan_job_id, port_number, protocol, state, service_name, version, os_match.
  - **`SubdomainResult`**: ID, scan_job_id, subdomain, ip_address, source_tool.
  - **`WebResult`**: ID, scan_job_id, header_data (JSON), server_tech, metadata_tags (JSON), waf_detected, is_load_balanced.

---

## 9. Scan Execution Architecture

```
[ Frontend UI ] --( POST /api/v1/scans )--> [ Flask API ]
                                                  |
                                          ( Validate Scope )
                                                  |
                                     ( Enqueue Task to Redis )
                                                  |
                                                  v
                                         [ Celery/RQ Worker ]
                                                  |
                                    +-------------+-------------+
                                    |                           |
                            (Native Py Services)       (Safe Process Runner)
                            - DNS / WHOIS              - Nmap / Wafw00f
                            - HTTP Footprint           - Dnsrecon / Wget
                                    |                           |
                                    +-------------+-------------+
                                                  |
                                       ( Parse & Standardize )
                                                  |
                                                  v
                                       [ Database (PostgreSQL) ]
                                                  |
                                      ( SSE / WebSocket Stream )
                                                  |
                                                  v
                                         [ Live Dashboard UI ]
```

---

## 10. Result Parsing Architecture

- Nmap outputs are parsed via `NmapParser` into structured Python dictionaries rather than scraping stdout.
- HTTP header checks return normalized JSON structures (`{ "server": "Apache", "x-powered-by": "PHP/8.1", "security_headers": {...} }`).
- WHOIS records are normalized into standard schema fields (`registrar`, `creation_date`, `expiration_date`, `name_servers`).

---

## 11. Testing Strategy

1. **Unit Testing**:
   - `pytest` suite for validation utilities (`app/utils/validation.py`).
   - Mocking external tool calls (`unittest.mock`) to test service logic without performing network requests.

2. **Integration Testing**:
   - Flask Test Client tests for REST API endpoints (`/api/v1/*`).
   - Database model creation and relationship validation.

3. **Security Testing**:
   - Input fuzzing against target submission endpoints to verify Command Injection immunity.
   - SSRF payload validation against IP restriction filters.

---

## 12. Development Phases

- **Phase 1: Architecture & Base Setup** (Current Phase)
  - Create directory structure, virtual environment, and configuration modules.
  - Implement target validation utilities and safe process runner.

- **Phase 2: Core Services & Native Python Refactoring**
  - Implement `dns_service`, `whois_service`, `web_footprint_service` natively in Python.

- **Phase 3: Async Task Engine & CLI Wrappers**
  - Integrate Redis/Celery background workers.
  - Build `nmap_service` and external tool process integration.

- **Phase 4: Web API & Dashboard UI**
  - Implement Flask REST blueprints.
  - Build modern responsive HTML/CSS/JS frontend dashboard with SSE live logs.

- **Phase 5: Testing, Hardening & Documentation**
  - Complete unit/integration test coverage.
  - Security audit and deployment guide.
