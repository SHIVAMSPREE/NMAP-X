"""
Website Footprinting & Web Reconnaissance Service for NMAP-X Platform.
Refactors WEBSITE FOOTPRINTING.txt into a safe, modular Python service.

Operations supported:
1. WHOIS
2. DNS/IP Resolution
3. HTML Analysis (bs4)
4. HTTP Headers Inspection
5. Server Technology Identification
6. Sitemap Discovery
7. Metadata Extraction
8. WAF Detection (wafw00f)
9. Load Balancer Detection
10. HTTP OPTIONS Discovery
11. Banner Grabbing (socket)
12. Common Directory Enumeration
13. Proxy Functionality Testing
14. Website Mirroring / Crawling (wget - requires explicit user opt-in)
"""

import socket
import subprocess
import shutil
import logging
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup
from scanner.validators import validate_url, validate_target_host, ValidationError

logger = logging.getLogger("nmap_x.footprinting")

class WebFootprintingService:
    """
    Service executing modular web footprinting and HTTP reconnaissance tasks.
    Enforces response timeouts, stream size limits, and safe execution.
    """

    def __init__(self, default_timeout: int = 10, max_response_size: int = 1024 * 1024):
        self.timeout = default_timeout
        self.max_response_size = max_response_size

    def _extract_domain(self, url: str) -> str:
        parsed = urlparse(url)
        host = parsed.netloc or parsed.path
        return host.split(":")[0]

    def _fetch_url_response(self, url: str, method: str = "GET", custom_headers: dict = None, proxies: dict = None) -> tuple[int, dict, str]:
        """
        Executes HTTP request with stream=True, enforcing maximum response size limit and timeouts.
        Returns tuple of (status_code, headers_dict, text_content).
        """
        headers = {"User-Agent": "NMAP-X-Scanner/1.0"}
        if custom_headers:
            headers.update(custom_headers)

        if method.upper() == "OPTIONS":
            r = requests.options(url, timeout=self.timeout, headers=headers, proxies=proxies, stream=True)
        else:
            r = requests.get(url, timeout=self.timeout, headers=headers, proxies=proxies, stream=True)

        content_bytes = bytearray()
        try:
            chunks = r.iter_content(chunk_size=8192)
            if chunks:
                for chunk in chunks:
                    if chunk:
                        content_bytes.extend(chunk)
                        if len(content_bytes) >= self.max_response_size:
                            break
        except Exception:
            pass

        text = content_bytes.decode('utf-8', errors='ignore') if content_bytes else getattr(r, 'text', '')
        return r.status_code, dict(r.headers), text

    def run_whois(self, url: str) -> Dict[str, Any]:
        """Runs WHOIS query on the domain of the given URL."""
        domain = self._extract_domain(url)
        if not shutil.which("whois"):
            return {"status": "NOT_INSTALLED", "output": "Tool 'whois' is not installed on system PATH."}

        try:
            res = subprocess.run(["whois", domain], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=self.timeout, shell=False)
            output = (res.stdout or res.stderr or "")[:self.max_response_size]
            return {"status": "SUCCESS" if res.returncode == 0 else "ERROR", "output": output}
        except Exception as e:
            return {"status": "ERROR", "output": f"WHOIS query failed: {str(e)}"}

    def run_dns_resolution(self, url: str) -> Dict[str, Any]:
        """Resolves target hostname to IPv4 address."""
        domain = self._extract_domain(url)
        try:
            ip = socket.gethostbyname(domain)
            return {"status": "SUCCESS", "ip": ip, "output": f"Resolved {domain} to IP: {ip}"}
        except Exception as e:
            return {"status": "ERROR", "output": f"DNS resolution failed for {domain}: {str(e)}"}

    def run_html_analysis(self, url: str) -> Dict[str, Any]:
        """Fetches HTML and extracts prettified snippet and page title."""
        try:
            status_code, headers, text = self._fetch_url_response(url)
            soup = BeautifulSoup(text, "html.parser")
            title = soup.title.string if soup.title else "No Title"
            snippet = soup.prettify()[:2000]
            return {"status": "SUCCESS", "title": title, "output": f"Page Title: {title}\n\nHTML Snippet:\n{snippet}"}
        except Exception as e:
            return {"status": "ERROR", "output": f"HTML analysis failed: {str(e)}"}

    def run_http_headers(self, url: str) -> Dict[str, Any]:
        """Inspects HTTP response headers."""
        try:
            status_code, headers, text = self._fetch_url_response(url)
            headers_str = "\n".join([f"{k}: {v}" for k, v in headers.items()])
            return {"status": "SUCCESS", "headers": headers, "output": headers_str}
        except Exception as e:
            return {"status": "ERROR", "output": f"HTTP header inspection failed: {str(e)}"}

    def run_server_tech(self, url: str) -> Dict[str, Any]:
        """Identifies Server and X-Powered-By response headers."""
        try:
            status_code, headers, text = self._fetch_url_response(url)
            server = headers.get("Server", "Unknown")
            powered_by = headers.get("X-Powered-By", "Unknown")
            return {
                "status": "SUCCESS",
                "server": server,
                "x_powered_by": powered_by,
                "output": f"Server: {server}\nX-Powered-By: {powered_by}"
            }
        except Exception as e:
            return {"status": "ERROR", "output": f"Server technology identification failed: {str(e)}"}

    def run_sitemap_discovery(self, url: str) -> Dict[str, Any]:
        """Discovers sitemap.xml."""
        sitemap_url = url.rstrip("/") + "/sitemap.xml"
        try:
            status_code, headers, text = self._fetch_url_response(sitemap_url)
            if status_code == 200:
                return {"status": "SUCCESS", "found": True, "output": text[:2000]}
            else:
                return {"status": "SUCCESS", "found": False, "output": f"No sitemap found at {sitemap_url} (HTTP Status {status_code})."}
        except Exception as e:
            return {"status": "ERROR", "output": f"Sitemap discovery failed: {str(e)}"}

    def run_metadata_extraction(self, url: str) -> Dict[str, Any]:
        """Extracts HTML meta tags."""
        try:
            status_code, headers, text = self._fetch_url_response(url)
            soup = BeautifulSoup(text, "html.parser")
            metas = soup.find_all("meta")
            meta_str = "\n".join([str(m) for m in metas]) if metas else "No <meta> tags identified."
            return {"status": "SUCCESS", "output": meta_str}
        except Exception as e:
            return {"status": "ERROR", "output": f"Metadata extraction failed: {str(e)}"}

    def run_waf_detection(self, url: str) -> Dict[str, Any]:
        """Runs wafw00f WAF detection."""
        if not shutil.which("wafw00f"):
            return {"status": "NOT_INSTALLED", "output": "Tool 'wafw00f' is not installed on system PATH."}

        try:
            res = subprocess.run(["wafw00f", url], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=self.timeout, shell=False)
            output = (res.stdout or res.stderr or "")[:self.max_response_size]
            return {"status": "SUCCESS" if res.returncode == 0 else "ERROR", "output": output}
        except Exception as e:
            return {"status": "ERROR", "output": f"WAF detection failed: {str(e)}"}

    def run_load_balancer(self, url: str) -> Dict[str, Any]:
        """Detects cookie drift across multiple requests."""
        try:
            st1, h1, t1 = self._fetch_url_response(url)
            st2, h2, t2 = self._fetch_url_response(url)
            c1 = h1.get("Set-Cookie")
            c2 = h2.get("Set-Cookie")
            
            is_lb = (c1 != c2) and (c1 is not None or c2 is not None)
            res_str = "Possible Load Balancer / Session Cookie Drift detected." if is_lb else "No Set-Cookie header drift detected across requests."
            return {"status": "SUCCESS", "load_balancer_detected": is_lb, "output": res_str}
        except Exception as e:
            return {"status": "ERROR", "output": f"Load balancer check failed: {str(e)}"}

    def run_http_options(self, url: str) -> Dict[str, Any]:
        """Discovers supported HTTP verbs via OPTIONS request."""
        try:
            st, headers, text = self._fetch_url_response(url, method="OPTIONS")
            allowed = headers.get("Allow", headers.get("Public", "Not Specified"))
            return {"status": "SUCCESS", "allow": allowed, "output": f"HTTP OPTIONS Response Headers:\n{str(headers)}"}
        except Exception as e:
            return {"status": "ERROR", "output": f"HTTP OPTIONS discovery failed: {str(e)}"}

    def run_banner_grabbing(self, url: str) -> Dict[str, Any]:
        """Performs raw socket banner grabbing on port 80."""
        domain = self._extract_domain(url)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect((domain, 80))
            s.send(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = s.recv(1024).decode('utf-8', errors='ignore')
            s.close()
            return {"status": "SUCCESS", "banner": banner, "output": banner or "No banner data received."}
        except Exception as e:
            return {"status": "ERROR", "output": f"Socket banner grabbing failed: {str(e)}"}

    def run_directory_enum(self, url: str) -> Dict[str, Any]:
        """Checks for common public web directories."""
        common_dirs = ["admin", "login", "uploads", "images", "css", "js", "api", "dashboard"]
        found = []
        base_url = url.rstrip("/")
        
        for d in common_dirs:
            test_url = f"{base_url}/{d}"
            try:
                status_code, headers, text = self._fetch_url_response(test_url)
                if status_code == 200:
                    found.append(test_url)
            except Exception:
                continue

        out_str = f"Directories Found:\n" + "\n".join(found) if found else "No common directories returned HTTP 200 OK."
        return {"status": "SUCCESS", "found_directories": found, "output": out_str}

    def run_proxy_test(self, url: str, proxy_url: str = "http://127.0.0.1:8080") -> Dict[str, Any]:
        """Tests HTTP requests via specified proxy endpoint."""
        try:
            proxies = {"http": proxy_url, "https": proxy_url}
            status_code, headers, text = self._fetch_url_response(url, proxies=proxies)
            return {"status": "SUCCESS", "output": f"Proxy test succeeded via {proxy_url}. Status Code: {status_code}"}
        except Exception as e:
            return {"status": "ERROR", "output": f"Proxy test failed via {proxy_url}: {str(e)}"}

    def run_website_mirroring(self, url: str, explicit_opt_in: bool = False) -> Dict[str, Any]:
        """
        Website Mirroring / Crawling using wget.
        Requires explicit user opt-in flag.
        """
        if not explicit_opt_in:
            return {
                "status": "REQUIRES_OPT_IN",
                "output": "Website mirroring requires explicit user confirmation. Check the opt-in box before running website mirroring."
            }

        if not shutil.which("wget"):
            return {"status": "NOT_INSTALLED", "output": "Tool 'wget' is not installed on system PATH."}

        try:
            cmd = ["wget", "--mirror", "--convert-links", "--adjust-extension", "--page-requisites", "--no-parent", "--quota=5m", url]
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=60, shell=False)
            output = (res.stdout or res.stderr or "")[:self.max_response_size]
            return {"status": "SUCCESS" if res.returncode == 0 else "ERROR", "output": output or "Website mirrored with quota limits."}
        except Exception as e:
            return {"status": "ERROR", "output": f"Website mirroring failed: {str(e)}"}

    def run_selected_footprinting(self, url: str, selected_operations: List[str], mirror_opt_in: bool = False) -> Dict[str, Any]:
        """
        Executes selected footprinting operations for a given URL.
        """
        valid_url = validate_url(url)
        results = {}

        operation_map = {
            'whois': self.run_whois,
            'dns': self.run_dns_resolution,
            'html': self.run_html_analysis,
            'headers': self.run_http_headers,
            'server_tech': self.run_server_tech,
            'sitemap': self.run_sitemap_discovery,
            'metadata': self.run_metadata_extraction,
            'waf': self.run_waf_detection,
            'load_balancer': self.run_load_balancer,
            'options': self.run_http_options,
            'banner': self.run_banner_grabbing,
            'directory_enum': self.run_directory_enum,
            'proxy': self.run_proxy_test,
        }

        for op in selected_operations:
            if op == 'mirror':
                results['mirror'] = self.run_website_mirroring(valid_url, explicit_opt_in=mirror_opt_in)
            elif op in operation_map:
                results[op] = operation_map[op](valid_url)

        combined_report_lines = [
            "=================================================",
            f"   WEBSITE FOOTPRINTING REPORT FOR: {valid_url}",
            "=================================================\n"
        ]

        for op, res in results.items():
            combined_report_lines.append(f"[{op.upper()}] Status: {res.get('status')}")
            combined_report_lines.append(res.get('output', 'No output recorded.'))
            combined_report_lines.append("\n" + "-"*45 + "\n")

        return {
            "url": valid_url,
            "selected_operations": selected_operations,
            "operation_results": results,
            "combined_report": "\n".join(combined_report_lines)
        }
