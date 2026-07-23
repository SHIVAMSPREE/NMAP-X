"""
Domain Enumeration Service Module for NMAP-X Platform.
Converts ENUMERATION.txt into a safe, modular Python service.
Supports:
1. Subdomain Enumeration (dnsmap)
2. Domain Variation Checking (urlcrazy)
3. WHOIS (whois)
4. DNS Enumeration (dnsrecon)
5. DNS Zone Transfer Checks (dig AXFR)

Uses safe subprocess execution without shell=True, checks binary availability, and returns structured result objects.
"""

import shutil
import subprocess
import logging
from typing import List, Dict, Any, Optional
from scanner.validators import validate_domain, ValidationError

logger = logging.getLogger("nmap_x.enumeration")

REQUIRED_TOOLS = {
    'dnsmap': 'dnsmap',
    'urlcrazy': 'urlcrazy',
    'whois': 'whois',
    'dnsrecon': 'dnsrecon',
    'dig': 'dig'
}

from scanner.security_config import MAX_OUTPUT_SIZE_BYTES

class EnumerationService:
    """
    Service executing domain enumeration tools.
    """

    def __init__(self, timeout: int = 120):
        self.timeout = timeout

    @staticmethod
    def check_tool_availability(tool_name: str) -> bool:
        """Checks if an external binary tool is available on the system PATH."""
        binary = REQUIRED_TOOLS.get(tool_name, tool_name)
        return shutil.which(binary) is not None

    def _run_process(self, cmd_vector: List[str]) -> Dict[str, Any]:
        """Runs a command vector safely using subprocess without shell=True."""
        binary = cmd_vector[0]
        if not self.check_tool_availability(binary):
            return {
                "success": False,
                "status": "NOT_INSTALLED",
                "output": "",
                "error": f"Tool '{binary}' is not installed or not found on system PATH."
            }

        try:
            res = subprocess.run(
                cmd_vector,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=self.timeout,
                shell=False
            )
            stdout = (res.stdout or "")[:MAX_OUTPUT_SIZE_BYTES]
            stderr = (res.stderr or "")[:MAX_OUTPUT_SIZE_BYTES]
            status = "SUCCESS" if res.returncode == 0 else "ERROR"
            
            return {
                "success": res.returncode == 0,
                "status": status,
                "return_code": res.returncode,
                "output": stdout or stderr,
                "stderr": stderr,
                "error": None if res.returncode == 0 else f"Process exited with code {res.returncode}."
            }
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "status": "TIMEOUT",
                "output": "",
                "error": f"Execution of '{binary}' timed out after {self.timeout} seconds."
            }
        except PermissionError:
            return {
                "success": False,
                "status": "PERMISSION_DENIED",
                "output": "",
                "error": f"Permission denied executing binary '{binary}'."
            }
        except Exception as e:
            return {
                "success": False,
                "status": "ERROR",
                "output": "",
                "error": f"Unexpected failure running '{binary}': {str(e)}"
            }

    def run_subdomain_enum(self, domain: str) -> Dict[str, Any]:
        """Runs dnsmap <domain>."""
        valid_domain = validate_domain(domain)
        return self._run_process(["dnsmap", valid_domain])

    def run_urlcrazy(self, domain: str) -> Dict[str, Any]:
        """Runs urlcrazy -p <domain>."""
        valid_domain = validate_domain(domain)
        return self._run_process(["urlcrazy", "-p", valid_domain])

    def run_whois(self, domain: str) -> Dict[str, Any]:
        """Runs whois <domain>."""
        valid_domain = validate_domain(domain)
        return self._run_process(["whois", valid_domain])

    def run_dnsrecon(self, domain: str) -> Dict[str, Any]:
        """Runs dnsrecon -d <domain>."""
        valid_domain = validate_domain(domain)
        return self._run_process(["dnsrecon", "-d", valid_domain])

    def run_zone_transfer(self, domain: str) -> Dict[str, Any]:
        """Performs DNS NS lookup and dig AXFR zone transfer checks."""
        valid_domain = validate_domain(domain)
        
        # 1. Fetch Name Servers using dig
        ns_res = self._run_process(["dig", "NS", valid_domain, "+short"])
        if not ns_res["success"] and ns_res["status"] == "NOT_INSTALLED":
            return ns_res

        nameservers = [ns.strip().rstrip('.') for ns in ns_res["output"].splitlines() if ns.strip()]
        
        if not nameservers:
            return {
                "success": True,
                "status": "SUCCESS",
                "output": f"No nameservers found for domain {valid_domain}.",
                "zone_transfers": []
            }

        combined_output = []
        transfer_results = []

        for ns in nameservers:
            combined_output.append(f"--- Trying Zone Transfer against NS: {ns} ---")
            axfr_res = self._run_process(["dig", "AXFR", valid_domain, f"@{ns}"])
            out = axfr_res.get("output", "")
            combined_output.append(out)
            transfer_results.append({
                "nameserver": ns,
                "status": axfr_res["status"],
                "output": out
            })

        return {
            "success": True,
            "status": "SUCCESS",
            "output": "\n".join(combined_output),
            "zone_transfers": transfer_results
        }

    def run_selected_enumeration(self, domain: str, selected_modules: List[str]) -> Dict[str, Any]:
        """
        Executes selected enumeration modules for a given domain.
        
        :param domain: Target domain string (e.g. example.com)
        :param selected_modules: List of modules ['dnsmap', 'urlcrazy', 'whois', 'dnsrecon', 'zone_transfer']
        :return: Combined enumeration report dictionary
        """
        valid_domain = validate_domain(domain)
        results = {}
        missing_tools = []

        # Check binary availability for selected modules first
        module_tool_map = {
            'dnsmap': 'dnsmap',
            'urlcrazy': 'urlcrazy',
            'whois': 'whois',
            'dnsrecon': 'dnsrecon',
            'zone_transfer': 'dig'
        }

        for mod in selected_modules:
            tool = module_tool_map.get(mod)
            if tool and not self.check_tool_availability(tool):
                missing_tools.append(f"{mod} ({tool})")

        # Execute only user-selected modules
        if 'dnsmap' in selected_modules:
            results['dnsmap'] = self.run_subdomain_enum(valid_domain)
        if 'urlcrazy' in selected_modules:
            results['urlcrazy'] = self.run_urlcrazy(valid_domain)
        if 'whois' in selected_modules:
            results['whois'] = self.run_whois(valid_domain)
        if 'dnsrecon' in selected_modules:
            results['dnsrecon'] = self.run_dnsrecon(valid_domain)
        if 'zone_transfer' in selected_modules:
            results['zone_transfer'] = self.run_zone_transfer(valid_domain)

        # Build combined summary report
        combined_report_lines = [
            "=================================================",
            f"   ENUMERATION REPORT FOR: {valid_domain}",
            "=================================================\n"
        ]

        for mod, res in results.items():
            combined_report_lines.append(f"[{mod.upper()}] Status: {res.get('status')}")
            if res.get('error'):
                combined_report_lines.append(f"Error: {res.get('error')}")
            combined_report_lines.append(res.get('output', 'No output recorded.'))
            combined_report_lines.append("\n" + "-"*45 + "\n")

        return {
            "domain": valid_domain,
            "selected_modules": selected_modules,
            "missing_tools": missing_tools,
            "module_results": results,
            "combined_report": "\n".join(combined_report_lines)
        }
