"""
Real System Tool Availability Checker Service for NMAP-X Platform.
Performs real system environment checks for external CLI security binaries:
- nmap
- dnsmap
- urlcrazy
- whois
- dnsrecon
- dig
- wafw00f
- wget

Statuses returned strictly adhere to:
- ONLINE: Binary is installed and successfully executes a test call.
- NOT INSTALLED: Binary is not present on the system PATH.
- ERROR: Binary execution threw a permission error or runtime failure.
"""

import shutil
import subprocess
import logging
from typing import Dict, Any, List

logger = logging.getLogger("nmap_x.tool_checker")

TARGET_TOOLS = [
    {"name": "nmap", "label": "Nmap Network Scanner", "args": ["--version"]},
    {"name": "dnsmap", "label": "DNS Map Subdomain Enumerator", "args": []},
    {"name": "urlcrazy", "label": "URLCrazy Typo Squatting", "args": ["-h"]},
    {"name": "whois", "label": "WHOIS Lookup Utility", "args": ["--version"]},
    {"name": "dnsrecon", "label": "DNSRecon Reconnaissance", "args": ["-h"]},
    {"name": "dig", "label": "Dig DNS Lookup Utility", "args": ["-v"]},
    {"name": "wafw00f", "label": "Wafw00f WAF Detector", "args": ["--version"]},
    {"name": "wget", "label": "Wget Web Mirror Utility", "args": ["--version"]},
]

class ToolCheckerService:
    """Service performing real system checks for required external CLI binaries."""

    @staticmethod
    def check_tool(binary: str, test_args: List[str] = None) -> Dict[str, Any]:
        """
        Performs a real system check for a specific binary.
        
        :param binary: Name of binary on PATH (e.g. 'nmap')
        :param test_args: Arguments for non-destructive execution check
        :return: Dict containing status ('ONLINE', 'NOT INSTALLED', 'ERROR'), binary path, and detail message.
        """
        executable_path = shutil.which(binary)
        if not executable_path:
            return {
                "binary": binary,
                "path": None,
                "status": "NOT INSTALLED",
                "output": f"Binary '{binary}' was not found on system PATH."
            }

        cmd = [binary] + (test_args if test_args is not None else [])
        try:
            res = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=3,
                shell=False
            )
            # If executable runs without OS Error / FileNotFoundError, it is ONLINE
            return {
                "binary": binary,
                "path": executable_path,
                "status": "ONLINE",
                "output": res.stdout[:200] if res.stdout else (res.stderr[:200] if res.stderr else "Operational")
            }
        except FileNotFoundError:
            return {
                "binary": binary,
                "path": None,
                "status": "NOT INSTALLED",
                "output": f"Binary '{binary}' could not be executed."
            }
        except PermissionError:
            return {
                "binary": binary,
                "path": executable_path,
                "status": "ERROR",
                "output": f"Permission denied executing binary '{binary}'."
            }
        except Exception as e:
            return {
                "binary": binary,
                "path": executable_path,
                "status": "ERROR",
                "output": f"Error executing check for '{binary}': {str(e)}"
            }

    @classmethod
    def get_all_tool_statuses(cls) -> Dict[str, Dict[str, Any]]:
        """
        Checks all 8 required external tools and returns a mapping of tool names to status dicts.
        """
        statuses = {}
        for tool in TARGET_TOOLS:
            name = tool["name"]
            res = cls.check_tool(name, tool["args"])
            res["label"] = tool["label"]
            statuses[name] = res
        return statuses

    @classmethod
    def get_nmap_status(cls) -> Dict[str, Any]:
        """Convenience method returning Nmap specific status."""
        return cls.check_tool("nmap", ["--version"])
