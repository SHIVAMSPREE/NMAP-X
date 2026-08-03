"""
Real System Tool Availability & Unified Dependency Checker Service for NMAP-X Platform.
Performs real verification checks for all 13 application dependencies with tool-specific verifiers
and candidate executable path resolution across active Python Scripts directories.
"""

import os
import sys
import shutil
import subprocess
import importlib
import importlib.metadata
import logging
from typing import Dict, Any, List, Optional
from scanner.tool_installer import (
    ToolInstallerService,
    TOOL_SPEC_REGISTRY,
    UNIFIED_DEPENDENCY_REGISTRY,
    get_python_script_directories,
    ensure_all_python_script_paths_in_path,
    find_python_cli_executable,
    detect_wsl,
    check_perl_runtime
)

logger = logging.getLogger("nmap_x.tool_checker")

# Mapping of application source files to required dependencies for Source Audit
SOURCE_AUDIT_MAP = [
    {
        "file": "modules/vulnerability_scanner.py",
        "original_source": "vuln.txt",
        "dependency": "requests",
        "type": "python_package",
        "detected_code": "import requests",
        "install_method": "python -m pip install requests",
        "verify_method": "importlib.import_module('requests')"
    },
    {
        "file": "modules/vulnerability_scanner.py",
        "original_source": "vuln.txt",
        "dependency": "beautifulsoup4",
        "type": "python_package",
        "detected_code": "from bs4 import BeautifulSoup",
        "install_method": "python -m pip install beautifulsoup4",
        "verify_method": "importlib.import_module('bs4')"
    },
    {
        "file": "modules/vulnerability_scanner.py",
        "original_source": "vuln.txt",
        "dependency": "lxml",
        "type": "python_package",
        "detected_code": "BeautifulSoup(..., 'lxml')",
        "install_method": "python -m pip install lxml",
        "verify_method": "importlib.import_module('lxml')"
    },
    {
        "file": "modules/vulnerability_scanner.py",
        "original_source": "vuln.txt",
        "dependency": "rich",
        "type": "python_package",
        "detected_code": "from rich.console import Console",
        "install_method": "python -m pip install rich",
        "verify_method": "importlib.import_module('rich')"
    },
    {
        "file": "modules/vulnerability_scanner.py",
        "original_source": "vuln.txt",
        "dependency": "nikto",
        "type": "external_tool",
        "detected_code": "shutil.which('nikto')",
        "install_method": "Windows: Sysinternals/Strawberry Perl or WSL | Linux: apt install nikto",
        "verify_method": "Execution call 'nikto -Version' (requires perl.exe on Windows)"
    },
    {
        "file": "scanner/nmap_engine.py",
        "original_source": "Nmap execution engine",
        "dependency": "nmap",
        "type": "external_tool",
        "detected_code": "subprocess.run(['nmap', ...])",
        "install_method": "Windows: winget install Insecure.Nmap | Linux: apt install nmap",
        "verify_method": "Execution call 'nmap --version'"
    },
    {
        "file": "modules/enumeration.py",
        "original_source": "DNS & Domain Enumerator",
        "dependency": "dnsmap",
        "type": "external_tool",
        "detected_code": "subprocess.run(['dnsmap', ...])",
        "install_method": "WSL / Linux: apt install dnsmap",
        "verify_method": "shutil.which('dnsmap')"
    },
    {
        "file": "modules/enumeration.py",
        "original_source": "Typosquatting Engine",
        "dependency": "urlcrazy",
        "type": "external_tool",
        "detected_code": "subprocess.run(['urlcrazy', ...])",
        "install_method": "WSL / Linux: apt install urlcrazy",
        "verify_method": "Execution call 'urlcrazy -h'"
    },
    {
        "file": "modules/footprinting.py",
        "original_source": "WHOIS Lookup",
        "dependency": "whois",
        "type": "external_tool",
        "detected_code": "subprocess.run(['whois', ...])",
        "install_method": "Windows: winget install Microsoft.Sysinternals.Whois | Linux: apt install whois",
        "verify_method": "Execution call 'whois -v'"
    },
    {
        "file": "modules/enumeration.py",
        "original_source": "DNSRecon Utility",
        "dependency": "dnsrecon",
        "type": "external_tool",
        "detected_code": "subprocess.run(['dnsrecon', ...])",
        "install_method": "python -m pip install dnsrecon",
        "verify_method": "Execution call 'dnsrecon -h'"
    },
    {
        "file": "modules/enumeration.py",
        "original_source": "Dig DNS Lookup",
        "dependency": "dig",
        "type": "external_tool",
        "detected_code": "subprocess.run(['dig', ...])",
        "install_method": "Windows: winget install ISC.Bind | Linux: apt install bind9-dnsutils",
        "verify_method": "Execution call 'dig -v'"
    },
    {
        "file": "modules/footprinting.py",
        "original_source": "WAF Detection",
        "dependency": "wafw00f",
        "type": "external_tool",
        "detected_code": "subprocess.run(['wafw00f', ...])",
        "install_method": "python -m pip install wafw00f",
        "verify_method": "Execution call 'wafw00f --help'"
    },
    {
        "file": "modules/footprinting.py",
        "original_source": "Website Mirroring",
        "dependency": "wget",
        "type": "external_tool",
        "detected_code": "subprocess.run(['wget', ...])",
        "install_method": "Windows: winget install GNU.Wget | Linux: apt install wget",
        "verify_method": "Execution call 'wget --version'"
    }
]

class ToolCheckerService:
    """Service performing real system checks for required external binaries & Python packages."""

    @staticmethod
    def get_executable_path(binary: str) -> Optional[str]:
        """Resolves executable path using find_python_cli_executable."""
        return find_python_cli_executable(binary)

    @classmethod
    def check_executable(cls, binary: str) -> bool:
        """Returns True if executable path exists."""
        return cls.get_executable_path(binary) is not None

    @classmethod
    def get_version(cls, binary: str, test_args: List[str] = None) -> Optional[str]:
        """Attempts version extraction via non-destructive CLI command or package import."""
        res = cls.check_tool(binary, test_args)
        return res.get("version")

    @classmethod
    def check_python_package(cls, pkg_name: str) -> Dict[str, Any]:
        """
        Verifies Python package importability using active backend interpreter.
        Does not rely solely on pip list.
        """
        spec = TOOL_SPEC_REGISTRY.get(pkg_name, {})
        import_name = spec.get("import_name", pkg_name)
        display_label = spec.get("display_name", pkg_name)

        try:
            mod = importlib.import_module(import_name)
            pkg_ver = None
            try:
                pkg_ver = getattr(mod, "__version__", None) or importlib.metadata.version(pkg_name)
            except Exception:
                pkg_ver = "Installed"

            return {
                "binary": pkg_name,
                "label": display_label,
                "dependency_type": "python_package",
                "import_name": import_name,
                "path": getattr(mod, "__file__", sys.executable),
                "version": pkg_ver,
                "status": "ONLINE",
                "actionable_message": f"Python package '{pkg_name}' (imported as '{import_name}') is installed and operational."
            }
        except ImportError as ie:
            return {
                "binary": pkg_name,
                "label": display_label,
                "dependency_type": "python_package",
                "import_name": import_name,
                "path": None,
                "version": None,
                "status": "NOT INSTALLED",
                "actionable_message": f"Python package '{pkg_name}' is not installed in the active environment ({sys.executable}). Click 'Install' to run 'python -m pip install {pkg_name}'."
            }
        except Exception as e:
            return {
                "binary": pkg_name,
                "label": display_label,
                "dependency_type": "python_package",
                "import_name": import_name,
                "path": None,
                "version": None,
                "status": "INSTALLED BUT NOT IMPORTABLE",
                "actionable_message": f"Package '{pkg_name}' is present but import failed: {str(e)}"
            }

    @classmethod
    def check_tool(cls, binary: str, test_args: List[str] = None, label: str = "") -> Dict[str, Any]:
        """
        Performs real system check for a dependency following the tool-specific verification functions.
        """
        ensure_all_python_script_paths_in_path()
        dep_key = binary.lower().strip()
        spec = TOOL_SPEC_REGISTRY.get(dep_key, {})
        display_label = label or spec.get("display_name", binary)

        # Route Python Packages
        if spec.get("dependency_type") == "python_package":
            return cls.check_python_package(dep_key)

        is_windows = (sys.platform == "win32")

        # Special Nikto handling on Windows
        if dep_key == "nikto" and is_windows:
            perl_info = check_perl_runtime()
            if not perl_info["available"]:
                msg = spec.get("actionable_win_note") or "Nikto requires Perl runtime on Windows. Install Strawberry Perl or use WSL."
                return {
                    "binary": dep_key,
                    "label": display_label,
                    "dependency_type": "external_tool",
                    "path": None,
                    "version": None,
                    "status": "RUNTIME MISSING",
                    "actionable_message": msg,
                    "output": msg
                }

        # Check if natively unsupported on Windows
        if is_windows and spec.get("win_native") == "Unsupported":
            wsl_info = detect_wsl()
            wsl_note = f" (WSL is available at {wsl_info['path']})" if wsl_info.get("available") else " (WSL is not currently detected)."
            msg = (spec.get("unsupported_reason") or spec.get("actionable_win_note", "")) + wsl_note
            return {
                "binary": dep_key,
                "label": display_label,
                "dependency_type": "external_tool",
                "path": None,
                "version": None,
                "status": "UNSUPPORTED ON OS",
                "actionable_message": msg,
                "output": msg
            }

        executable_path = cls.get_executable_path(dep_key)
        if not executable_path:
            msg = f"{display_label} is not installed. Click 'Install' to install the supported dependency for this environment."
            if is_windows and spec.get("actionable_win_note"):
                msg += f" Note: {spec['actionable_win_note']}"

            return {
                "binary": dep_key,
                "label": display_label,
                "dependency_type": "external_tool",
                "path": None,
                "version": None,
                "status": "NOT INSTALLED",
                "actionable_message": msg,
                "output": f"Binary '{dep_key}' was not found on system PATH."
            }

        # Executable exists: Execute tool-specific verification command
        ver_args = test_args if test_args is not None else spec.get("version_check_command", [])
        cmd = [executable_path] + ver_args
        if is_windows and dep_key == "nikto" and executable_path.endswith(".pl"):
            perl_exe = shutil.which("perl")
            if perl_exe:
                cmd = [perl_exe, executable_path, "-Version"]

        try:
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5, shell=False)
            raw_out = (res.stdout or res.stderr or "").strip()
            version_str = raw_out.splitlines()[0][:100] if raw_out else "Installed & Operational"

            return {
                "binary": dep_key,
                "label": display_label,
                "dependency_type": "external_tool",
                "path": executable_path,
                "version": version_str,
                "status": "ONLINE",
                "actionable_message": f"{display_label} is installed and operational at '{executable_path}'.",
                "output": raw_out[:200] if raw_out else "Operational"
            }
        except Exception as e:
            return {
                "binary": dep_key,
                "label": display_label,
                "dependency_type": "external_tool",
                "path": executable_path,
                "version": None,
                "status": "INSTALLED BUT EXECUTION FAILED",
                "actionable_message": f"Executable found at '{executable_path}', but execution call failed: {str(e)}",
                "output": f"Error executing check for '{dep_key}': {str(e)}"
            }

    @classmethod
    def get_all_tool_statuses(cls) -> Dict[str, Dict[str, Any]]:
        """Checks all 13 required dependencies and returns mapping of names to status dicts."""
        statuses = {}
        for dep_key, spec in TOOL_SPEC_REGISTRY.items():
            if spec.get("dependency_type") == "python_package":
                res = cls.check_python_package(dep_key)
            else:
                res = cls.check_tool(dep_key, spec.get("version_check_command"), label=spec["display_name"])
            statuses[dep_key] = res
        return statuses

    @classmethod
    def get_application_source_audit(cls) -> List[Dict[str, Any]]:
        """Scans codebase audit map and evaluates real current status of each requirement."""
        audit_results = []
        for item in SOURCE_AUDIT_MAP:
            dep_key = item["dependency"]
            if item["type"] == "python_package":
                status_info = cls.check_python_package(dep_key)
            else:
                spec = TOOL_SPEC_REGISTRY.get(dep_key, {})
                status_info = cls.check_tool(dep_key, spec.get("version_check_command", []), label=item.get("dependency"))

            audit_results.append({
                "file": item["file"],
                "original_source": item["original_source"],
                "dependency": dep_key,
                "type": item["type"],
                "detected_code": item["detected_code"],
                "install_method": item["install_method"],
                "verify_method": item["verify_method"],
                "status": status_info["status"],
                "version": status_info.get("version"),
                "path": status_info.get("path"),
                "actionable_message": status_info.get("actionable_message")
            })
        return audit_results

    @classmethod
    def get_nmap_status(cls) -> Dict[str, Any]:
        """Convenience method returning Nmap specific status."""
        return cls.check_tool("nmap", ["--version"], label="Nmap Network Scanner")

    @staticmethod
    def get_environment_telemetry() -> Dict[str, Any]:
        """Returns Python environment diagnostics telemetry from ToolInstallerService."""
        return ToolInstallerService.detect_environment()
