"""
Tool-Specific Installation Registry & Python CLI Detection Engine for NMAP-X Platform.
Provides candidate search across sys.prefix, sys.base_prefix, site.getuserbase(), and VIRTUAL_ENV;
winget exit code 2316632107 re-verification; state machine flow; and strict execution verification.
"""

import os
import sys
import shutil
import site
import platform
import subprocess
import importlib
import importlib.metadata
import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger("nmap_x.tool_installer")

def get_python_script_directories() -> List[str]:
    """
    Returns all candidate Python script directories for the active backend Python interpreter.
    Inspects sys.prefix, sys.exec_prefix, sys.base_prefix, site.getuserbase(), VIRTUAL_ENV, and sys.executable dir.
    """
    candidates = []

    # 1. Active sys.prefix Scripts/bin
    if hasattr(sys, 'prefix') and sys.prefix:
        candidates.append(os.path.join(sys.prefix, 'Scripts' if sys.platform == 'win32' else 'bin'))

    # 2. sys.exec_prefix Scripts/bin
    if hasattr(sys, 'exec_prefix') and sys.exec_prefix:
        candidates.append(os.path.join(sys.exec_prefix, 'Scripts' if sys.platform == 'win32' else 'bin'))

    # 3. sys.base_prefix Scripts/bin
    if hasattr(sys, 'base_prefix') and sys.base_prefix:
        candidates.append(os.path.join(sys.base_prefix, 'Scripts' if sys.platform == 'win32' else 'bin'))

    # 4. Virtual environment Scripts/bin
    venv = os.environ.get('VIRTUAL_ENV')
    if venv:
        candidates.append(os.path.join(venv, 'Scripts' if sys.platform == 'win32' else 'bin'))

    # 5. User Base Scripts
    try:
        user_base = site.getuserbase()
        if user_base:
            candidates.append(os.path.join(user_base, 'Scripts' if sys.platform == 'win32' else 'bin'))
    except Exception:
        pass

    # 6. Windows AppData Roaming Python Scripts
    if sys.platform == 'win32':
        py_ver_short = f"{sys.version_info.major}{sys.version_info.minor}"
        candidates.append(os.path.expanduser(rf"~\AppData\Roaming\Python\Python{py_ver_short}\Scripts"))

    # 7. sys.executable directory
    candidates.append(os.path.dirname(sys.executable))

    # Filter unique existing directories
    existing = []
    for d in candidates:
        if d and os.path.exists(d) and d not in existing:
            existing.append(d)

    return existing

def ensure_all_python_script_paths_in_path() -> List[str]:
    """Prepends all candidate Python script directories to runtime process os.environ['PATH']."""
    dirs = get_python_script_directories()
    current_path = os.environ.get('PATH', '')
    path_list = current_path.split(os.pathsep)
    added = []

    for d in dirs:
        if d not in path_list:
            os.environ['PATH'] = d + os.pathsep + os.environ['PATH']
            path_list.insert(0, d)
            added.append(d)

    return added

# Execute PATH injection immediately when module is loaded
ensure_all_python_script_paths_in_path()

def find_python_cli_executable(binary_name: str) -> Optional[str]:
    """
    Searches all candidate Python script directories for the CLI executable or script launcher.
    Checks: <name>.exe, <name>-script.py, <name>.py, <name>.bat, <name>.cmd, <name>
    """
    ensure_all_python_script_paths_in_path()

    # First check shutil.which
    found = shutil.which(binary_name)
    if found:
        return found

    dirs = get_python_script_directories()
    extensions = [".exe", "-script.py", ".py", ".bat", ".cmd", ""] if sys.platform == "win32" else ["", ".py"]

    for d in dirs:
        for ext in extensions:
            candidate = os.path.join(d, binary_name + ext)
            if os.path.exists(candidate) and os.path.isfile(candidate):
                if d not in os.environ.get("PATH", "").split(os.pathsep):
                    os.environ["PATH"] = d + os.pathsep + os.environ["PATH"]
                return candidate

    return None

def detect_wsl() -> Dict[str, Any]:
    """Detects whether Windows Subsystem for Linux (WSL) is available."""
    wsl_path = shutil.which("wsl")
    if not wsl_path:
        return {"available": False, "details": "wsl.exe not found on system PATH."}

    try:
        res = subprocess.run(
            [wsl_path, "--status"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5,
            shell=False
        )
        is_ok = (res.returncode == 0)
        return {
            "available": is_ok,
            "path": wsl_path,
            "details": res.stdout.strip() if res.stdout else ("WSL available" if is_ok else "WSL status return code non-zero.")
        }
    except Exception as e:
        return {"available": False, "details": f"Error querying WSL: {str(e)}"}

def check_perl_runtime() -> Dict[str, Any]:
    """Detects Perl runtime availability for Nikto on Windows/Linux."""
    perl_path = shutil.which("perl")
    if not perl_path:
        return {"available": False, "path": None, "version": None, "details": "perl.exe not found on system PATH."}

    try:
        res = subprocess.run(
            [perl_path, "-v"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=4,
            shell=False
        )
        out = (res.stdout or res.stderr or "").strip()
        first_line = out.splitlines()[0][:100] if out else "Perl Operational"
        return {
            "available": res.returncode == 0,
            "path": perl_path,
            "version": first_line,
            "details": f"Perl runtime found at {perl_path}"
        }
    except Exception as e:
        return {"available": False, "path": perl_path, "version": None, "details": f"Error checking Perl: {str(e)}"}

def format_exit_code(code: int) -> str:
    """Formats integer exit code into decimal and hexadecimal string."""
    if code is None:
        return "N/A"
    if code < 0:
        return f"{code} (Signal {-code})"
    hex_val = hex(code & 0xFFFFFFFF).upper().replace("0X", "0x")
    return f"{code} ({hex_val})"

# Detailed Tool Specification Registry
TOOL_SPEC_REGISTRY: Dict[str, Dict[str, Any]] = {
    "nmap": {
        "display_name": "Nmap Network Scanner",
        "executable_name": "nmap",
        "dependency_type": "external_tool",
        "supported_platforms": ["win32", "linux", "darwin"],
        "win_native": "Supported",
        "installation_method": "winget",
        "package_name": "Insecure.Nmap",
        "package_manager": "winget",
        "candidate_executable_paths": [r"C:\Program Files (x86)\Nmap\nmap.exe", r"C:\Program Files\Nmap\nmap.exe"],
        "version_check_command": ["--version"],
        "unsupported_reason": None,
        "win_install": ["winget", "install", "--id", "Insecure.Nmap", "-e", "--accept-source-agreements", "--accept-package-agreements"],
        "linux_install": ["apt-get", "install", "-y", "nmap"],
        "actionable_win_note": "Install Nmap via Nmap.org official Windows installer or winget."
    },
    "dnsmap": {
        "display_name": "DNS Map Subdomain Enumerator",
        "executable_name": "dnsmap",
        "dependency_type": "external_tool",
        "supported_platforms": ["linux", "wsl"],
        "win_native": "Unsupported",
        "installation_method": "wsl",
        "package_name": "dnsmap",
        "package_manager": "apt-get",
        "candidate_executable_paths": [],
        "version_check_command": [],
        "unsupported_reason": "DNSMap is not available through Windows package managers and is supported through Linux/WSL.",
        "win_install": None,
        "linux_install": ["apt-get", "install", "-y", "dnsmap"],
        "actionable_win_note": "DNSMap is supported through Linux/WSL. Run 'sudo apt install dnsmap' inside WSL."
    },
    "urlcrazy": {
        "display_name": "URLCrazy Typo Squatting",
        "executable_name": "urlcrazy",
        "dependency_type": "external_tool",
        "supported_platforms": ["linux", "wsl"],
        "win_native": "Unsupported",
        "installation_method": "wsl",
        "package_name": "urlcrazy",
        "package_manager": "apt-get",
        "candidate_executable_paths": [],
        "version_check_command": ["-h"],
        "unsupported_reason": "URLCrazy is a Ruby security tool that is not natively supported through current Windows installation flow and is supported through Linux/WSL.",
        "win_install": None,
        "linux_install": ["apt-get", "install", "-y", "urlcrazy"],
        "actionable_win_note": "URLCrazy is supported through Linux/WSL. Install inside WSL ('sudo apt install urlcrazy')."
    },
    "whois": {
        "display_name": "WHOIS Lookup Utility",
        "executable_name": "whois",
        "dependency_type": "external_tool",
        "supported_platforms": ["win32", "linux", "wsl"],
        "win_native": "Check Package Manager",
        "installation_method": "winget",
        "package_name": "Microsoft.Sysinternals.Whois",
        "package_manager": "winget",
        "candidate_executable_paths": [],
        "version_check_command": ["-v"],
        "unsupported_reason": None,
        "win_install": ["winget", "install", "--id", "Microsoft.Sysinternals.Whois", "-e", "--accept-source-agreements", "--accept-package-agreements"],
        "linux_install": ["apt-get", "install", "-y", "whois"],
        "actionable_win_note": "Install Sysinternals WHOIS on Windows ('winget install Microsoft.Sysinternals.Whois') or use WSL whois. Note: Python 'python-whois' is a library, not CLI binary."
    },
    "dnsrecon": {
        "display_name": "DNSRecon Reconnaissance",
        "executable_name": "dnsrecon",
        "dependency_type": "external_tool",
        "supported_platforms": ["win32", "linux", "wsl"],
        "win_native": "Supported",
        "installation_method": "pip",
        "package_name": "dnsrecon",
        "package_manager": "pip",
        "candidate_executable_paths": [os.path.join(d, "dnsrecon.exe") for d in get_python_script_directories()],
        "version_check_command": ["-h"],
        "unsupported_reason": None,
        "win_install": [sys.executable, "-m", "pip", "install", "dnsrecon"],
        "linux_install": [sys.executable, "-m", "pip", "install", "dnsrecon"],
        "actionable_win_note": "Python CLI tool. Installs via active Python interpreter into Python Scripts directory."
    },
    "dig": {
        "display_name": "Dig DNS Lookup Utility",
        "executable_name": "dig",
        "dependency_type": "external_tool",
        "supported_platforms": ["win32", "linux", "wsl"],
        "win_native": "Check Package Manager",
        "installation_method": "winget",
        "package_name": "ISC.Bind",
        "package_manager": "winget",
        "candidate_executable_paths": [],
        "version_check_command": ["-v"],
        "unsupported_reason": None,
        "win_install": ["winget", "install", "--id", "ISC.Bind", "-e", "--accept-source-agreements", "--accept-package-agreements"],
        "linux_install": ["apt-get", "install", "-y", "bind9-dnsutils"],
        "actionable_win_note": "Dig is available through BIND. Install ISC BIND ('winget install ISC.Bind') or use WSL dig ('sudo apt install bind9-dnsutils')."
    },
    "wafw00f": {
        "display_name": "Wafw00f WAF Detector",
        "executable_name": "wafw00f",
        "dependency_type": "external_tool",
        "supported_platforms": ["win32", "linux", "wsl"],
        "win_native": "Supported",
        "installation_method": "pip",
        "package_name": "wafw00f",
        "package_manager": "pip",
        "candidate_executable_paths": [os.path.join(d, "wafw00f.exe") for d in get_python_script_directories()],
        "version_check_command": ["--help"],
        "unsupported_reason": None,
        "win_install": [sys.executable, "-m", "pip", "install", "wafw00f"],
        "linux_install": [sys.executable, "-m", "pip", "install", "wafw00f"],
        "actionable_win_note": "Python CLI tool. Installs via active Python interpreter into Python Scripts directory."
    },
    "wget": {
        "display_name": "Wget Web Mirror Utility",
        "executable_name": "wget",
        "dependency_type": "external_tool",
        "supported_platforms": ["win32", "linux", "wsl"],
        "win_native": "Check Package Manager",
        "installation_method": "winget",
        "package_name": "GNU.Wget",
        "package_manager": "winget",
        "candidate_executable_paths": [],
        "version_check_command": ["--version"],
        "unsupported_reason": None,
        "win_install": ["winget", "install", "--id", "GNU.Wget", "-e", "--accept-source-agreements", "--accept-package-agreements"],
        "linux_install": ["apt-get", "install", "-y", "wget"],
        "actionable_win_note": "Install GNU Wget on Windows ('winget install GNU.Wget' or 'choco install wget') or use WSL wget."
    },
    "nikto": {
        "display_name": "Nikto Vulnerability Scanner",
        "executable_name": "nikto",
        "dependency_type": "external_tool",
        "supported_platforms": ["win32", "linux", "wsl"],
        "win_native": "Requires Perl Runtime",
        "installation_method": "manual",
        "package_name": "nikto",
        "package_manager": "apt-get",
        "candidate_executable_paths": [],
        "version_check_command": ["-Version"],
        "unsupported_reason": None,
        "win_install": None,
        "linux_install": ["apt-get", "install", "-y", "nikto"],
        "actionable_win_note": "Nikto requires Perl runtime on Windows. Prerequisite chain: 1) Install Strawberry Perl (strawberryperl.com) -> 2) Download Nikto -> 3) Verify nikto/perl path -> 4) Verify execution."
    },

    # Python Packages
    "requests": {
        "display_name": "Requests HTTP Library",
        "executable_name": None,
        "dependency_type": "python_package",
        "import_name": "requests",
        "supported_platforms": ["win32", "linux", "darwin"],
        "win_native": "Supported",
        "installation_method": "pip",
        "package_name": "requests",
        "package_manager": "pip",
        "pip_install": [sys.executable, "-m", "pip", "install", "requests"],
        "actionable_win_note": "Python HTTP package. Installs via active Python interpreter: python -m pip install requests."
    },
    "beautifulsoup4": {
        "display_name": "BeautifulSoup4 HTML Parser",
        "executable_name": None,
        "dependency_type": "python_package",
        "import_name": "bs4",
        "supported_platforms": ["win32", "linux", "darwin"],
        "win_native": "Supported",
        "installation_method": "pip",
        "package_name": "beautifulsoup4",
        "package_manager": "pip",
        "pip_install": [sys.executable, "-m", "pip", "install", "beautifulsoup4"],
        "actionable_win_note": "Python HTML parsing package. Installs via active Python interpreter: python -m pip install beautifulsoup4."
    },
    "lxml": {
        "display_name": "LXML XML/HTML Parser",
        "executable_name": None,
        "dependency_type": "python_package",
        "import_name": "lxml",
        "supported_platforms": ["win32", "linux", "darwin"],
        "win_native": "Supported",
        "installation_method": "pip",
        "package_name": "lxml",
        "package_manager": "pip",
        "pip_install": [sys.executable, "-m", "pip", "install", "lxml"],
        "actionable_win_note": "Python C-XML parsing library. Installs via active Python interpreter: python -m pip install lxml."
    },
    "rich": {
        "display_name": "Rich Terminal Formatting",
        "executable_name": None,
        "dependency_type": "python_package",
        "import_name": "rich",
        "supported_platforms": ["win32", "linux", "darwin"],
        "win_native": "Supported",
        "installation_method": "pip",
        "package_name": "rich",
        "package_manager": "pip",
        "pip_install": [sys.executable, "-m", "pip", "install", "rich"],
        "actionable_win_note": "Python rich terminal formatting package. Installs via active Python interpreter: python -m pip install rich."
    }
}

UNIFIED_DEPENDENCY_REGISTRY = TOOL_SPEC_REGISTRY

class ToolInstallerService:
    """Windows-aware tool installer and unified dependency manager service."""

    @staticmethod
    def detect_environment() -> Dict[str, Any]:
        """Returns comprehensive Python environment diagnostics."""
        ensure_all_python_script_paths_in_path()
        system_os = platform.system()
        os_release = platform.release()
        os_version = platform.version()
        py_version = sys.version.split()[0]
        python_dir = os.path.dirname(sys.executable)
        scripts_dir = os.path.join(python_dir, "Scripts" if sys.platform == "win32" else "bin")

        user_base = ""
        user_site = ""
        try:
            user_base = site.getuserbase()
            user_site = site.getusersitepackages()
        except Exception:
            pass

        site_pkgs = []
        try:
            import site as st
            site_pkgs = st.getsitepackages()
        except Exception:
            pass

        path_dirs = [p for p in os.environ.get("PATH", "").split(os.pathsep) if p]
        wsl_info = detect_wsl()
        perl_info = check_perl_runtime()

        managers = {
            "pip": sys.executable is not None,
            "apt": shutil.which("apt-get") is not None,
            "winget": shutil.which("winget") is not None,
            "choco": shutil.which("choco") is not None,
            "brew": shutil.which("brew") is not None,
        }

        virtual_env = os.environ.get("VIRTUAL_ENV", None)

        return {
            "os": system_os,
            "os_release": os_release,
            "os_version": os_version,
            "platform_details": platform.platform(),
            "python_executable": sys.executable,
            "python_version": py_version,
            "sys_prefix": getattr(sys, "prefix", ""),
            "sys_base_prefix": getattr(sys, "base_prefix", ""),
            "python_scripts_dir": scripts_dir,
            "user_base": user_base,
            "user_site": user_site,
            "site_packages": site_pkgs,
            "virtual_env": virtual_env,
            "package_managers": managers,
            "wsl": wsl_info,
            "perl": perl_info,
            "path_directories": path_dirs[:15]
        }

    @classmethod
    def get_install_command(cls, dep_name: str) -> Optional[List[str]]:
        """Determines the exact safe subprocess installation command array for current OS."""
        if dep_name not in TOOL_SPEC_REGISTRY:
            return None

        spec = TOOL_SPEC_REGISTRY[dep_name]
        is_windows = (sys.platform == "win32")

        if spec.get("dependency_type") == "python_package":
            return [sys.executable, "-m", "pip", "install", dep_name]

        if is_windows:
            return spec.get("win_install")
        else:
            return spec.get("linux_install")

    @classmethod
    def install_tool(cls, dep_name: str, timeout: int = 180) -> Dict[str, Any]:
        """
        State Machine Installation Pipeline:
        1. Check if tool is already executable & runnable -> ONLINE.
        2. Check if supported on current OS. If unsupported -> UNSUPPORTED ON OS.
        3. Run predefined command array (shell=False, timeout=180).
        4. Capture exit code, stdout, stderr.
        5. If exit code != 0: Check if package is already installed & executable works (e.g. winget 2316632107).
        6. Refresh runtime process PATH and search candidate Python Script directories.
        7. Run verification command.
        """
        ensure_all_python_script_paths_in_path()
        dep_key = dep_name.lower().strip()

        if dep_key not in TOOL_SPEC_REGISTRY:
            return {
                "success": False,
                "tool": dep_name,
                "status": "INSTALL FAILED",
                "error": f"Dependency '{dep_name}' is not in the allowed installation registry.",
                "output": ""
            }

        spec = TOOL_SPEC_REGISTRY[dep_key]
        is_windows = (sys.platform == "win32")

        # 1. Check if already executable & working
        exec_path = find_python_cli_executable(spec.get("executable_name") or dep_key)
        if exec_path:
            ver_cmd = [exec_path] + (spec.get("version_check_command") or [])
            try:
                v_res = subprocess.run(ver_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=4, shell=False)
                if v_res.returncode == 0 or (v_res.stdout or v_res.stderr):
                    ver_out = (v_res.stdout or v_res.stderr or "").strip()
                    ver_str = ver_out.splitlines()[0][:100] if ver_out else "Installed & Operational"
                    return {
                        "success": True,
                        "tool": dep_key,
                        "path": exec_path,
                        "version": ver_str,
                        "status": "ONLINE",
                        "output": ver_str,
                        "actionable_message": f"'{dep_key}' is already installed and verified operational at '{exec_path}'."
                    }
            except Exception:
                pass

        # 2. Check Python Packages
        if spec.get("dependency_type") == "python_package":
            cmd = [sys.executable, "-m", "pip", "install", dep_key]
            logger.info(f"Installing Python package '{dep_key}': {cmd}")
            try:
                res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout, shell=False)
                combined_output = (res.stdout or "") + ("\n" + res.stderr if res.stderr else "")
                formatted_exit = format_exit_code(res.returncode)

                import_name = spec.get("import_name", dep_key)
                try:
                    mod = importlib.import_module(import_name)
                    pkg_ver = getattr(mod, "__version__", None) or importlib.metadata.version(dep_key)
                    succ_msg = f"Python package '{dep_key}' (imported as '{import_name}') is installed and verified ONLINE (Version: {pkg_ver})."
                    return {
                        "success": True,
                        "tool": dep_key,
                        "import_name": import_name,
                        "version": pkg_ver,
                        "status": "ONLINE",
                        "return_code": res.returncode,
                        "formatted_exit_code": formatted_exit,
                        "command": " ".join(cmd),
                        "output": combined_output[:4000],
                        "error": None,
                        "actionable_message": succ_msg
                    }
                except Exception as ie:
                    err_msg = f"Pip returned code {formatted_exit}, but import of '{import_name}' failed: {str(ie)}"
                    return {
                        "success": False,
                        "tool": dep_key,
                        "status": "INSTALLED BUT NOT IMPORTABLE",
                        "return_code": res.returncode,
                        "formatted_exit_code": formatted_exit,
                        "command": " ".join(cmd),
                        "error": err_msg,
                        "output": combined_output[:4000],
                        "actionable_message": err_msg
                    }
            except Exception as e:
                err_msg = f"Failed installing Python package '{dep_key}': {str(e)}"
                return {"success": False, "tool": dep_key, "status": "INSTALL FAILED", "error": err_msg, "output": err_msg, "actionable_message": err_msg}

        # 3. Check Nikto Perl requirement
        if dep_key == "nikto" and is_windows:
            perl_info = check_perl_runtime()
            if not perl_info["available"]:
                msg = spec["actionable_win_note"]
                return {"success": False, "tool": dep_key, "status": "RUNTIME MISSING", "error": msg, "output": msg, "actionable_message": msg}

        # 4. Check Unsupported OS Native tools
        if is_windows and spec.get("win_native") == "Unsupported":
            wsl_info = detect_wsl()
            wsl_note = f" (WSL is available at {wsl_info['path']})" if wsl_info.get("available") else " (WSL is not currently detected)."
            msg = (spec.get("unsupported_reason") or spec.get("actionable_win_note", "")) + wsl_note
            return {"success": False, "tool": dep_key, "status": "UNSUPPORTED ON OS", "error": msg, "output": msg, "actionable_message": msg}

        cmd = cls.get_install_command(dep_key)
        if not cmd:
            env = cls.detect_environment()
            msg = spec.get("unsupported_reason") or f"{spec['display_name']} is not supported natively via automated installer on {env['os']}."
            return {"success": False, "tool": dep_key, "status": "INSTALLATION METHOD UNAVAILABLE", "error": msg, "output": msg, "actionable_message": msg}

        logger.info(f"Executing predefined installation command for '{dep_key}': {cmd}")
        try:
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout, shell=False)
            stdout = res.stdout or ""
            stderr = res.stderr or ""
            combined_output = stdout + ("\n" + stderr if stderr else "")
            formatted_exit = format_exit_code(res.returncode)

            # Re-verify executable after installation even if return code is non-zero (e.g. winget 2316632107 "Already installed")
            ensure_all_python_script_paths_in_path()
            binary_name = spec.get("executable_name") or dep_key
            installed_path = find_python_cli_executable(binary_name)

            if res.returncode != 0:
                # Check if failure is "Already installed / No upgrade found" (winget code 2316632107 / 0x8A15002B)
                is_already_installed_msg = ("already installed" in combined_output.lower() or "no available upgrade" in combined_output.lower())
                if installed_path and is_already_installed_msg:
                    ver_cmd = [installed_path] + (spec.get("version_check_command") or [])
                    try:
                        v_res = subprocess.run(ver_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=4, shell=False)
                        ver_out = (v_res.stdout or v_res.stderr or "").strip()
                        ver_str = ver_out.splitlines()[0][:100] if ver_out else "Installed & Operational"
                        succ_msg = f"{spec['display_name']} is already installed and verified ONLINE at '{installed_path}'."
                        return {
                            "success": True,
                            "tool": dep_key,
                            "binary": binary_name,
                            "path": installed_path,
                            "version": ver_str,
                            "status": "ONLINE",
                            "return_code": res.returncode,
                            "formatted_exit_code": formatted_exit,
                            "command": " ".join(cmd),
                            "output": combined_output[:4000],
                            "error": None,
                            "actionable_message": succ_msg
                        }
                    except Exception:
                        pass

                err_msg = f"Package manager exited with code {formatted_exit}. Output snippet: {combined_output[:300]}"
                return {
                    "success": False,
                    "tool": dep_key,
                    "status": "INSTALL FAILED",
                    "return_code": res.returncode,
                    "formatted_exit_code": formatted_exit,
                    "command": " ".join(cmd),
                    "error": err_msg,
                    "output": combined_output[:4000],
                    "actionable_message": err_msg
                }

            if not installed_path:
                err_msg = f"Package manager returned exit code {formatted_exit}, but executable '{binary_name}' was not found in Python Scripts or system PATH. {spec.get('actionable_win_note', '')}"
                return {
                    "success": False,
                    "tool": dep_key,
                    "status": "PACKAGE INSTALLED BUT EXECUTABLE NOT FOUND",
                    "return_code": res.returncode,
                    "formatted_exit_code": formatted_exit,
                    "command": " ".join(cmd),
                    "error": err_msg,
                    "output": combined_output[:4000],
                    "actionable_message": err_msg
                }

            # Verify Binary Execution
            ver_cmd = [installed_path] + (spec.get("version_check_command") or [])
            try:
                v_res = subprocess.run(ver_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5, shell=False)
                ver_out = (v_res.stdout or v_res.stderr or "").strip()
                ver_str = ver_out.splitlines()[0][:100] if ver_out else "Installed & Operational"
                succ_msg = f"{spec['display_name']} is installed and operational at '{installed_path}'."
                return {
                    "success": True,
                    "tool": dep_key,
                    "binary": binary_name,
                    "path": installed_path,
                    "version": ver_str,
                    "status": "ONLINE",
                    "return_code": res.returncode,
                    "formatted_exit_code": formatted_exit,
                    "command": " ".join(cmd),
                    "output": combined_output[:4000],
                    "error": None,
                    "actionable_message": succ_msg
                }
            except Exception as ve:
                err_msg = f"Executable found at '{installed_path}', but verification call failed: {str(ve)}"
                return {"success": False, "tool": dep_key, "status": "INSTALLED BUT EXECUTION FAILED", "path": installed_path, "error": err_msg, "output": combined_output[:4000], "actionable_message": err_msg}

        except Exception as e:
            err_msg = f"Unexpected failure installing '{dep_key}': {str(e)}"
            return {"success": False, "tool": dep_key, "status": "INSTALL FAILED", "error": err_msg, "output": err_msg, "actionable_message": err_msg}
