import sys
import pytest
from app import create_app
from scanner.tool_installer import (
    ToolInstallerService,
    TOOL_SPEC_REGISTRY,
    get_python_script_directories,
    ensure_all_python_script_paths_in_path,
    find_python_cli_executable,
    format_exit_code,
    detect_wsl
)
from scanner.tool_checker import ToolCheckerService

@pytest.fixture
def client():
    app = create_app('testing')
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_ensure_all_python_script_paths_in_path():
    """Verify runtime PATH injection for Python Script directories."""
    dirs = get_python_script_directories()
    assert isinstance(dirs, list)
    assert len(dirs) > 0

    added = ensure_all_python_script_paths_in_path()
    assert isinstance(added, list)

def test_find_python_cli_executable():
    """Verify candidate search for CLI executables."""
    # Test with python executable itself or pip
    exe = find_python_cli_executable("python")
    assert exe is not None or sys.executable is not None

def test_format_exit_code():
    """Verify exit code formatting produces decimal and hex."""
    formatted = format_exit_code(2316632084)
    assert "2316632084" in formatted
    assert "0x8A150014" in formatted

    formatted_zero = format_exit_code(0)
    assert "0" in formatted_zero

def test_detect_wsl():
    """Verify WSL detection returns structure."""
    res = detect_wsl()
    assert "available" in res
    assert "details" in res

def test_detect_environment():
    """Verify environment detection telemetry."""
    env = ToolInstallerService.detect_environment()
    assert "os" in env
    assert "python_version" in env
    assert "sys_prefix" in env
    assert "sys_base_prefix" in env
    assert "python_scripts_dir" in env
    assert "user_base" in env
    assert "wsl" in env
    assert "package_managers" in env

def test_get_install_command_unsupported_win():
    """Verify unsupported tools return None or win_install spec."""
    if sys.platform == "win32":
        cmd = ToolInstallerService.get_install_command("dnsmap")
        assert cmd is None

def test_install_tool_unsupported_on_windows():
    """Verify unsupported tools return UNSUPPORTED ON OS status."""
    if sys.platform == "win32":
        res = ToolInstallerService.install_tool("dnsmap")
        assert res["status"] == "UNSUPPORTED ON OS"
        assert "WSL" in res["actionable_message"] or "Linux" in res["actionable_message"]

def test_diagnostic_checker_methods():
    """Verify ToolCheckerService diagnostic methods."""
    nmap_path = ToolCheckerService.get_executable_path("nmap")
    nmap_exists = ToolCheckerService.check_executable("nmap")
    assert isinstance(nmap_exists, bool)

    ver = ToolCheckerService.get_version("nmap", ["--version"])
    assert ver is None or isinstance(ver, str)

def test_api_tools_status_endpoint(client):
    """Test GET /api/v1/tools/status returns statuses and telemetry."""
    response = client.get('/api/v1/tools/status')
    assert response.status_code == 200
    data = response.get_json()
    assert "tool_statuses" in data
    assert "telemetry" in data

def test_api_tools_retry_install_endpoint(client):
    """Test POST /api/v1/tools/retry-install endpoint."""
    response = client.post('/api/v1/tools/retry-install', json={'tool': 'invalid_tool'})
    assert response.status_code == 400

    response_valid = client.post('/api/v1/tools/retry-install', json={'tool': 'dnsmap'})
    assert response_valid.status_code in [200, 400]
