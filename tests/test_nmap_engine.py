import pytest
import subprocess
from unittest.mock import MagicMock, patch
from scanner.nmap_engine import NmapExecutionEngine, ScanExecutionResult
from scanner.command_builder import build_tcp_scan_command
from scanner.validators import ValidationError

@patch('subprocess.Popen')
def test_successful_execution(mock_popen):
    # Mock Popen instance
    mock_process = MagicMock()
    mock_process.communicate.return_value = ("Starting Nmap 7.94... Host is up. 80/tcp open http", "")
    mock_process.returncode = 0
    mock_popen.return_value = mock_process

    engine = NmapExecutionEngine(timeout=10)
    cmd = build_tcp_scan_command(target="192.168.1.1", ports="80")
    
    result = engine.execute(cmd)

    assert result.status == "SUCCESS"
    assert result.return_code == 0
    assert "80/tcp open" in result.stdout
    assert result.stderr == ""
    assert result.duration >= 0.0
    assert result.error is None
    # Verify Popen called with shell=False
    mock_popen.assert_called_once_with(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=False)

@patch('subprocess.Popen')
def test_timeout_handling(mock_popen):
    mock_process = MagicMock()
    mock_process.communicate.side_effect = [
        subprocess.TimeoutExpired(cmd=["nmap"], timeout=1),
        ("partial stdout", "timeout error")
    ]
    mock_popen.return_value = mock_process

    engine = NmapExecutionEngine(timeout=1)
    cmd = build_tcp_scan_command(target="192.168.1.1", ports="80")

    result = engine.execute(cmd)

    assert result.status == "TIMEOUT"
    assert result.return_code == -1
    assert "partial stdout" in result.stdout
    assert "Scan execution exceeded maximum timeout" in result.error
    mock_process.kill.assert_called_once()

@patch('subprocess.Popen')
def test_nmap_not_installed(mock_popen):
    mock_popen.side_effect = FileNotFoundError()

    engine = NmapExecutionEngine()
    cmd = build_tcp_scan_command(target="192.168.1.1", ports="80")

    result = engine.execute(cmd)

    assert result.status == "NOT_INSTALLED"
    assert result.return_code == -1
    assert "not found on the system PATH" in result.error

@patch('subprocess.Popen')
def test_permission_denied_process_error(mock_popen):
    mock_popen.side_effect = PermissionError()

    engine = NmapExecutionEngine()
    cmd = build_tcp_scan_command(target="192.168.1.1", ports="80")

    result = engine.execute(cmd)

    assert result.status == "PERMISSION_DENIED"
    assert result.return_code == -1
    assert "Permission denied" in result.error

@patch('subprocess.Popen')
def test_permission_denied_in_stderr(mock_popen):
    mock_process = MagicMock()
    mock_process.communicate.return_value = ("", "nmap: QUITTING due to ERROR: You requested a scan type which requires root privileges.")
    mock_process.returncode = 1
    mock_popen.return_value = mock_process

    engine = NmapExecutionEngine()
    cmd = build_tcp_scan_command(target="192.168.1.1", ports="80")

    result = engine.execute(cmd)

    assert result.status == "PERMISSION_DENIED"
    assert result.return_code == 1
    assert "Permission denied" in result.error
    assert "requires root" in result.stderr

@patch('subprocess.Popen')
def test_output_truncation(mock_popen):
    large_stdout = "A" * 2000
    mock_process = MagicMock()
    mock_process.communicate.return_value = (large_stdout, "")
    mock_process.returncode = 0
    mock_popen.return_value = mock_process

    # Set max output size to 500 bytes
    engine = NmapExecutionEngine(max_output_bytes=500)
    cmd = build_tcp_scan_command(target="192.168.1.1", ports="80")

    result = engine.execute(cmd)

    assert result.status == "SUCCESS"
    assert len(result.stdout) < 1000
    assert "[OUTPUT TRUNCATED: Exceeded Max Size Quota]" in result.stdout

def test_invalid_command_vector_input():
    engine = NmapExecutionEngine()
    with pytest.raises(ValidationError):
        engine.execute([])
