"""
Safe Nmap Execution Engine for NMAP-X Cybersecurity Reconnaissance Platform.
Executes Nmap CLI commands securely via subprocess argument arrays (shell=False),
captures stdout/stderr, enforces execution timeouts, output size quotas, and returns
structured execution results with detailed logging.
"""

import time
import subprocess
import logging
from dataclasses import dataclass, asdict
from typing import List, Optional, Dict, Any
from scanner.security_config import DEFAULT_SCAN_TIMEOUT, MAX_SCAN_TIMEOUT, MAX_OUTPUT_SIZE_BYTES
from scanner.validators import ValidationError

# Configure logger
logger = logging.getLogger("nmap_x.nmap_engine")
logger.setLevel(logging.INFO)

@dataclass
class ScanExecutionResult:
    """Structured result returned by Nmap execution engine."""
    command: List[str]
    return_code: int
    stdout: str
    stderr: str
    status: str          # "SUCCESS", "TIMEOUT", "PERMISSION_DENIED", "NOT_INSTALLED", "ERROR"
    duration: float      # Execution duration in seconds
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Returns result as a dictionary."""
        return asdict(self)


class NmapExecutionEngine:
    """
    Execution engine for running Nmap process vectors safely.
    Enforces shell=False, timeouts, output limits, and structured error handling.
    """

    def __init__(self, timeout: int = DEFAULT_SCAN_TIMEOUT, max_output_bytes: int = MAX_OUTPUT_SIZE_BYTES):
        self.timeout = min(timeout, MAX_SCAN_TIMEOUT)
        self.max_output_bytes = max_output_bytes

    def execute(self, cmd_vector: List[str]) -> ScanExecutionResult:
        """
        Executes an Nmap command argument vector.
        
        :param cmd_vector: List of CLI arguments e.g. ["nmap", "-sS", "-p", "80", "192.168.1.1"]
        :return: ScanExecutionResult instance
        """
        if not cmd_vector or not isinstance(cmd_vector, list):
            raise ValidationError("Command vector must be a non-empty list of arguments.")

        target_obfuscated = cmd_vector[-1] if cmd_vector else "unknown"
        logger.info(f"Initiating scan execution. Binary: {cmd_vector[0]}, Target: {target_obfuscated}")

        start_time = time.time()
        
        try:
            # Enforce shell=False strictly
            process = subprocess.Popen(
                cmd_vector,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                shell=False
            )

            try:
                stdout_data, stderr_data = process.communicate(timeout=self.timeout)
            except subprocess.TimeoutExpired:
                process.kill()
                stdout_data, stderr_data = process.communicate()
                duration = round(time.time() - start_time, 3)
                logger.warning(f"Scan execution timed out after {self.timeout}s.")
                return ScanExecutionResult(
                    command=cmd_vector,
                    return_code=-1,
                    stdout=stdout_data[:self.max_output_bytes] if stdout_data else "",
                    stderr=stderr_data[:self.max_output_bytes] if stderr_data else "",
                    status="TIMEOUT",
                    duration=duration,
                    error=f"Scan execution exceeded maximum timeout limit of {self.timeout} seconds."
                )

            duration = round(time.time() - start_time, 3)

            # Truncate output if exceeding maximum quota
            if stdout_data and len(stdout_data.encode('utf-8')) > self.max_output_bytes:
                stdout_data = stdout_data[:self.max_output_bytes] + "\n[OUTPUT TRUNCATED: Exceeded Max Size Quota]"
            if stderr_data and len(stderr_data.encode('utf-8')) > self.max_output_bytes:
                stderr_data = stderr_data[:self.max_output_bytes] + "\n[STDERR TRUNCATED: Exceeded Max Size Quota]"

            # Evaluate return code & status
            if process.returncode == 0:
                status = "SUCCESS"
                err_msg = None
            else:
                status = "ERROR"
                err_msg = f"Nmap process exited with non-zero status code {process.returncode}."
                if "Permission denied" in stderr_data or "requires root" in stderr_data or "raw sockets" in stderr_data:
                    status = "PERMISSION_DENIED"
                    err_msg = "Permission denied: Elevated privileges (root/sudo or CAP_NET_RAW) required for raw socket scan."

            logger.info(f"Scan finished in {duration}s with status {status} (returncode: {process.returncode})")
            return ScanExecutionResult(
                command=cmd_vector,
                return_code=process.returncode,
                stdout=stdout_data or "",
                stderr=stderr_data or "",
                status=status,
                duration=duration,
                error=err_msg
            )

        except FileNotFoundError:
            duration = round(time.time() - start_time, 3)
            err_msg = f"Nmap executable '{cmd_vector[0]}' was not found on the system PATH."
            logger.error(err_msg)
            return ScanExecutionResult(
                command=cmd_vector,
                return_code=-1,
                stdout="",
                stderr="",
                status="NOT_INSTALLED",
                duration=duration,
                error=err_msg
            )
        except PermissionError:
            duration = round(time.time() - start_time, 3)
            err_msg = f"Permission denied trying to execute process '{cmd_vector[0]}'."
            logger.error(err_msg)
            return ScanExecutionResult(
                command=cmd_vector,
                return_code=-1,
                stdout="",
                stderr="",
                status="PERMISSION_DENIED",
                duration=duration,
                error=err_msg
            )
        except Exception as e:
            duration = round(time.time() - start_time, 3)
            err_msg = f"Unexpected process execution failure: {str(e)}"
            logger.error(err_msg)
            return ScanExecutionResult(
                command=cmd_vector,
                return_code=-1,
                stdout="",
                stderr=str(e),
                status="ERROR",
                duration=duration,
                error=err_msg
            )
