"""
Port Scanning Service Module for NMAP-X Platform.
Converts and enhances port scanning functionality from RECON.txt into a safe, structured module.
"""

from typing import List, Optional, Dict, Any
from scanner.validators import validate_target_host, validate_ports_input, ValidationError
from scanner.command_builder import build_tcp_scan_command, NmapCommandBuilder, TCP_SCAN_FLAGS, UDP_SCAN_FLAGS
from scanner.nmap_engine import NmapExecutionEngine, ScanExecutionResult
from scanner.result_parser import NmapResultParser, ParsedScanResult
from scanner.security_config import IS_CLOUD_ENV, CLOUD_SAFE_SCAN_TYPE

class PortScanningService:
    """
    Service handling Port Scanning operations.
    """

    def __init__(self, engine: Optional[NmapExecutionEngine] = None):
        self.engine = engine or NmapExecutionEngine()

    def run_port_scan(
        self,
        target: str,
        scan_type: str = "-sS",
        port_selection_type: str = "specific",  # "specific", "top", "all"
        ports: Optional[str] = None,
        top_ports_count: int = 100,
        timing: str = "-T4"
    ) -> Dict[str, Any]:
        """
        Executes a port scan against a validated target.
        
        :param target: Target IP or Hostname
        :param scan_type: Scan technique flag (-sS, -sT, -sU, -sA, -sV etc.)
        :param port_selection_type: Type of port selection ("specific", "top", "all")
        :param ports: Specific port range or comma-separated list e.g. "22,80,443" or "1-1000"
        :param top_ports_count: Number of top ports if port_selection_type == "top"
        :param timing: Timing template e.g. "-T4"
        :return: Structured JSON-serializable dictionary containing execution status and parsed results
        """
        # Validate Target
        validated_target = validate_target_host(target)

        builder = NmapCommandBuilder(validated_target)
        builder.set_timing(timing)

        # Apply scan type flag; on cloud auto-swap -sS to -sT (TCP Connect - no raw socket needed)
        effective_scan_type = CLOUD_SAFE_SCAN_TYPE if IS_CLOUD_ENV and scan_type == '-sS' else scan_type
        allowed_flags = TCP_SCAN_FLAGS.union(UDP_SCAN_FLAGS).union({'-sV', '-O', '-T0','-T1','-T2','-T3','-T4','-T5'})
        builder.add_flags([effective_scan_type], allowed_subset=allowed_flags)

        # Port Selection Logic
        if port_selection_type == "specific":
            if not ports:
                ports = "1-1024"  # Default fallback range if none specified
            validated_ports = validate_ports_input(ports)
            builder.set_ports(validated_ports)
        elif port_selection_type == "top":
            builder.set_top_ports(top_ports_count)
        elif port_selection_type == "all":
            builder.set_ports("1-65535")
        else:
            raise ValidationError(f"Invalid port selection mode '{port_selection_type}'. Expected 'specific', 'top', or 'all'.")

        # XML output flag
        builder.add_flags(['-oX'], allowed_subset={'-oX'})

        cmd_vector = builder.build()
        ox_index = cmd_vector.index("-oX")
        cmd_vector.insert(ox_index + 1, "-")

        # Execute
        exec_result: ScanExecutionResult = self.engine.execute(cmd_vector)

        # Parse output
        if exec_result.status in ("SUCCESS", "ERROR") and exec_result.stdout:
            parsed: ParsedScanResult = NmapResultParser.parse_xml(exec_result.stdout, raw_text_fallback=exec_result.stdout)
        else:
            parsed = ParsedScanResult(raw_xml="", raw_text=exec_result.stderr or exec_result.stdout, parsing_error=exec_result.error)

        return {
            "target": validated_target,
            "execution": exec_result.to_dict(),
            "parsed": parsed.to_dict()
        }
