"""
Host Discovery Service Module for NMAP-X Platform.
Converts and enhances host discovery functionality from RECON.txt into a safe, structured module.
"""

from typing import List, Optional, Dict, Any
from scanner.validators import validate_target_host, ValidationError
from scanner.command_builder import build_host_discovery_command, NmapCommandBuilder, HOST_DISCOVERY_FLAGS
from scanner.nmap_engine import NmapExecutionEngine, ScanExecutionResult
from scanner.result_parser import NmapResultParser, ParsedScanResult

class HostDiscoveryService:
    """
    Service handling Host Discovery operations.
    """

    def __init__(self, engine: Optional[NmapExecutionEngine] = None):
        self.engine = engine or NmapExecutionEngine()

    def run_discovery(self, target: str, discovery_flags: Optional[List[str]] = None, timing: str = "-T4") -> Dict[str, Any]:
        """
        Executes host discovery against a validated target.
        
        :param target: Target IP, Hostname, or CIDR range
        :param discovery_flags: List of discovery flags e.g. ['-sn', '-PE', '-PA']
        :param timing: Timing template e.g. '-T4'
        :return: Structured JSON-serializable dictionary containing execution status and parsed results
        """
        # Validate Target
        validated_target = validate_target_host(target)

        # Default discovery flags if none selected
        if not discovery_flags:
            discovery_flags = ['-sn', '-PE', '-PA']

        # Include -oX - flag for XML output parsing
        builder = NmapCommandBuilder(validated_target)
        builder.set_timing(timing)
        builder.add_flags(discovery_flags, allowed_subset=HOST_DISCOVERY_FLAGS.union({'-T0','-T1','-T2','-T3','-T4','-T5'}))
        builder.add_flags(['-oX'], allowed_subset={'-oX'})
        
        # Build command array with XML output to stdout: ["nmap", ..., "-oX", "-", target]
        cmd_vector = builder.build()
        # Ensure "-oX" is followed by "-"
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
