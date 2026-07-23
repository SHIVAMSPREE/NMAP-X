"""
Advanced Fingerprinting Services for NMAP-X Platform.
Implements Version Detection, OS Fingerprinting, and Banner Grabbing.
Converts functionality from RECON.txt and WEBSITE FOOTPRINTING.txt into modular Python services.
"""

from typing import List, Optional, Dict, Any
from scanner.validators import validate_target_host, validate_ports_input, ValidationError
from scanner.command_builder import (
    build_version_detection_command,
    build_os_detection_command,
    build_banner_grabbing_command,
    VERSION_DETECTION_FLAGS,
    OS_DETECTION_FLAGS,
    BANNER_GRABBING_FLAGS,
    NmapCommandBuilder
)
from scanner.nmap_engine import NmapExecutionEngine, ScanExecutionResult
from scanner.result_parser import NmapResultParser, ParsedScanResult

class FingerprintingService:
    """
    Service handling Version Detection, OS Fingerprinting, and Banner Grabbing.
    """

    def __init__(self, engine: Optional[NmapExecutionEngine] = None):
        self.engine = engine or NmapExecutionEngine()

    def run_version_detection(
        self,
        target: str,
        ports: Optional[str] = None,
        version_flag: str = "-sV",
        intensity: Optional[int] = None,
        timing: str = "-T4"
    ) -> Dict[str, Any]:
        """Runs Nmap service version detection (-sV, --version-light, --version-all, --version-intensity)."""
        validated_target = validate_target_host(target)

        builder = NmapCommandBuilder(validated_target)
        builder.set_timing(timing)

        allowed = VERSION_DETECTION_FLAGS.union({'-T0','-T1','-T2','-T3','-T4','-T5'})
        builder.add_flags([version_flag], allowed_subset=allowed)

        if intensity is not None:
            builder.add_version_intensity(intensity)

        if ports:
            builder.set_ports(validate_ports_input(ports))
        else:
            builder.set_ports("21,22,25,53,80,110,143,443,3306,5432,8080")

        builder.add_flags(['-oX'], allowed_subset={'-oX'})
        cmd_vector = builder.build()
        ox_index = cmd_vector.index("-oX")
        cmd_vector.insert(ox_index + 1, "-")

        exec_result: ScanExecutionResult = self.engine.execute(cmd_vector)
        parsed: ParsedScanResult = NmapResultParser.parse_xml(exec_result.stdout, raw_text_fallback=exec_result.stdout) if exec_result.stdout else ParsedScanResult(raw_xml="", raw_text=exec_result.stderr, parsing_error=exec_result.error)

        return {
            "target": validated_target,
            "scan_type": "VERSION_DETECTION",
            "execution": exec_result.to_dict(),
            "parsed": parsed.to_dict()
        }

    def run_os_detection(
        self,
        target: str,
        ports: Optional[str] = None,
        os_options: Optional[List[str]] = None,
        timing: str = "-T4"
    ) -> Dict[str, Any]:
        """Runs Nmap OS fingerprinting (-O, --osscan-limit, --osscan-guess)."""
        validated_target = validate_target_host(target)

        builder = NmapCommandBuilder(validated_target)
        builder.set_timing(timing)

        flags = ['-O'] + (os_options or [])
        allowed = OS_DETECTION_FLAGS.union({'-T0','-T1','-T2','-T3','-T4','-T5'})
        builder.add_flags(flags, allowed_subset=allowed)

        if ports:
            builder.set_ports(validate_ports_input(ports))

        builder.add_flags(['-oX'], allowed_subset={'-oX'})
        cmd_vector = builder.build()
        ox_index = cmd_vector.index("-oX")
        cmd_vector.insert(ox_index + 1, "-")

        exec_result: ScanExecutionResult = self.engine.execute(cmd_vector)
        parsed: ParsedScanResult = NmapResultParser.parse_xml(exec_result.stdout, raw_text_fallback=exec_result.stdout) if exec_result.stdout else ParsedScanResult(raw_xml="", raw_text=exec_result.stderr, parsing_error=exec_result.error)

        return {
            "target": validated_target,
            "scan_type": "OS_DETECTION",
            "execution": exec_result.to_dict(),
            "parsed": parsed.to_dict()
        }

    def run_banner_grabbing(
        self,
        target: str,
        ports: Optional[str] = None,
        timing: str = "-T4"
    ) -> Dict[str, Any]:
        """Runs NSE banner grabbing (-sV --script=banner)."""
        validated_target = validate_target_host(target)

        builder = NmapCommandBuilder(validated_target)
        builder.set_timing(timing)

        allowed = BANNER_GRABBING_FLAGS.union({'-T0','-T1','-T2','-T3','-T4','-T5'})
        builder.add_flags(['-sV', '--script=banner'], allowed_subset=allowed)

        if ports:
            builder.set_ports(validate_ports_input(ports))
        else:
            builder.set_ports("21,22,25,80,110,143,443,3306,8080")

        builder.add_flags(['-oX'], allowed_subset={'-oX'})
        cmd_vector = builder.build()
        ox_index = cmd_vector.index("-oX")
        cmd_vector.insert(ox_index + 1, "-")

        exec_result: ScanExecutionResult = self.engine.execute(cmd_vector)
        parsed: ParsedScanResult = NmapResultParser.parse_xml(exec_result.stdout, raw_text_fallback=exec_result.stdout) if exec_result.stdout else ParsedScanResult(raw_xml="", raw_text=exec_result.stderr, parsing_error=exec_result.error)

        return {
            "target": validated_target,
            "scan_type": "BANNER_GRABBING",
            "execution": exec_result.to_dict(),
            "parsed": parsed.to_dict()
        }
