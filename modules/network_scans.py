"""
Specialized Network Scan Services for NMAP-X Platform.
Provides backend business logic for TCP Scans, UDP Scans, and ICMP Scans.
Reuses NmapCommandBuilder, NmapExecutionEngine, and NmapResultParser without code duplication.
"""

from typing import List, Optional, Dict, Any
from scanner.validators import validate_target_host, validate_ports_input, ValidationError
from scanner.command_builder import (
    build_tcp_scan_command,
    build_udp_scan_command,
    build_icmp_scan_command,
    TCP_SCAN_FLAGS,
    UDP_SCAN_FLAGS,
    ICMP_SCAN_FLAGS,
    NmapCommandBuilder
)
from scanner.nmap_engine import NmapExecutionEngine, ScanExecutionResult
from scanner.result_parser import NmapResultParser, ParsedScanResult
from scanner.security_config import IS_CLOUD_ENV, CLOUD_SAFE_SCAN_TYPE

class NetworkScanService:
    """
    Unified service handling specialized scan types (TCP, UDP, ICMP).
    """

    def __init__(self, engine: Optional[NmapExecutionEngine] = None):
        self.engine = engine or NmapExecutionEngine()

    def run_tcp_scan(
        self,
        target: str,
        tcp_flag: str = "-sS",
        ports: Optional[str] = None,
        top_ports_count: Optional[int] = None,
        timing: str = "-T4"
    ) -> Dict[str, Any]:
        """Runs a TCP scan (-sS, -sT, -sA, -sW, -sM)."""
        validated_target = validate_target_host(target)

        builder = NmapCommandBuilder(validated_target)
        builder.set_timing(timing)
        # On cloud: -sS needs CAP_NET_RAW; auto-swap to -sT (TCP Connect)
        effective_flag = CLOUD_SAFE_SCAN_TYPE if IS_CLOUD_ENV and tcp_flag == '-sS' else tcp_flag
        builder.add_flags([effective_flag], allowed_subset=TCP_SCAN_FLAGS.union({'-T0','-T1','-T2','-T3','-T4','-T5'}))

        if ports:
            builder.set_ports(validate_ports_input(ports))
        elif top_ports_count:
            builder.set_top_ports(top_ports_count)
        else:
            builder.set_ports("1-1024")

        builder.add_flags(['-oX'], allowed_subset={'-oX'})
        cmd_vector = builder.build()
        ox_index = cmd_vector.index("-oX")
        cmd_vector.insert(ox_index + 1, "-")

        exec_result: ScanExecutionResult = self.engine.execute(cmd_vector)
        parsed: ParsedScanResult = NmapResultParser.parse_xml(exec_result.stdout, raw_text_fallback=exec_result.stdout) if exec_result.stdout else ParsedScanResult(raw_xml="", raw_text=exec_result.stderr, parsing_error=exec_result.error)

        return {
            "target": validated_target,
            "scan_type": "TCP",
            "execution": exec_result.to_dict(),
            "parsed": parsed.to_dict()
        }

    def run_udp_scan(
        self,
        target: str,
        ports: Optional[str] = None,
        top_ports_count: Optional[int] = None,
        timing: str = "-T4"
    ) -> Dict[str, Any]:
        """Runs a UDP scan (-sU)."""
        validated_target = validate_target_host(target)

        builder = NmapCommandBuilder(validated_target)
        builder.set_timing(timing)
        builder.add_flags(['-sU'], allowed_subset=UDP_SCAN_FLAGS.union({'-T0','-T1','-T2','-T3','-T4','-T5'}))

        if ports:
            builder.set_ports(validate_ports_input(ports))
        elif top_ports_count:
            builder.set_top_ports(top_ports_count)
        else:
            builder.set_top_ports(50)  # Default top 50 UDP ports for speed

        builder.add_flags(['-oX'], allowed_subset={'-oX'})
        cmd_vector = builder.build()
        ox_index = cmd_vector.index("-oX")
        cmd_vector.insert(ox_index + 1, "-")

        exec_result: ScanExecutionResult = self.engine.execute(cmd_vector)
        parsed: ParsedScanResult = NmapResultParser.parse_xml(exec_result.stdout, raw_text_fallback=exec_result.stdout) if exec_result.stdout else ParsedScanResult(raw_xml="", raw_text=exec_result.stderr, parsing_error=exec_result.error)

        return {
            "target": validated_target,
            "scan_type": "UDP",
            "execution": exec_result.to_dict(),
            "parsed": parsed.to_dict()
        }

    def run_icmp_scan(
        self,
        target: str,
        icmp_flags: Optional[List[str]] = None,
        timing: str = "-T4"
    ) -> Dict[str, Any]:
        """Runs an ICMP scan (-PE, -PP, -PM)."""
        validated_target = validate_target_host(target)

        if not icmp_flags:
            # On cloud: ICMP raw sockets are blocked; use TCP-based host probing instead
            icmp_flags = ['-sn', '-PS80,443', '-PA80', '-Pn'] if IS_CLOUD_ENV else ['-PE', '-sn']

        builder = NmapCommandBuilder(validated_target)
        builder.set_timing(timing)
        builder.add_flags(icmp_flags, allowed_subset=ICMP_SCAN_FLAGS.union({'-T0','-T1','-T2','-T3','-T4','-T5'}))

        builder.add_flags(['-oX'], allowed_subset={'-oX'})
        cmd_vector = builder.build()
        ox_index = cmd_vector.index("-oX")
        cmd_vector.insert(ox_index + 1, "-")

        exec_result: ScanExecutionResult = self.engine.execute(cmd_vector)
        parsed: ParsedScanResult = NmapResultParser.parse_xml(exec_result.stdout, raw_text_fallback=exec_result.stdout) if exec_result.stdout else ParsedScanResult(raw_xml="", raw_text=exec_result.stderr, parsing_error=exec_result.error)

        return {
            "target": validated_target,
            "scan_type": "ICMP",
            "execution": exec_result.to_dict(),
            "parsed": parsed.to_dict()
        }
