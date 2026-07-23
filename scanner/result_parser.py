"""
Nmap XML Result Parser for NMAP-X Cybersecurity Reconnaissance Platform.
Parses Nmap XML output into clean, structured Python dataclasses and dictionaries.
Preserves raw XML output and handles missing fields, empty XML, or malformed XML gracefully.
"""

import xml.etree.ElementTree as ET
import logging
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict, Any

logger = logging.getLogger("nmap_x.result_parser")

@dataclass
class HostResult:
    address: str
    hostname: str = ""
    state: str = "unknown"
    reason: str = ""
    latency: str = ""

@dataclass
class PortResult:
    host: str
    port: int
    protocol: str
    state: str = "unknown"
    service: str = "unknown"
    product: str = ""
    version: str = ""
    extra_info: str = ""
    cpe: List[str] = field(default_factory=list)

@dataclass
class OsResult:
    host: str
    name: str
    accuracy: str = "0"
    device_type: str = ""
    cpe: List[str] = field(default_factory=list)

@dataclass
class ServiceInfo:
    service_name: str
    product: str = ""
    version: str = ""
    extra_information: str = ""

@dataclass
class ParsedScanResult:
    raw_xml: str
    raw_text: str = ""
    hosts: List[HostResult] = field(default_factory=list)
    ports: List[PortResult] = field(default_factory=list)
    os_matches: List[OsResult] = field(default_factory=list)
    services: List[ServiceInfo] = field(default_factory=list)
    parsing_error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "raw_xml": self.raw_xml,
            "raw_text": self.raw_text,
            "hosts": [asdict(h) for h in self.hosts],
            "ports": [asdict(p) for p in self.ports],
            "os_matches": [asdict(o) for o in self.os_matches],
            "services": [asdict(s) for s in self.services],
            "parsing_error": self.parsing_error
        }


class NmapResultParser:
    """
    Parser for processing Nmap XML output files or XML strings.
    """

    @staticmethod
    def parse_xml(xml_content: str, raw_text_fallback: str = "") -> ParsedScanResult:
        """
        Parses Nmap XML output.
        
        :param xml_content: XML string returned by Nmap (e.g. via -oX - option)
        :param raw_text_fallback: Standard text stdout output to preserve
        :return: ParsedScanResult instance
        """
        result = ParsedScanResult(raw_xml=xml_content or "", raw_text=raw_text_fallback or "")

        if not xml_content or not xml_content.strip():
            logger.warning("Empty XML content provided to NmapResultParser.")
            result.parsing_error = "Empty XML input."
            return result

        try:
            root = ET.fromstring(xml_content)
        except ET.ParseError as e:
            logger.error(f"Failed to parse Nmap XML content: {e}")
            result.parsing_error = f"Malformed XML output: {e}"
            return result

        if root.tag != 'nmaprun':
            result.parsing_error = f"Invalid Nmap XML document root tag '{root.tag}'. Expected 'nmaprun'."
            return result

        # Iterate over <host> elements
        for host_elem in root.findall('host'):
            # Address extraction
            addr_elem = host_elem.find('address')
            if addr_elem is None or 'addr' not in addr_elem.attrib:
                # Fallback check for any address tag
                addresses = host_elem.findall('address')
                if addresses:
                    addr_str = addresses[0].attrib.get('addr', '0.0.0.0')
                else:
                    addr_str = 'unknown'
            else:
                addr_str = addr_elem.attrib['addr']

            # Hostname extraction
            hostname_str = ""
            hostnames_elem = host_elem.find('hostnames')
            if hostnames_elem is not None:
                hn_elem = hostnames_elem.find('hostname')
                if hn_elem is not None:
                    hostname_str = hn_elem.attrib.get('name', '')

            # Status / State
            status_elem = host_elem.find('status')
            host_state = status_elem.attrib.get('state', 'unknown') if status_elem is not None else 'unknown'
            host_reason = status_elem.attrib.get('reason', '') if status_elem is not None else ''

            # Latency
            times_elem = host_elem.find('times')
            latency_str = ""
            if times_elem is not None and 'srtt' in times_elem.attrib:
                try:
                    latency_ms = float(times_elem.attrib['srtt']) / 1000.0
                    latency_str = f"{latency_ms:.2f}ms"
                except ValueError:
                    latency_str = times_elem.attrib['srtt']

            host_result = HostResult(
                address=addr_str,
                hostname=hostname_str,
                state=host_state,
                reason=host_reason,
                latency=latency_str
            )
            result.hosts.append(host_result)

            # Ports extraction
            ports_elem = host_elem.find('ports')
            if ports_elem is not None:
                for port_elem in ports_elem.findall('port'):
                    try:
                        port_num = int(port_elem.attrib.get('portid', 0))
                    except ValueError:
                        continue
                    
                    protocol = port_elem.attrib.get('protocol', 'tcp')

                    state_elem = port_elem.find('state')
                    port_state = state_elem.attrib.get('state', 'unknown') if state_elem is None else state_elem.attrib.get('state', 'unknown')

                    service_name = "unknown"
                    product = ""
                    version = ""
                    extra_info = ""
                    cpes = []

                    service_elem = port_elem.find('service')
                    if service_elem is not None:
                        service_name = service_elem.attrib.get('name', 'unknown')
                        product = service_elem.attrib.get('product', '')
                        version = service_elem.attrib.get('version', '')
                        extra_info = service_elem.attrib.get('extrainfo', '')

                        for cpe_elem in service_elem.findall('cpe'):
                            if cpe_elem.text:
                                cpes.append(cpe_elem.text)

                        # Collect service summary
                        result.services.append(ServiceInfo(
                            service_name=service_name,
                            product=product,
                            version=version,
                            extra_information=extra_info
                        ))

                    port_result = PortResult(
                        host=addr_str,
                        port=port_num,
                        protocol=protocol,
                        state=port_state,
                        service=service_name,
                        product=product,
                        version=version,
                        extra_info=extra_info,
                        cpe=cpes
                    )
                    result.ports.append(port_result)

            # OS Detection extraction
            os_elem = host_elem.find('os')
            if os_elem is not None:
                for osmatch in os_elem.findall('osmatch'):
                    os_name = osmatch.attrib.get('name', 'Unknown OS')
                    os_accuracy = osmatch.attrib.get('accuracy', '0')
                    
                    dev_type = ""
                    os_cpes = []
                    for osclass in osmatch.findall('osclass'):
                        if 'type' in osclass.attrib and not dev_type:
                            dev_type = osclass.attrib['type']
                        for cpe_elem in osclass.findall('cpe'):
                            if cpe_elem.text:
                                os_cpes.append(cpe_elem.text)

                    result.os_matches.append(OsResult(
                        host=addr_str,
                        name=os_name,
                        accuracy=os_accuracy,
                        device_type=dev_type,
                        cpe=os_cpes
                    ))

        return result
