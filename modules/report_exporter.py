"""
Report Exporting Service for NMAP-X Platform.
Generates structured JSON, CSV, and Text reports for scans while preventing directory traversal.
"""

import os
import json
import csv
import io
import re
from typing import Dict, Any
from models.db import db, Scan

class ReportExportService:
    """
    Service generating exported reports safely.
    """

    @staticmethod
    def sanitize_filename(name: str) -> str:
        """Sanitizes filename strings removing filesystem path traversal vectors."""
        sanitized = re.sub(r'[^a-zA-Z0-9_\-]', '_', name)
        return sanitized.strip('_')

    @staticmethod
    def export_json(scan: Scan) -> str:
        """Exports full scan data as formatted JSON string."""
        data = scan.to_dict()
        data['hosts_detailed'] = [h.to_dict() for h in scan.hosts]
        return json.dumps(data, indent=2)

    @staticmethod
    def export_csv(scan: Scan) -> str:
        """Exports discovered ports and host services as CSV string."""
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['Scan ID', 'Target', 'Scan Type', 'Host IP', 'Hostname', 'Port', 'Protocol', 'State', 'Service', 'Product', 'Version'])

        for h in scan.hosts:
            if h.ports:
                for p in h.ports:
                    writer.writerow([
                        scan.id, scan.target, scan.scan_type, h.address, h.hostname or '',
                        p.port, p.protocol, p.state, p.service or '', p.product or '', p.version or ''
                    ])
            else:
                writer.writerow([scan.id, scan.target, scan.scan_type, h.address, h.hostname or '', '', '', h.state, '', '', ''])

        return output.getvalue()

    @staticmethod
    def export_text(scan: Scan) -> str:
        """Exports human-readable text report for a scan."""
        lines = [
            "==================================================================",
            f" NMAP-X RECONNAISSANCE SCAN REPORT - SCAN #{scan.id}",
            "==================================================================",
            f"Target:        {scan.target}",
            f"Scan Type:     {scan.scan_type}",
            f"Status:        {scan.status}",
            f"Started At:    {scan.started_at}",
            f"Completed At:  {scan.completed_at}",
            f"Duration:      {scan.duration}s",
            f"Command:       {scan.command or 'N/A'}",
            "------------------------------------------------------------------",
            "DISCOVERED HOSTS & SERVICES:",
            "------------------------------------------------------------------"
        ]

        for h in scan.hosts:
            lines.append(f"\nHost: {h.address} ({h.hostname or 'No Hostname'}) [State: {h.state}]")
            if h.ports:
                for p in h.ports:
                    lines.append(f"  - Port {p.port}/{p.protocol}: {p.state.upper()} | Service: {p.service or 'unknown'} ({p.product or ''} {p.version or ''})")
            if h.os_matches:
                lines.append("  - Operating System Matches:")
                for o in h.os_matches:
                    lines.append(f"      * {o.name} (Accuracy: {o.accuracy}%, Type: {o.device_type or 'N/A'})")

        lines.extend([
            "\n------------------------------------------------------------------",
            "RAW TERMINAL OUTPUT:",
            "------------------------------------------------------------------",
            scan.raw_output or "No raw output recorded."
        ])

        if scan.error:
            lines.extend([
                "\n------------------------------------------------------------------",
                "ERRORS / WARNINGS:",
                "------------------------------------------------------------------",
                scan.error
            ])

        return "\n".join(lines)
