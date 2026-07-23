"""
Scan persistence manager for storing and retrieving scan results from SQLite database.
"""

from datetime import datetime
from typing import Dict, Any, Optional
from models.db import db, Scan, Host, Port, OSDetection

class ScanPersistenceManager:
    """
    Persistence helper storing scan execution results and parsed data models into database.
    """

    @staticmethod
    def create_scan_record(target: str, scan_type: str, command: str = "") -> Scan:
        scan = Scan(
            target=target,
            scan_type=scan_type,
            command=command,
            status='RUNNING',
            started_at=datetime.utcnow()
        )
        db.session.add(scan)
        db.session.commit()
        return scan

    @staticmethod
    def save_scan_result(scan_id: Optional[int], scan_result_dict: Dict[str, Any]) -> Scan:
        scan = db.session.get(Scan, scan_id) if scan_id else None
        if not scan:
            scan = Scan(
                target=scan_result_dict.get('target', 'unknown'),
                scan_type=scan_result_dict.get('scan_type', 'UNKNOWN')
            )
            db.session.add(scan)

        exec_data = scan_result_dict.get('execution', {})
        parsed_data = scan_result_dict.get('parsed', {})

        scan.status = exec_data.get('status', 'COMPLETED')
        scan.completed_at = datetime.utcnow()
        scan.duration = exec_data.get('duration', 0.0)
        scan.command = " ".join(exec_data.get('command', [])) if isinstance(exec_data.get('command'), list) else str(exec_data.get('command', ''))
        scan.raw_output = exec_data.get('stdout', '') or exec_data.get('stderr', '')
        scan.error = exec_data.get('error') or parsed_data.get('parsing_error')

        # Clear any existing host records if re-saving
        Host.query.filter_by(scan_id=scan.id).delete()

        # Save Hosts
        hosts_list = parsed_data.get('hosts', [])
        host_obj_map = {}

        for h in hosts_list:
            host_obj = Host(
                scan_id=scan.id,
                address=h.get('address', '0.0.0.0'),
                hostname=h.get('hostname', ''),
                state=h.get('state', 'unknown'),
                reason=h.get('reason', ''),
                latency=h.get('latency', '')
            )
            db.session.add(host_obj)
            db.session.flush()  # Gets host_obj.id
            host_obj_map[host_obj.address] = host_obj

        # Save Ports
        ports_list = parsed_data.get('ports', [])
        for p in ports_list:
            host_addr = p.get('host', '0.0.0.0')
            host_obj = host_obj_map.get(host_addr)
            if not host_obj:
                host_obj = Host(scan_id=scan.id, address=host_addr, state='up')
                db.session.add(host_obj)
                db.session.flush()
                host_obj_map[host_addr] = host_obj

            port_obj = Port(
                host_id=host_obj.id,
                port=p.get('port', 0),
                protocol=p.get('protocol', 'tcp'),
                state=p.get('state', 'unknown'),
                service=p.get('service', 'unknown'),
                product=p.get('product', ''),
                version=p.get('version', ''),
                extra_info=p.get('extra_info', '')
            )
            db.session.add(port_obj)

        # Save OS Matches
        os_list = parsed_data.get('os_matches', [])
        for o in os_list:
            host_addr = o.get('host', '0.0.0.0')
            host_obj = host_obj_map.get(host_addr)
            if not host_obj:
                host_obj = Host(scan_id=scan.id, address=host_addr, state='up')
                db.session.add(host_obj)
                db.session.flush()
                host_obj_map[host_addr] = host_obj

            cpe_str = ", ".join(o.get('cpe', [])) if isinstance(o.get('cpe'), list) else str(o.get('cpe', ''))
            os_obj = OSDetection(
                host_id=host_obj.id,
                name=o.get('name', 'Unknown OS'),
                accuracy=str(o.get('accuracy', '0')),
                device_type=o.get('device_type', ''),
                cpe=cpe_str
            )
            db.session.add(os_obj)

        db.session.commit()
        return scan

    @staticmethod
    def get_dashboard_metrics() -> Dict[str, Any]:
        total_scans = Scan.query.count()
        completed_scans = Scan.query.filter(Scan.status.in_(['SUCCESS', 'COMPLETED'])).count()
        failed_scans = Scan.query.filter(Scan.status.in_(['ERROR', 'TIMEOUT', 'PERMISSION_DENIED', 'NOT_INSTALLED', 'FAILED'])).count()
        hosts_discovered = Host.query.filter_by(state='up').count()
        open_ports = Port.query.filter_by(state='open').count()
        last_scan = Scan.query.order_by(Scan.id.desc()).first()

        return {
            'total_scans': total_scans,
            'completed_scans': completed_scans,
            'failed_scans': failed_scans,
            'hosts_discovered': hosts_discovered,
            'open_ports': open_ports,
            'last_scan': last_scan.to_dict() if last_scan else None
        }
