import os
from datetime import datetime
from flask import Flask, render_template, jsonify, request, Response, make_response
from config import config_by_name
from models.db import db, Scan
from models.persistence import ScanPersistenceManager
from modules.report_exporter import ReportExportService
from scanner.validators import ValidationError
from modules.host_discovery import HostDiscoveryService
from modules.port_scanning import PortScanningService
from modules.network_scans import NetworkScanService
from modules.fingerprinting import FingerprintingService
from modules.enumeration import EnumerationService
from modules.footprinting import WebFootprintingService
from modules.vulnerability_scanner import VulnerabilityScannerService

from scanner.tool_checker import ToolCheckerService
from scanner.tool_installer import ToolInstallerService, ensure_all_python_script_paths_in_path

ensure_all_python_script_paths_in_path()

def create_app(config_name=None):
    if config_name is None:
        config_name = os.getenv('FLASK_CONFIG', 'default')

    app = Flask(__name__)
    app.config.from_object(config_by_name[config_name])

    # Database configuration for SQLite
    db_path = os.path.join(app.root_path, 'nmap_x.db')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', f'sqlite:///{db_path}')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    db.init_app(app)

    with app.app_context():
        db.create_all()

    # Ensure required directories exist
    os.makedirs(app.config.get('REPORT_DIR', 'reports'), exist_ok=True)
    os.makedirs('scanner', exist_ok=True)
    os.makedirs('modules', exist_ok=True)
    os.makedirs('models', exist_ok=True)
    os.makedirs('tests', exist_ok=True)

    # Context Processor for common navigation items
    @app.context_processor
    def inject_nav():
        nav_items = [
            {'name': 'Dashboard', 'endpoint': 'dashboard', 'icon': 'fa-tachometer-alt', 'implemented': True},
            {'name': 'Host Discovery', 'endpoint': 'host_discovery', 'icon': 'fa-network-wired', 'implemented': True},
            {'name': 'Port Scanning', 'endpoint': 'port_scanning', 'icon': 'fa-ethernet', 'implemented': True},
            {'name': 'TCP Scans', 'endpoint': 'tcp_scans', 'icon': 'fa-stream', 'implemented': True},
            {'name': 'UDP Scans', 'endpoint': 'udp_scans', 'icon': 'fa-bolt', 'implemented': True},
            {'name': 'ICMP Scans', 'endpoint': 'icmp_scans', 'icon': 'fa-satellite-dish', 'implemented': True},
            {'name': 'Version Detection', 'endpoint': 'version_detection', 'icon': 'fa-microchip', 'implemented': True},
            {'name': 'OS Detection', 'endpoint': 'os_detection', 'icon': 'fa-desktop', 'implemented': True},
            {'name': 'Banner Grabbing', 'endpoint': 'banner_grabbing', 'icon': 'fa-flag', 'implemented': True},
            {'name': 'Enumeration', 'endpoint': 'enumeration', 'icon': 'fa-list-ol', 'implemented': True},
            {'name': 'Website Footprinting', 'endpoint': 'website_footprinting', 'icon': 'fa-globe', 'implemented': True},
            {'name': 'Vulnerability Scanner', 'endpoint': 'vulnerability_scanner', 'icon': 'fa-bug', 'implemented': True},
            {'name': 'Dependency Manager', 'endpoint': 'dependencies', 'icon': 'fa-download', 'implemented': True},
            {'name': 'Reports & History', 'endpoint': 'reports', 'icon': 'fa-file-alt', 'implemented': True},
            {'name': 'Settings', 'endpoint': 'settings', 'icon': 'fa-cog', 'implemented': True},
        ]
        return dict(nav_items=nav_items)

    # Dashboard & Health Check
    @app.route('/')
    @app.route('/dashboard')
    def dashboard():
        metrics = ScanPersistenceManager.get_dashboard_metrics()
        recent_scans = Scan.query.order_by(Scan.id.desc()).limit(10).all()
        tool_statuses = ToolCheckerService.get_all_tool_statuses()
        nmap_status = tool_statuses.get('nmap', {})
        return render_template(
            'dashboard.html',
            metrics=metrics,
            recent_scans=recent_scans,
            tool_statuses=tool_statuses,
            nmap_status=nmap_status
        )

    @app.route('/health')
    def health_check():
        return jsonify({
            'status': 'healthy',
            'app': app.config['APP_NAME'],
            'version': app.config['VERSION']
        }), 200

    # View Routes
    @app.route('/host-discovery')
    def host_discovery():
        return render_template('host_discovery.html')

    @app.route('/port-scanning')
    def port_scanning():
        return render_template('port_scanning.html')

    @app.route('/tcp-scans')
    def tcp_scans():
        return render_template('scan_shared_view.html',
            page_title='TCP Packet Scans',
            page_description='Perform SYN (-sS), Connect (-sT), ACK (-sA), Window (-sW), and Maimon (-sM) TCP scans.',
            mode_code='TCP',
            has_scan_type=True,
            has_port_options=True,
            default_ports='21,22,25,80,443,8080',
            api_endpoint='/api/v1/scan/tcp'
        )

    @app.route('/udp-scans')
    def udp_scans():
        return render_template('scan_shared_view.html',
            page_title='UDP Service Scans',
            page_description='Scan open and open|filtered UDP service ports (-sU).',
            mode_code='UDP',
            has_scan_type=False,
            has_port_options=True,
            default_ports='53,67,68,69,123,137,138,161,500',
            api_endpoint='/api/v1/scan/udp'
        )

    @app.route('/icmp-scans')
    def icmp_scans():
        return render_template('scan_shared_view.html',
            page_title='ICMP Ping Scans',
            page_description='Transmit ICMP Echo (-PE), Timestamp (-PP), and Netmask (-PM) discovery requests.',
            mode_code='ICMP',
            has_scan_type=False,
            has_port_options=False,
            has_icmp_flags=True,
            api_endpoint='/api/v1/scan/icmp'
        )

    @app.route('/version-detection')
    def version_detection():
        return render_template('fingerprint_shared_view.html',
            page_title='Service Version Detection',
            page_description='Determine application service name, product, version, and CPE tags (-sV, --version-intensity).',
            mode_code='VERSION',
            has_version_select=True,
            default_ports='21,22,25,53,80,110,143,443,3306,8080',
            api_endpoint='/api/v1/scan/version-detection'
        )

    @app.route('/os-detection')
    def os_detection():
        return render_template('fingerprint_shared_view.html',
            page_title='Operating System Fingerprinting',
            page_description='Fingerprint remote host Operating System, TCP/IP stack implementation, and device type (-O).',
            mode_code='OS',
            has_os_options=True,
            default_ports='22,80,443',
            api_endpoint='/api/v1/scan/os-detection'
        )

    @app.route('/banner-grabbing')
    def banner_grabbing():
        return render_template('fingerprint_shared_view.html',
            page_title='Banner Grabbing Engine',
            page_description='Extract service connection banners and NSE script response signatures (--script=banner).',
            mode_code='BANNER',
            default_ports='21,22,25,80,110,143,443,3306,8080',
            api_endpoint='/api/v1/scan/banner-grabbing'
        )

    @app.route('/enumeration')
    def enumeration():
        return render_template('enumeration.html')

    @app.route('/website-footprinting')
    def website_footprinting():
        return render_template('website_footprinting.html')

    @app.route('/vulnerability-scanner')
    def vulnerability_scanner():
        return render_template('vulnerability_scanner.html')

    @app.route('/dependencies')
    def dependencies():
        tool_statuses = ToolCheckerService.get_all_tool_statuses()
        telemetry = ToolCheckerService.get_environment_telemetry()
        source_audit = ToolCheckerService.get_application_source_audit()
        return render_template('dependencies.html', tool_statuses=tool_statuses, telemetry=telemetry, source_audit=source_audit)

    @app.route('/api/v1/dependencies/audit', methods=['GET'])
    def api_dependencies_audit():
        audit = ToolCheckerService.get_application_source_audit()
        return jsonify({'audit': audit}), 200

    @app.route('/api/v1/scan/vulnerability-scan', methods=['POST'])
    def api_scan_vulnerability():
        data = request.get_json() or {}
        url = data.get('url', '').strip()
        skip_nikto = bool(data.get('skip_nikto', False))
        skip_fuzz = bool(data.get('skip_fuzz', False))

        if not url:
            return jsonify({'error': 'Target URL cannot be empty.'}), 400

        try:
            from scanner.validators import validate_url
            target_url = validate_url(url)
        except Exception as ve:
            return jsonify({'error': str(ve)}), 400

        service = VulnerabilityScannerService()
        ep_res = service.discover_entry_points(target_url)

        nikto_res = {"status": "SKIPPED", "output": "Nikto scan skipped by user."} if skip_nikto else service.run_nikto_scan(target_url)
        fuzz_res = {"status": "SKIPPED", "findings": []} if skip_fuzz else service.run_fuzz_testing(target_url)

        # Generate report file
        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_filename = f"Web_Vulnerability_Scan_{timestamp_str}.txt"
        report_path = os.path.join(app.config.get('REPORT_DIR', 'reports'), report_filename)
        service.generate_ascii_report(target_url, ep_res, nikto_res, fuzz_res, report_path)

        # Persist scan job
        scan_record = ScanPersistenceManager.save_scan(
            target=target_url,
            scan_type="VULN_SCAN",
            command=f"vulnerability-scanner --url {target_url}",
            status="SUCCESS" if ep_res.get("status") == "SUCCESS" else "ERROR",
            raw_output=f"Entry Points: {len(ep_res.get('entry_points', {}).get('forms', []))} forms found.\nNikto: {nikto_res.get('status')}\nFuzzing Findings: {len(fuzz_res.get('findings', []))}",
            parsed_data={"entry_points": ep_res, "nikto": nikto_res, "fuzzing": fuzz_res},
            duration=3.5,
            error_message=ep_res.get("error")
        )

        return jsonify({
            'status': 'SUCCESS',
            'scan_id': scan_record.id,
            'target_url': target_url,
            'report_file': report_filename,
            'entry_points': ep_res,
            'nikto': nikto_res,
            'fuzzing': fuzz_res
        }), 200

    @app.route('/api/v1/tools/status', methods=['GET'])
    def api_tools_status():
        tool_statuses = ToolCheckerService.get_all_tool_statuses()
        telemetry = ToolCheckerService.get_environment_telemetry()
        return jsonify({
            'tool_statuses': tool_statuses,
            'telemetry': telemetry
        }), 200

    @app.route('/api/v1/tools/install', methods=['POST'])
    def api_tools_install():
        data = request.get_json() or {}
        tool_name = data.get('tool', '').strip().lower()
        if not tool_name:
            return jsonify({'error': 'Tool name cannot be empty.'}), 400

        result = ToolInstallerService.install_tool(tool_name)
        updated_status = ToolCheckerService.check_tool(tool_name)
        result['updated_status'] = updated_status
        status_code = 200 if result.get('success') else 400
        return jsonify(result), status_code

    @app.route('/api/v1/tools/check-all', methods=['POST'])
    def api_tools_check_all():
        tool_statuses = ToolCheckerService.get_all_tool_statuses()
        return jsonify({'tool_statuses': tool_statuses}), 200

    @app.route('/api/v1/tools/retry-install', methods=['POST'])
    def api_tools_retry_install():
        data = request.get_json() or {}
        tool_name = data.get('tool', '').strip().lower()
        if not tool_name:
            return jsonify({'error': 'Tool name cannot be empty.'}), 400

        result = ToolInstallerService.install_tool(tool_name)
        updated_status = ToolCheckerService.check_tool(tool_name)
        result['updated_status'] = updated_status
        status_code = 200 if result.get('success') else 400
        return jsonify(result), status_code

    @app.route('/reports')
    def reports():
        search = request.args.get('search', '').strip()
        scan_type = request.args.get('scan_type', '').strip()
        status = request.args.get('status', '').strip()
        sort = request.args.get('sort', 'desc').strip()

        query = Scan.query

        if search:
            query = query.filter(Scan.target.ilike(f'%{search}%'))
        if scan_type:
            query = query.filter(Scan.scan_type == scan_type)
        if status:
            query = query.filter(Scan.status == status)

        if sort == 'asc':
            query = query.order_by(Scan.id.asc())
        else:
            query = query.order_by(Scan.id.desc())

        scans = query.all()
        query_params = {
            'search': search,
            'scan_type': scan_type,
            'status': status,
            'sort': sort
        }
        return render_template('reports.html', scans=scans, query_params=query_params)

    @app.route('/scans/<int:scan_id>')
    def scan_detail(scan_id):
        scan = db.session.get(Scan, scan_id)
        if not scan:
            return render_template('404.html'), 404
        return render_template('scan_detail.html', scan=scan)

    @app.route('/reports/<int:scan_id>/export')
    def export_report(scan_id):
        scan = db.session.get(Scan, scan_id)
        if not scan:
            return render_template('404.html'), 404

        fmt = request.args.get('format', 'txt').lower()
        safe_target = ReportExportService.sanitize_filename(scan.target)
        base_filename = f"scan_{scan.id}_{safe_target}"

        if fmt == 'json':
            content = ReportExportService.export_json(scan)
            mimetype = 'application/json'
            filename = f"{base_filename}.json"
        elif fmt == 'csv':
            content = ReportExportService.export_csv(scan)
            mimetype = 'text/csv'
            filename = f"{base_filename}.csv"
        else:
            content = ReportExportService.export_text(scan)
            mimetype = 'text/plain'
            filename = f"{base_filename}.txt"

        response = make_response(content)
        response.headers['Content-Type'] = mimetype
        response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
        return response

    # Security Middleware: Enforce application/json for API requests to mitigate simple CSRF
    @app.before_request
    def enforce_json_api_security():
        if request.path.startswith('/api/') and request.method in ['POST', 'PUT', 'DELETE']:
            if not request.is_json:
                return jsonify({'error': 'Unsupported Media Type: Content-Type must be application/json'}), 415

    # API Endpoints with Automatic Database Persistence
    @app.route('/api/v1/scan/host-discovery', methods=['POST'])
    def api_host_discovery():
        data = request.get_json() or {}
        try:
            service = HostDiscoveryService()
            result = service.run_discovery(
                target=data.get('target', ''),
                discovery_flags=data.get('flags', ['-sn', '-PE', '-PA']),
                timing=data.get('timing', '-T4')
            )
            result['scan_type'] = 'HOST_DISCOVERY'
            ScanPersistenceManager.save_scan_result(None, result)
            return jsonify(result), 200
        except ValidationError as e:
            return jsonify({'error': str(e)}), 400
        except Exception as e:
            return jsonify({'error': f'Internal scan failure: {str(e)}'}), 500

    @app.route('/api/v1/scan/port-scanning', methods=['POST'])
    def api_port_scanning():
        data = request.get_json() or {}
        try:
            service = PortScanningService()
            result = service.run_port_scan(
                target=data.get('target', ''),
                scan_type=data.get('scan_type', '-sS'),
                port_selection_type=data.get('port_selection_type', 'specific'),
                ports=data.get('ports', None),
                top_ports_count=data.get('top_ports_count', 100),
                timing=data.get('timing', '-T4')
            )
            result['scan_type'] = 'PORT_SCANNING'
            ScanPersistenceManager.save_scan_result(None, result)
            return jsonify(result), 200
        except ValidationError as e:
            return jsonify({'error': str(e)}), 400
        except Exception as e:
            return jsonify({'error': f'Internal scan failure: {str(e)}'}), 500

    @app.route('/api/v1/scan/tcp', methods=['POST'])
    def api_tcp_scan():
        data = request.get_json() or {}
        try:
            service = NetworkScanService()
            result = service.run_tcp_scan(
                target=data.get('target', ''),
                tcp_flag=data.get('scan_type', '-sS'),
                ports=data.get('ports', None),
                timing=data.get('timing', '-T4')
            )
            ScanPersistenceManager.save_scan_result(None, result)
            return jsonify(result), 200
        except ValidationError as e:
            return jsonify({'error': str(e)}), 400
        except Exception as e:
            return jsonify({'error': f'Internal scan failure: {str(e)}'}), 500

    @app.route('/api/v1/scan/udp', methods=['POST'])
    def api_udp_scan():
        data = request.get_json() or {}
        try:
            service = NetworkScanService()
            result = service.run_udp_scan(
                target=data.get('target', ''),
                ports=data.get('ports', None),
                timing=data.get('timing', '-T4')
            )
            ScanPersistenceManager.save_scan_result(None, result)
            return jsonify(result), 200
        except ValidationError as e:
            return jsonify({'error': str(e)}), 400
        except Exception as e:
            return jsonify({'error': f'Internal scan failure: {str(e)}'}), 500

    @app.route('/api/v1/scan/icmp', methods=['POST'])
    def api_icmp_scan():
        data = request.get_json() or {}
        try:
            service = NetworkScanService()
            result = service.run_icmp_scan(
                target=data.get('target', ''),
                icmp_flags=data.get('icmp_flags', ['-PE', '-sn']),
                timing=data.get('timing', '-T4')
            )
            ScanPersistenceManager.save_scan_result(None, result)
            return jsonify(result), 200
        except ValidationError as e:
            return jsonify({'error': str(e)}), 400
        except Exception as e:
            return jsonify({'error': f'Internal scan failure: {str(e)}'}), 500

    @app.route('/api/v1/scan/version-detection', methods=['POST'])
    def api_version_detection():
        data = request.get_json() or {}
        try:
            service = FingerprintingService()
            result = service.run_version_detection(
                target=data.get('target', ''),
                ports=data.get('ports', None),
                version_flag=data.get('version_flag', '-sV'),
                intensity=data.get('intensity', None),
                timing=data.get('timing', '-T4')
            )
            ScanPersistenceManager.save_scan_result(None, result)
            return jsonify(result), 200
        except ValidationError as e:
            return jsonify({'error': str(e)}), 400
        except Exception as e:
            return jsonify({'error': f'Internal scan failure: {str(e)}'}), 500

    @app.route('/api/v1/scan/os-detection', methods=['POST'])
    def api_os_detection():
        data = request.get_json() or {}
        try:
            service = FingerprintingService()
            result = service.run_os_detection(
                target=data.get('target', ''),
                ports=data.get('ports', None),
                os_options=data.get('os_options', None),
                timing=data.get('timing', '-T4')
            )
            ScanPersistenceManager.save_scan_result(None, result)
            return jsonify(result), 200
        except ValidationError as e:
            return jsonify({'error': str(e)}), 400
        except Exception as e:
            return jsonify({'error': f'Internal scan failure: {str(e)}'}), 500

    @app.route('/api/v1/scan/banner-grabbing', methods=['POST'])
    def api_banner_grabbing():
        data = request.get_json() or {}
        try:
            service = FingerprintingService()
            result = service.run_banner_grabbing(
                target=data.get('target', ''),
                ports=data.get('ports', None),
                timing=data.get('timing', '-T4')
            )
            ScanPersistenceManager.save_scan_result(None, result)
            return jsonify(result), 200
        except ValidationError as e:
            return jsonify({'error': str(e)}), 400
        except Exception as e:
            return jsonify({'error': f'Internal scan failure: {str(e)}'}), 500

    @app.route('/api/v1/scan/enumeration', methods=['POST'])
    def api_enumeration():
        data = request.get_json() or {}
        domain = data.get('domain', '')
        selected_modules = data.get('modules', ['dnsmap', 'urlcrazy', 'whois', 'dnsrecon', 'zone_transfer'])
        
        try:
            service = EnumerationService()
            result = service.run_selected_enumeration(domain, selected_modules)
            result_dict = {
                "target": domain,
                "scan_type": "ENUMERATION",
                "execution": {"status": "SUCCESS", "duration": 0.0, "command": ["enumeration", domain], "stdout": result.get('combined_report', ''), "stderr": ""},
                "parsed": {}
            }
            ScanPersistenceManager.save_scan_result(None, result_dict)
            return jsonify(result), 200
        except ValidationError as e:
            return jsonify({'error': str(e)}), 400
        except Exception as e:
            return jsonify({'error': f'Internal scan failure: {str(e)}'}), 500

    @app.route('/api/v1/scan/website-footprinting', methods=['POST'])
    def api_website_footprinting():
        data = request.get_json() or {}
        url = data.get('url', '')
        selected_operations = data.get('operations', ['headers', 'server_tech'])
        mirror_opt_in = data.get('mirror_opt_in', False)

        try:
            service = WebFootprintingService()
            result = service.run_selected_footprinting(url, selected_operations, mirror_opt_in=mirror_opt_in)
            result_dict = {
                "target": url,
                "scan_type": "FOOTPRINTING",
                "execution": {"status": "SUCCESS", "duration": 0.0, "command": ["footprinting", url], "stdout": result.get('combined_report', ''), "stderr": ""},
                "parsed": {}
            }
            ScanPersistenceManager.save_scan_result(None, result_dict)
            return jsonify(result), 200
        except ValidationError as e:
            return jsonify({'error': str(e)}), 400
        except Exception as e:
            return jsonify({'error': f'Internal scan failure: {str(e)}'}), 500

    # Module placeholder route handler helper
    def render_module_placeholder(title, category, description):
        return render_template('module_placeholder.html', title=title, category=category, description=description)

    @app.route('/settings')
    def settings():
        return render_module_placeholder('Platform Settings', 'Configuration', 'Scan scope guardrails, rate limits, Nmap binary paths, and proxy options.')

    # Error Handlers
    @app.errorhandler(404)
    def page_not_found(e):
        return render_template('404.html'), 404

    @app.errorhandler(500)
    def internal_server_error(e):
        return render_template('500.html'), 500

    return app

if __name__ == '__main__':
    app = create_app('development')
    app.run(host='127.0.0.1', port=5000, debug=True)
