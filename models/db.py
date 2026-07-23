"""
Database models for NMAP-X Cybersecurity Reconnaissance Platform.
Uses Flask-SQLAlchemy with SQLite to persist scans, hosts, ports, and OS matches.
"""

from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class Scan(db.Model):
    __tablename__ = 'scans'

    id = db.Column(db.Integer, primary_key=True)
    target = db.Column(db.String(255), nullable=False)
    scan_type = db.Column(db.String(100), nullable=False)
    command = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(50), nullable=False, default='PENDING')
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime, nullable=True)
    duration = db.Column(db.Float, nullable=True, default=0.0)
    raw_output = db.Column(db.Text, nullable=True)
    error = db.Column(db.Text, nullable=True)

    hosts = db.relationship('Host', backref='scan', cascade='all, delete-orphan')

    def to_dict(self):
        return {
            'id': self.id,
            'target': self.target,
            'scan_type': self.scan_type,
            'command': self.command,
            'status': self.status,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'duration': self.duration,
            'raw_output': self.raw_output,
            'error': self.error,
            'host_count': len(self.hosts)
        }

class Host(db.Model):
    __tablename__ = 'hosts'

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False)
    address = db.Column(db.String(100), nullable=False)
    hostname = db.Column(db.String(255), nullable=True)
    state = db.Column(db.String(50), nullable=True, default='unknown')
    reason = db.Column(db.String(100), nullable=True)
    latency = db.Column(db.String(50), nullable=True)

    ports = db.relationship('Port', backref='host', cascade='all, delete-orphan')
    os_matches = db.relationship('OSDetection', backref='host', cascade='all, delete-orphan')

    def to_dict(self):
        return {
            'id': self.id,
            'scan_id': self.scan_id,
            'address': self.address,
            'hostname': self.hostname,
            'state': self.state,
            'reason': self.reason,
            'latency': self.latency,
            'ports': [p.to_dict() for p in self.ports],
            'os_matches': [o.to_dict() for o in self.os_matches]
        }

class Port(db.Model):
    __tablename__ = 'ports'

    id = db.Column(db.Integer, primary_key=True)
    host_id = db.Column(db.Integer, db.ForeignKey('hosts.id'), nullable=False)
    port = db.Column(db.Integer, nullable=False)
    protocol = db.Column(db.String(20), nullable=False, default='tcp')
    state = db.Column(db.String(50), nullable=False, default='unknown')
    service = db.Column(db.String(100), nullable=True)
    product = db.Column(db.String(150), nullable=True)
    version = db.Column(db.String(100), nullable=True)
    extra_info = db.Column(db.Text, nullable=True)

    def to_dict(self):
        return {
            'id': self.id,
            'host_id': self.host_id,
            'port': self.port,
            'protocol': self.protocol,
            'state': self.state,
            'service': self.service,
            'product': self.product,
            'version': self.version,
            'extra_info': self.extra_info
        }

class OSDetection(db.Model):
    __tablename__ = 'os_detections'

    id = db.Column(db.Integer, primary_key=True)
    host_id = db.Column(db.Integer, db.ForeignKey('hosts.id'), nullable=False)
    name = db.Column(db.String(255), nullable=False)
    accuracy = db.Column(db.String(20), nullable=True, default='0')
    device_type = db.Column(db.String(100), nullable=True)
    cpe = db.Column(db.Text, nullable=True)

    def to_dict(self):
        return {
            'id': self.id,
            'host_id': self.host_id,
            'name': self.name,
            'accuracy': self.accuracy,
            'device_type': self.device_type,
            'cpe': self.cpe
        }
