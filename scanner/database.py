"""
OceanCSec — Database models (SQLite via SQLAlchemy)
"""
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import json

db = SQLAlchemy()


class Client(db.Model):
    __tablename__ = 'clients'

    id           = db.Column(db.Integer, primary_key=True)
    name         = db.Column(db.String(200), nullable=False)
    domain       = db.Column(db.String(200), default='')
    contact_name  = db.Column(db.String(200), default='')
    contact_email = db.Column(db.String(200), default='')
    industry     = db.Column(db.String(100), default='')
    notes        = db.Column(db.Text, default='')
    created_at   = db.Column(db.DateTime, default=datetime.utcnow)

    scans = db.relationship('Scan', backref='client', lazy=True,
                            cascade='all, delete-orphan')

    def to_dict(self):
        return {
            'id':            self.id,
            'name':          self.name,
            'domain':        self.domain,
            'contact_name':  self.contact_name,
            'contact_email': self.contact_email,
            'industry':      self.industry,
            'notes':         self.notes,
            'created_at':    self.created_at.isoformat() if self.created_at else None,
            'scan_count':    len(self.scans),
        }


class Scan(db.Model):
    __tablename__ = 'scans'

    id            = db.Column(db.Integer, primary_key=True)
    client_id     = db.Column(db.Integer, db.ForeignKey('clients.id'), nullable=False)
    target        = db.Column(db.String(500), nullable=False)
    scan_types    = db.Column(db.String(200), default='nmap')
    status        = db.Column(db.String(50), default='pending')
    notes         = db.Column(db.Text, default='')
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)
    started_at    = db.Column(db.DateTime)
    completed_at  = db.Column(db.DateTime)
    results_json  = db.Column(db.Text, default='{}')
    error_message = db.Column(db.Text, default='')

    def get_results(self):
        try:
            return json.loads(self.results_json) if self.results_json else {}
        except Exception:
            return {}

    def set_results(self, results_dict):
        self.results_json = json.dumps(results_dict)

    def to_dict(self):
        return {
            'id':            self.id,
            'client_id':     self.client_id,
            'client_name':   self.client.name if self.client else None,
            'target':        self.target,
            'scan_types':    self.scan_types.split(',') if self.scan_types else [],
            'status':        self.status,
            'notes':         self.notes,
            'created_at':    self.created_at.isoformat()   if self.created_at   else None,
            'started_at':    self.started_at.isoformat()   if self.started_at   else None,
            'completed_at':  self.completed_at.isoformat() if self.completed_at else None,
            'error_message': self.error_message,
        }

    def to_dict_full(self):
        d = self.to_dict()
        d['results'] = self.get_results()
        return d
