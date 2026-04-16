"""
OceanCSec — Flask REST API backend
Run:  python app.py
      ADMIN_USER=admin ADMIN_PASS=changeme python app.py
"""
import io
import os
import threading
from datetime import datetime
from functools import wraps

from flask import Flask, jsonify, request, send_file, render_template, session
from flask_cors import CORS

from database import db, Client, Scan
from scanners import run_scan
from reports import generate_pdf_report

# ─────────────────────────────────────────────
# App setup
# ─────────────────────────────────────────────

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'oceancsec-dev-key-change-in-prod')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///oceancsec.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

CORS(app, supports_credentials=True, origins='*')
db.init_app(app)

ADMIN_USER = os.environ.get('ADMIN_USER', 'admin')
ADMIN_PASS = os.environ.get('ADMIN_PASS', 'oceancsec2024')


# ─────────────────────────────────────────────
# Auth helpers
# ─────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('logged_in'):
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated


# ─────────────────────────────────────────────
# Static / frontend
# ─────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('dashboard.html')


# ─────────────────────────────────────────────
# Auth endpoints
# ─────────────────────────────────────────────

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    if data.get('username') == ADMIN_USER and data.get('password') == ADMIN_PASS:
        session['logged_in'] = True
        return jsonify({'success': True, 'username': ADMIN_USER})
    return jsonify({'error': 'Invalid credentials'}), 401


@app.route('/api/logout', methods=['POST'])
def logout():
    session.pop('logged_in', None)
    return jsonify({'success': True})


@app.route('/api/auth/status')
def auth_status():
    return jsonify({'logged_in': bool(session.get('logged_in'))})


# ─────────────────────────────────────────────
# Stats
# ─────────────────────────────────────────────

@app.route('/api/stats')
@login_required
def get_stats():
    total_clients   = Client.query.count()
    total_scans     = Scan.query.count()
    active_scans    = Scan.query.filter_by(status='running').count()
    completed_scans = Scan.query.filter_by(status='completed').count()
    failed_scans    = Scan.query.filter_by(status='failed').count()

    vuln_count = 0
    for scan in Scan.query.filter_by(status='completed').all():
        r = scan.get_results()
        vuln_count += len(r.get('nuclei', {}).get('findings', []))
        vuln_count += len(r.get('zap',    {}).get('alerts',   []))
        vuln_count += len(r.get('nikto',  {}).get('findings', []))

    recent_scans = (
        Scan.query
        .order_by(Scan.created_at.desc())
        .limit(5)
        .all()
    )

    return jsonify({
        'total_clients':       total_clients,
        'total_scans':         total_scans,
        'active_scans':        active_scans,
        'completed_scans':     completed_scans,
        'failed_scans':        failed_scans,
        'vulnerabilities_found': vuln_count,
        'recent_scans':        [s.to_dict() for s in recent_scans],
    })


# ─────────────────────────────────────────────
# Clients
# ─────────────────────────────────────────────

@app.route('/api/clients', methods=['GET'])
@login_required
def get_clients():
    clients = Client.query.order_by(Client.name).all()
    return jsonify([c.to_dict() for c in clients])


@app.route('/api/clients', methods=['POST'])
@login_required
def create_client():
    data = request.get_json() or {}
    if not data.get('name', '').strip():
        return jsonify({'error': 'name is required'}), 400

    client = Client(
        name          = data['name'].strip(),
        domain        = data.get('domain', ''),
        contact_name  = data.get('contact_name', ''),
        contact_email = data.get('contact_email', ''),
        industry      = data.get('industry', ''),
        notes         = data.get('notes', ''),
    )
    db.session.add(client)
    db.session.commit()
    return jsonify(client.to_dict()), 201


@app.route('/api/clients/<int:client_id>', methods=['GET'])
@login_required
def get_client(client_id):
    return jsonify(Client.query.get_or_404(client_id).to_dict())


@app.route('/api/clients/<int:client_id>', methods=['PUT'])
@login_required
def update_client(client_id):
    client = Client.query.get_or_404(client_id)
    data   = request.get_json() or {}
    for field in ('name', 'domain', 'contact_name', 'contact_email', 'industry', 'notes'):
        if field in data:
            setattr(client, field, data[field])
    db.session.commit()
    return jsonify(client.to_dict())


@app.route('/api/clients/<int:client_id>', methods=['DELETE'])
@login_required
def delete_client(client_id):
    client = Client.query.get_or_404(client_id)
    db.session.delete(client)
    db.session.commit()
    return jsonify({'success': True})


# ─────────────────────────────────────────────
# Scans
# ─────────────────────────────────────────────

@app.route('/api/scans', methods=['GET'])
@login_required
def get_scans():
    client_id = request.args.get('client_id', type=int)
    query = Scan.query.order_by(Scan.created_at.desc())
    if client_id:
        query = query.filter_by(client_id=client_id)
    return jsonify([s.to_dict() for s in query.all()])


@app.route('/api/scans', methods=['POST'])
@login_required
def create_scan():
    data = request.get_json() or {}

    if not data.get('client_id'):
        return jsonify({'error': 'client_id is required'}), 400
    if not data.get('target', '').strip():
        return jsonify({'error': 'target is required'}), 400

    # Validate client exists
    Client.query.get_or_404(int(data['client_id']))

    scan_types = data.get('scan_types', ['nmap'])
    if isinstance(scan_types, list):
        scan_types = ','.join(t.strip() for t in scan_types if t.strip())

    scan = Scan(
        client_id  = int(data['client_id']),
        target     = data['target'].strip(),
        scan_types = scan_types,
        notes      = data.get('notes', ''),
    )
    db.session.add(scan)
    db.session.commit()

    if data.get('auto_run', False):
        t = threading.Thread(target=run_scan, args=(scan.id, app), daemon=True)
        t.start()

    return jsonify(scan.to_dict()), 201


@app.route('/api/scans/<int:scan_id>', methods=['GET'])
@login_required
def get_scan(scan_id):
    return jsonify(Scan.query.get_or_404(scan_id).to_dict_full())


@app.route('/api/scans/<int:scan_id>/run', methods=['POST'])
@login_required
def run_scan_endpoint(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    if scan.status == 'running':
        return jsonify({'error': 'Scan is already running'}), 400

    scan.status = 'pending'
    db.session.commit()

    t = threading.Thread(target=run_scan, args=(scan.id, app), daemon=True)
    t.start()
    return jsonify({'success': True, 'message': f'Scan #{scan_id} started'})


@app.route('/api/scans/<int:scan_id>', methods=['DELETE'])
@login_required
def delete_scan(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    if scan.status == 'running':
        return jsonify({'error': 'Cannot delete a running scan'}), 400
    db.session.delete(scan)
    db.session.commit()
    return jsonify({'success': True})


# ─────────────────────────────────────────────
# Reports
# ─────────────────────────────────────────────

@app.route('/api/reports/<int:scan_id>/pdf', methods=['GET'])
@login_required
def download_report(scan_id):
    scan   = Scan.query.get_or_404(scan_id)
    client = Client.query.get_or_404(scan.client_id)

    if scan.status != 'completed':
        return jsonify({'error': 'Scan has not completed yet'}), 400

    try:
        pdf_bytes = generate_pdf_report(scan, client)
        safe_name = client.name.replace(' ', '_').replace('/', '-')
        filename  = f'oceancsec-report-{safe_name}-scan{scan.id}.pdf'

        return send_file(
            io.BytesIO(pdf_bytes),
            mimetype='application/pdf',
            as_attachment=True,
            download_name=filename,
        )
    except Exception as e:
        return jsonify({'error': f'Report generation failed: {e}'}), 500


# ─────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        print('OceanCSec scanner ready — http://0.0.0.0:5000')
        print(f'  Admin user: {ADMIN_USER}')
    app.run(debug=False, host='0.0.0.0', port=5000)
