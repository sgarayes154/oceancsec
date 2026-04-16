"""
OceanCSec — Scanner wrappers for Nmap, Nuclei, Nikto, and OWASP ZAP.
Each scanner returns a structured dict that is stored in the Scan.results_json field.
"""
import subprocess
import json
import xml.etree.ElementTree as ET
import tempfile
import os
import logging
import time
from datetime import datetime

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────
# Nmap
# ─────────────────────────────────────────────

class NmapScanner:
    """Port scan + service/OS detection via nmap."""

    def scan(self, target, options=None):
        result = {
            'tool':      'nmap',
            'target':    target,
            'timestamp': datetime.utcnow().isoformat(),
            'hosts':     [],
            'error':     None,
        }
        try:
            with tempfile.NamedTemporaryFile(suffix='.xml', delete=False) as f:
                xml_file = f.name

            cmd = ['nmap', '-sV', '-sC', '-O', '--open', '-oX', xml_file]
            if options:
                cmd.extend(options)
            cmd.append(target)

            subprocess.run(cmd, capture_output=True, text=True, timeout=600)

            if os.path.exists(xml_file):
                with open(xml_file, 'r') as f:
                    xml_content = f.read()
                os.unlink(xml_file)
                result['hosts'] = self._parse_xml(xml_content)

        except FileNotFoundError:
            result['error'] = 'nmap not installed. Install with: apt install nmap'
        except subprocess.TimeoutExpired:
            result['error'] = 'Scan timed out after 10 minutes'
        except Exception as e:
            result['error'] = str(e)

        return result

    def _parse_xml(self, xml_content):
        hosts = []
        try:
            root = ET.fromstring(xml_content)
            for host_elem in root.findall('host'):
                host = {
                    'status':    'unknown',
                    'addresses': [],
                    'hostnames': [],
                    'ports':     [],
                    'os':        [],
                }

                status_elem = host_elem.find('status')
                if status_elem is not None:
                    host['status'] = status_elem.get('state', 'unknown')

                for addr_elem in host_elem.findall('address'):
                    host['addresses'].append({
                        'addr': addr_elem.get('addr', ''),
                        'type': addr_elem.get('addrtype', ''),
                    })

                for hn_elem in host_elem.findall('hostnames/hostname'):
                    host['hostnames'].append(hn_elem.get('name', ''))

                for port_elem in host_elem.findall('ports/port'):
                    state_elem   = port_elem.find('state')
                    service_elem = port_elem.find('service')

                    port = {
                        'protocol':   port_elem.get('protocol', ''),
                        'portid':     port_elem.get('portid', ''),
                        'state':      state_elem.get('state', 'unknown') if state_elem is not None else 'unknown',
                        'service':    '',
                        'product':    '',
                        'version':    '',
                        'extra_info': '',
                        'scripts':    [],
                    }

                    if service_elem is not None:
                        port['service']    = service_elem.get('name', '')
                        port['product']    = service_elem.get('product', '')
                        port['version']    = service_elem.get('version', '')
                        port['extra_info'] = service_elem.get('extrainfo', '')

                    for script_elem in port_elem.findall('script'):
                        port['scripts'].append({
                            'id':     script_elem.get('id', ''),
                            'output': script_elem.get('output', ''),
                        })

                    host['ports'].append(port)

                for osmatch_elem in host_elem.findall('os/osmatch'):
                    host['os'].append({
                        'name':     osmatch_elem.get('name', ''),
                        'accuracy': osmatch_elem.get('accuracy', ''),
                    })

                hosts.append(host)
        except Exception as e:
            logger.error('Error parsing nmap XML: %s', e)

        return hosts


# ─────────────────────────────────────────────
# Nuclei
# ─────────────────────────────────────────────

class NucleiScanner:
    """Template-based vulnerability scanner."""

    def scan(self, target, options=None):
        result = {
            'tool':      'nuclei',
            'target':    target,
            'timestamp': datetime.utcnow().isoformat(),
            'findings':  [],
            'error':     None,
        }
        try:
            cmd = ['nuclei', '-u', target, '-json', '-silent', '-no-color']
            if options:
                cmd.extend(options)

            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=1200)

            for line in proc.stdout.split('\n'):
                line = line.strip()
                if not line:
                    continue
                try:
                    raw = json.loads(line)
                    info = raw.get('info', {})
                    result['findings'].append({
                        'template_id': raw.get('template-id', ''),
                        'name':        info.get('name', ''),
                        'severity':    info.get('severity', 'info'),
                        'description': info.get('description', ''),
                        'matched_at':  raw.get('matched-at', ''),
                        'type':        raw.get('type', ''),
                        'tags':        info.get('tags', []),
                    })
                except json.JSONDecodeError:
                    pass

        except FileNotFoundError:
            result['error'] = 'nuclei not installed. See: https://github.com/projectdiscovery/nuclei'
        except subprocess.TimeoutExpired:
            result['error'] = 'Scan timed out after 20 minutes'
        except Exception as e:
            result['error'] = str(e)

        return result


# ─────────────────────────────────────────────
# Nikto
# ─────────────────────────────────────────────

class NiktoScanner:
    """Web server misconfiguration and CVE scanner."""

    def scan(self, target, options=None):
        result = {
            'tool':      'nikto',
            'target':    target,
            'timestamp': datetime.utcnow().isoformat(),
            'findings':  [],
            'error':     None,
        }
        try:
            with tempfile.NamedTemporaryFile(suffix='.json', delete=False, mode='w') as f:
                json_file = f.name

            cmd = ['nikto', '-h', target, '-Format', 'json', '-o', json_file, '-nointeractive']
            if options:
                cmd.extend(options)

            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)

            if os.path.exists(json_file):
                with open(json_file, 'r') as f:
                    content = f.read().strip()
                os.unlink(json_file)

                if content:
                    try:
                        data = json.loads(content)
                        vulns = data.get('vulnerabilities', data if isinstance(data, list) else [])
                        for v in vulns:
                            result['findings'].append({
                                'id':    v.get('id', ''),
                                'osvdb': v.get('OSVDB', ''),
                                'method': v.get('method', ''),
                                'url':   v.get('url', ''),
                                'msg':   v.get('msg', ''),
                            })
                    except json.JSONDecodeError:
                        result['findings'] = self._parse_text(proc.stdout)
                else:
                    result['findings'] = self._parse_text(proc.stdout)
            else:
                result['findings'] = self._parse_text(proc.stdout)

        except FileNotFoundError:
            result['error'] = 'nikto not installed. Install with: apt install nikto'
        except subprocess.TimeoutExpired:
            result['error'] = 'Scan timed out after 10 minutes'
        except Exception as e:
            result['error'] = str(e)

        return result

    def _parse_text(self, text):
        findings = []
        skip_prefixes = ('+ Target', '+ Start', '+ End', '+ 0 host(s)', '+ 1 host(s)')
        for line in text.split('\n'):
            line = line.strip()
            if line.startswith('+ ') and not any(line.startswith(p) for p in skip_prefixes):
                findings.append({'id': '', 'msg': line[2:], 'url': '', 'method': ''})
        return findings


# ─────────────────────────────────────────────
# OWASP ZAP
# ─────────────────────────────────────────────

class ZAPScanner:
    """Web application active scanner via ZAP REST API."""

    def __init__(self, zap_url='http://localhost:8080', api_key=''):
        self.zap_url = zap_url
        self.api_key = api_key

    def scan(self, target, options=None):
        result = {
            'tool':      'zap',
            'target':    target,
            'timestamp': datetime.utcnow().isoformat(),
            'alerts':    [],
            'error':     None,
        }
        try:
            import requests as req

            # Verify ZAP is running
            health = req.get(
                f'{self.zap_url}/JSON/core/view/version/',
                params={'apikey': self.api_key},
                timeout=10,
            )
            if health.status_code != 200:
                result['error'] = 'ZAP not responding. Start ZAP with: zaproxy -daemon -port 8080'
                return result

            # Spider
            spider_resp = req.get(
                f'{self.zap_url}/JSON/spider/action/scan/',
                params={'apikey': self.api_key, 'url': target},
                timeout=30,
            )
            spider_id = spider_resp.json().get('scan', '0')

            while True:
                st = req.get(
                    f'{self.zap_url}/JSON/spider/view/status/',
                    params={'apikey': self.api_key, 'scanId': spider_id},
                    timeout=10,
                ).json().get('status', '100')
                if int(st) >= 100:
                    break
                time.sleep(5)

            # Active scan
            ascan_resp = req.get(
                f'{self.zap_url}/JSON/ascan/action/scan/',
                params={'apikey': self.api_key, 'url': target},
                timeout=30,
            )
            ascan_id = ascan_resp.json().get('scan', '0')

            while True:
                st = req.get(
                    f'{self.zap_url}/JSON/ascan/view/status/',
                    params={'apikey': self.api_key, 'scanId': ascan_id},
                    timeout=10,
                ).json().get('status', '100')
                if int(st) >= 100:
                    break
                time.sleep(10)

            # Collect alerts
            alerts_resp = req.get(
                f'{self.zap_url}/JSON/alert/view/alerts/',
                params={'apikey': self.api_key, 'baseurl': target},
                timeout=30,
            )
            for alert in alerts_resp.json().get('alerts', []):
                result['alerts'].append({
                    'name':        alert.get('name', ''),
                    'risk':        alert.get('risk', ''),
                    'confidence':  alert.get('confidence', ''),
                    'description': alert.get('description', ''),
                    'solution':    alert.get('solution', ''),
                    'url':         alert.get('url', ''),
                    'cweid':       alert.get('cweid', ''),
                    'wascid':      alert.get('wascid', ''),
                })

        except ImportError:
            result['error'] = 'requests library not installed'
        except Exception as e:
            if 'Connection refused' in str(e):
                result['error'] = 'Cannot connect to ZAP. Start ZAP with: zaproxy -daemon -port 8080'
            else:
                result['error'] = str(e)

        return result


# ─────────────────────────────────────────────
# Orchestrator
# ─────────────────────────────────────────────

def run_scan(scan_id, app):
    """Run all selected tools for a scan. Executed in a background thread."""
    with app.app_context():
        from database import db, Scan

        scan = db.session.get(Scan, scan_id)
        if not scan:
            return

        scan.status     = 'running'
        scan.started_at = datetime.utcnow()
        db.session.commit()

        results    = {}
        scan_types = [t.strip() for t in (scan.scan_types or '').split(',') if t.strip()]
        target     = scan.target

        try:
            if 'nmap' in scan_types:
                results['nmap'] = NmapScanner().scan(target)

            if 'nuclei' in scan_types:
                results['nuclei'] = NucleiScanner().scan(target)

            if 'nikto' in scan_types:
                results['nikto'] = NiktoScanner().scan(target)

            if 'zap' in scan_types:
                results['zap'] = ZAPScanner().scan(target)

            scan.set_results(results)
            scan.status       = 'completed'
            scan.completed_at = datetime.utcnow()

        except Exception as e:
            scan.status        = 'failed'
            scan.error_message = str(e)
            scan.completed_at  = datetime.utcnow()

        db.session.commit()
