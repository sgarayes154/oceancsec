"""
OceanCSec — Professional PDF report generator (ReportLab).
"""
import io
from datetime import datetime

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib.colors import HexColor
from reportlab.lib.enums import TA_LEFT, TA_CENTER
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak,
)

# ── Brand colours ──────────────────────────────────────────────
DEEP    = HexColor('#020d18')
SURFACE = HexColor('#041525')
CURRENT = HexColor('#062038')
WAVE    = HexColor('#0d7abf')
CREST   = HexColor('#00c2ff')
ACCENT  = HexColor('#00ffc8')
MUTED   = HexColor('#6a99bb')
WHITE   = HexColor('#e8f4ff')

SEV_COLORS = {
    'critical':      HexColor('#ff2d55'),
    'high':          HexColor('#ff6b35'),
    'medium':        HexColor('#ffcc02'),
    'low':           CREST,
    'info':          MUTED,
    'informational': MUTED,
}
RISK_TO_SEV = {'High': 'high', 'Medium': 'medium', 'Low': 'low', 'Informational': 'info'}


def _sev_color(sev):
    return SEV_COLORS.get((sev or 'info').lower(), MUTED)


# ── Style helpers ───────────────────────────────────────────────

def _styles():
    base = getSampleStyleSheet()

    def ps(name, **kw):
        return ParagraphStyle(name, parent=base['Normal'], **kw)

    return {
        'title':   ps('T', fontName='Helvetica-Bold', fontSize=26, textColor=WHITE),
        'heading': ps('H', fontName='Helvetica-Bold', fontSize=15, textColor=CREST,
                      spaceBefore=0.7*cm, spaceAfter=0.35*cm),
        'sub':     ps('S', fontName='Helvetica-Bold', fontSize=11, textColor=WHITE,
                      spaceBefore=0.4*cm, spaceAfter=0.2*cm),
        'body':    ps('B', fontName='Helvetica', fontSize=10, textColor=WHITE,
                      leading=14, spaceAfter=0.25*cm),
        'mono':    ps('M', fontName='Courier', fontSize=9, textColor=ACCENT,
                      leading=12, spaceAfter=0.15*cm),
        'footer':  ps('F', fontName='Helvetica', fontSize=8, textColor=MUTED,
                      alignment=TA_CENTER),
        'label':   ps('L', fontName='Helvetica-Bold', fontSize=10, textColor=MUTED),
    }


def _hr(elements):
    elements.append(HRFlowable(width='100%', thickness=1, color=WAVE, spaceAfter=0.4*cm))


def _grid_table(header_row, data_rows, col_widths, sev_col=None):
    """Build a styled table with optional per-row severity colouring in column sev_col."""
    all_rows = [header_row] + data_rows
    t = Table(all_rows, colWidths=col_widths, repeatRows=1)

    cmds = [
        ('BACKGROUND',  (0, 0), (-1, 0),  SURFACE),
        ('TEXTCOLOR',   (0, 0), (-1, 0),  CREST),
        ('FONTNAME',    (0, 0), (-1, 0),  'Helvetica-Bold'),
        ('FONTSIZE',    (0, 0), (-1, -1), 9),
        ('TOPPADDING',  (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING',(0,0), (-1, -1), 6),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ('GRID',        (0, 0), (-1, -1), 0.4, WAVE),
        ('TEXTCOLOR',   (0, 1), (-1, -1), WHITE),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [DEEP, CURRENT]),
        ('WORDWRAP',    (0, 0), (-1, -1), True),
    ]

    if sev_col is not None:
        for i, row in enumerate(data_rows, 1):
            sev_text = str(row[sev_col]).lower()
            color = _sev_color(sev_text)
            cmds += [
                ('BACKGROUND', (sev_col, i), (sev_col, i), color),
                ('TEXTCOLOR',  (sev_col, i), (sev_col, i), DEEP),
                ('FONTNAME',   (sev_col, i), (sev_col, i), 'Helvetica-Bold'),
            ]

    t.setStyle(TableStyle(cmds))
    return t


# ── Main entry point ────────────────────────────────────────────

def generate_pdf_report(scan, client):
    """Return PDF bytes for a completed scan."""
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=2*cm, rightMargin=2*cm,
        topMargin=2*cm, bottomMargin=2*cm,
    )

    S  = _styles()
    el = []

    # ── Cover ────────────────────────────────────────────────────
    cover_data = [[Paragraph('OCEAN<font color="#00c2ff">C</font>SEC', S['title']), '']]
    cover = Table(cover_data, colWidths=[12*cm, 5*cm])
    cover.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (-1, -1), DEEP),
        ('TOPPADDING',    (0, 0), (-1, -1), 28),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 28),
        ('LEFTPADDING',   (0, 0), (-1, -1), 16),
    ]))
    el.append(cover)
    el.append(HRFlowable(width='100%', thickness=3, color=CREST, spaceAfter=0.8*cm))

    el.append(Paragraph('VULNERABILITY ASSESSMENT REPORT', S['heading']))
    el.append(Spacer(1, 0.4*cm))

    # Client / scan metadata
    scan_types_label = ', '.join(scan.scan_types.split(',')) if scan.scan_types else '—'
    meta_rows = [
        ['Client',   client.name],
        ['Domain',   client.domain or '—'],
        ['Target',   scan.target],
        ['Scan ID',  f'#{scan.id}'],
        ['Date',     scan.completed_at.strftime('%Y-%m-%d %H:%M UTC') if scan.completed_at else '—'],
        ['Tools',    scan_types_label],
        ['Status',   scan.status.upper()],
    ]
    meta_t = Table(meta_rows, colWidths=[3.5*cm, 13.5*cm])
    meta_t.setStyle(TableStyle([
        ('BACKGROUND',  (0, 0), (0, -1), SURFACE),
        ('BACKGROUND',  (1, 0), (1, -1), DEEP),
        ('TEXTCOLOR',   (0, 0), (0, -1), MUTED),
        ('TEXTCOLOR',   (1, 0), (1, -1), WHITE),
        ('FONTNAME',    (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTNAME',    (1, 0), (1, -1), 'Helvetica'),
        ('FONTSIZE',    (0, 0), (-1, -1), 10),
        ('TOPPADDING',  (0, 0), (-1, -1), 7),
        ('BOTTOMPADDING',(0,0), (-1, -1), 7),
        ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ('GRID',        (0, 0), (-1, -1), 0.4, WAVE),
    ]))
    el.append(meta_t)
    el.append(Spacer(1, 0.6*cm))

    # Confidentiality banner
    conf = Table([['CONFIDENTIAL — For authorised recipients only.']], colWidths=[17*cm])
    conf.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (-1, -1), HexColor('#1a0505')),
        ('TEXTCOLOR',     (0, 0), (-1, -1), HexColor('#ff6b6b')),
        ('FONTNAME',      (0, 0), (-1, -1), 'Helvetica-Bold'),
        ('FONTSIZE',      (0, 0), (-1, -1), 10),
        ('TOPPADDING',    (0, 0), (-1, -1), 7),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 7),
        ('LEFTPADDING',   (0, 0), (-1, -1), 10),
        ('BOX',           (0, 0), (-1, -1), 1, HexColor('#ff2d55')),
    ]))
    el.append(conf)
    el.append(PageBreak())

    # ── Executive summary ────────────────────────────────────────
    results = scan.get_results()
    sev_cnt = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}

    for f in results.get('nuclei', {}).get('findings', []):
        k = f.get('severity', 'info').lower()
        sev_cnt[k] = sev_cnt.get(k, 0) + 1

    for a in results.get('zap', {}).get('alerts', []):
        k = RISK_TO_SEV.get(a.get('risk', ''), 'info')
        sev_cnt[k] = sev_cnt.get(k, 0) + 1

    sev_cnt['low'] += len(results.get('nikto', {}).get('findings', []))

    el.append(Paragraph('EXECUTIVE SUMMARY', S['heading']))
    _hr(el)

    sev_header = [['Severity', 'Count', 'Recommended Action']]
    sev_rows   = [
        ['CRITICAL', str(sev_cnt['critical']), 'Remediate immediately'],
        ['HIGH',     str(sev_cnt['high']),     'Remediate within 24 hours'],
        ['MEDIUM',   str(sev_cnt['medium']),   'Remediate within 7 days'],
        ['LOW',      str(sev_cnt['low']),      'Schedule for next sprint'],
        ['INFO',     str(sev_cnt['info']),     'Informational — review'],
    ]
    el.append(_grid_table(sev_header, sev_rows,
                          [3.5*cm, 2.5*cm, 11*cm], sev_col=0))
    el.append(Spacer(1, 0.8*cm))

    # ── Nmap ─────────────────────────────────────────────────────
    if 'nmap' in results:
        nmap = results['nmap']
        el.append(Paragraph('PORT SCAN  ·  Nmap', S['heading']))
        _hr(el)

        if nmap.get('error'):
            el.append(Paragraph(f'Tool error: {nmap["error"]}', S['body']))
        else:
            hosts = nmap.get('hosts', [])
            if not hosts:
                el.append(Paragraph('No live hosts discovered.', S['body']))
            for host in hosts:
                addrs = ', '.join(a['addr'] for a in host.get('addresses', []))
                names = ', '.join(h for h in host.get('hostnames', []) if h)
                label = f'{addrs}  ({names})' if names else addrs
                el.append(Paragraph(f'Host: {label}', S['sub']))

                os_list = host.get('os', [])
                if os_list:
                    el.append(Paragraph(f'OS: {os_list[0].get("name","?")} '
                                        f'({os_list[0].get("accuracy","?")}% accuracy)', S['body']))

                ports = host.get('ports', [])
                if ports:
                    hdr  = [['Port', 'Proto', 'State', 'Service', 'Version / Product']]
                    rows = []
                    for p in ports:
                        ver = f'{p.get("product","")  } {p.get("version","")}'.strip()
                        rows.append([
                            p.get('portid', ''),
                            p.get('protocol', ''),
                            p.get('state', ''),
                            p.get('service', ''),
                            ver or '—',
                        ])
                    el.append(_grid_table(hdr, rows,
                                          [2*cm, 2*cm, 2.5*cm, 3.5*cm, 7*cm]))
                    el.append(Spacer(1, 0.4*cm))
        el.append(Spacer(1, 0.4*cm))

    # ── Nuclei ───────────────────────────────────────────────────
    if 'nuclei' in results:
        nuclei = results['nuclei']
        el.append(Paragraph('VULNERABILITY SCAN  ·  Nuclei', S['heading']))
        _hr(el)

        if nuclei.get('error'):
            el.append(Paragraph(f'Tool error: {nuclei["error"]}', S['body']))
        else:
            findings = nuclei.get('findings', [])
            if not findings:
                el.append(Paragraph('No vulnerabilities found.', S['body']))
            else:
                hdr  = [['Severity', 'Name', 'Template ID', 'Matched At']]
                rows = [
                    [
                        f.get('severity', 'info').upper(),
                        f.get('name', '—'),
                        f.get('template_id', '—'),
                        f.get('matched_at', '—'),
                    ]
                    for f in findings
                ]
                el.append(_grid_table(hdr, rows,
                                      [2.5*cm, 5*cm, 4*cm, 5.5*cm], sev_col=0))
        el.append(Spacer(1, 0.4*cm))

    # ── Nikto ────────────────────────────────────────────────────
    if 'nikto' in results:
        nikto = results['nikto']
        el.append(Paragraph('WEB SERVER SCAN  ·  Nikto', S['heading']))
        _hr(el)

        if nikto.get('error'):
            el.append(Paragraph(f'Tool error: {nikto["error"]}', S['body']))
        else:
            findings = nikto.get('findings', [])
            if not findings:
                el.append(Paragraph('No issues found.', S['body']))
            else:
                for f in findings:
                    msg = f.get('msg', '')
                    url = f.get('url', '')
                    text = f'• {msg}'
                    if url:
                        text += f'  [{url}]'
                    el.append(Paragraph(text, S['body']))
        el.append(Spacer(1, 0.4*cm))

    # ── OWASP ZAP ────────────────────────────────────────────────
    if 'zap' in results:
        zap = results['zap']
        el.append(Paragraph('WEB APPLICATION SCAN  ·  OWASP ZAP', S['heading']))
        _hr(el)

        if zap.get('error'):
            el.append(Paragraph(f'Tool error: {zap["error"]}', S['body']))
        else:
            alerts = zap.get('alerts', [])
            if not alerts:
                el.append(Paragraph('No alerts found.', S['body']))
            else:
                hdr  = [['Risk', 'Name', 'URL', 'Confidence']]
                rows = []
                for a in alerts:
                    url = a.get('url', '')
                    url_short = (url[:48] + '…') if len(url) > 50 else url
                    rows.append([
                        a.get('risk', '—'),
                        a.get('name', '—'),
                        url_short,
                        a.get('confidence', '—'),
                    ])
                el.append(_grid_table(hdr, rows,
                                      [2.5*cm, 5*cm, 6.5*cm, 3*cm], sev_col=0))
        el.append(Spacer(1, 0.4*cm))

    # ── Footer ───────────────────────────────────────────────────
    el.append(Spacer(1, 0.8*cm))
    _hr(el)
    el.append(Paragraph(
        f'Generated by OceanCSec Vulnerability Scanner  ·  '
        f'{datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")}',
        S['footer'],
    ))

    doc.build(el)
    buf.seek(0)
    return buf.getvalue()
