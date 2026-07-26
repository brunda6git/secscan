from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, KeepTogether
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from io import BytesIO
from datetime import datetime

# Color palette
DARK = colors.HexColor('#0a0e17')
GREEN = colors.HexColor('#00d97e')
RED = colors.HexColor('#ff4d5e')
YELLOW = colors.HexColor('#ffb020')
BLUE = colors.HexColor('#4f9cf9')
GRAY = colors.HexColor('#8b949e')
LIGHT_GRAY = colors.HexColor('#f0f4f8')
WHITE = colors.white
DARK_CARD = colors.HexColor('#f8fafc')

SEVERITY_COLORS = {
    'HIGH': RED,
    'MEDIUM': YELLOW,
    'LOW': BLUE,
    'INFO': GRAY,
}

SECURITY_IMPORTANCE = {
    'HSTS': 'Prevents downgrade attacks. Forces browsers to always use HTTPS, protecting users from man-in-the-middle attacks.',
    'Content Security Policy': 'Primary defense against XSS attacks. Restricts which scripts and resources can load on your page.',
    'X-Frame-Options': 'Prevents clickjacking attacks where attackers embed your site in invisible iframes to steal clicks.',
    'X-Content-Type-Options': 'Prevents MIME sniffing attacks where browsers execute disguised malicious files.',
    'Referrer Policy': 'Prevents sensitive URL data from leaking to third-party sites via the Referer header.',
    'Permissions Policy': 'Restricts browser API access (camera, mic, location) preventing silent device exploitation.',
    'Server Info Leakage': 'Hiding server software version prevents attackers from targeting known vulnerabilities.',
    'HTTPS Redirect': 'Ensures all traffic is encrypted. Plain HTTP traffic can be intercepted and modified.',
    'SSL Certificate': 'Valid certificates verify server identity and enable encrypted communication.',
}

def risk_color(risk):
    return {
        'LOW': GREEN,
        'MEDIUM': YELLOW,
        'HIGH': RED,
        'CRITICAL': colors.HexColor('#cc0000'),
    }.get(risk, GRAY)


def generate_report(data):
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        leftMargin=2*cm, rightMargin=2*cm,
        topMargin=2*cm, bottomMargin=2.5*cm
    )

    # Styles
    title_style = ParagraphStyle('title', fontSize=22, fontName='Helvetica-Bold',
                                  textColor=DARK, leading=28, spaceAfter=10, alignment=TA_LEFT)
    subtitle_style = ParagraphStyle('sub', fontSize=10, textColor=GRAY,
                                     leading=14, spaceBefore=2, spaceAfter=4, fontName='Helvetica')
    heading_style = ParagraphStyle('h2', fontSize=13, fontName='Helvetica-Bold',
                                    textColor=DARK, spaceBefore=16, spaceAfter=8)
    body_style = ParagraphStyle('body', fontSize=9, fontName='Helvetica',
                                 textColor=colors.HexColor('#333333'), leading=14, spaceAfter=4)
    small_style = ParagraphStyle('small', fontSize=8, fontName='Helvetica',
                                  textColor=GRAY, leading=12, spaceAfter=3)
    importance_style = ParagraphStyle('imp', fontSize=8.5, fontName='Helvetica',
                                       textColor=colors.HexColor('#444444'),
                                       leading=13, leftIndent=8, spaceAfter=3)
    rec_style = ParagraphStyle('rec', fontSize=8.5, fontName='Helvetica',
                                textColor=colors.HexColor('#0052cc'),
                                leading=13, leftIndent=8, spaceAfter=3)
    footer_style = ParagraphStyle('footer', fontSize=7.5, fontName='Helvetica',
                                   textColor=GRAY, alignment=TA_CENTER)

    story = []

    # ── HEADER ──────────────────────────────────────────────
    story.append(Paragraph('Security Scan Report', title_style))
    story.append(Paragraph(
        f'Target: <b>{data.get("url", "N/A")}</b>', subtitle_style))
    story.append(Paragraph(
        f'Generated: {datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")}  ·  '
        f'Host: {data.get("hostname", "N/A")}',
        subtitle_style))
    story.append(HRFlowable(width='100%', thickness=2,
                             color=GREEN, spaceAfter=14, spaceBefore=6))

    # ── SUMMARY CARD ────────────────────────────────────────
    score = data.get('score', 0)
    risk = data.get('risk_level', 'UNKNOWN')
    checks = data.get('checks', [])
    passed = sum(1 for c in checks if c.get('passed'))
    failed = len(checks) - passed

    summary_data = [
        ['Security Score', 'Risk Level', 'Checks Passed', 'Checks Failed', 'Total Checks'],
        [f'{score}/100', risk, str(passed), str(failed), str(len(checks))],
    ]
    summary_table = Table(summary_data, colWidths=[3.2*cm, 3.2*cm, 3.2*cm, 3.2*cm, 3.2*cm])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), DARK),
        ('TEXTCOLOR', (0, 0), (-1, 0), WHITE),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 8),
        ('BACKGROUND', (0, 1), (-1, 1), LIGHT_GRAY),
        ('FONTNAME', (0, 1), (-1, 1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 1), (-1, 1), 13),
        ('TEXTCOLOR', (0, 1), (0, 1), risk_color(risk)),
        ('TEXTCOLOR', (1, 1), (1, 1), risk_color(risk)),
        ('TEXTCOLOR', (2, 1), (2, 1), GREEN),
        ('TEXTCOLOR', (3, 1), (3, 1), RED),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#dddddd')),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('ROUNDEDCORNERS', [4]),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 0.4*cm))

    # Enterprise note
    if data.get('is_enterprise'):
        story.append(Paragraph(
            'ⓘ Enterprise Platform: This domain belongs to a major technology platform. '
            'Low scores may reflect custom security architecture rather than poor security practices.',
            ParagraphStyle('ent', fontSize=8, fontName='Helvetica',
                           textColor=colors.HexColor('#0052cc'),
                           backColor=colors.HexColor('#e8f0fe'),
                           borderPad=6, leading=13, spaceAfter=8)))

    # ── CHECKS BY CATEGORY ──────────────────────────────────
    categories = {
        'headers': 'HTTP Security Headers',
        'transport': 'Transport Security',
        'ssl': 'SSL / TLS Certificate',
        'ports': 'Open Port Analysis',
    }

    checks_by_cat = {}
    for c in checks:
        cat = c.get('category', 'other')
        checks_by_cat.setdefault(cat, []).append(c)

    for cat_key, cat_name in categories.items():
        cat_checks = checks_by_cat.get(cat_key, [])
        if not cat_checks:
            continue

        story.append(Paragraph(cat_name, heading_style))
        story.append(HRFlowable(width='100%', thickness=0.5,
                                 color=LIGHT_GRAY, spaceAfter=6))

        for c in cat_checks:
            status = 'PASS' if c.get('passed') else 'FAIL'
            sev = c.get('severity', 'INFO')
            status_color = GREEN if c.get('passed') else RED
            sev_color = SEVERITY_COLORS.get(sev, GRAY)
            importance = SECURITY_IMPORTANCE.get(c.get('name', ''), '')
            recommendation = c.get('recommendation', '')

            # Main check row
            row_data = [[
                Paragraph(f'<b>{c.get("name", "")}</b>', body_style),
                Paragraph(f'<b>{status}</b>', ParagraphStyle('st', fontSize=9,
                           fontName='Helvetica-Bold', textColor=status_color, alignment=TA_CENTER)),
                Paragraph(sev, ParagraphStyle('sv', fontSize=8,
                           fontName='Helvetica-Bold', textColor=sev_color, alignment=TA_CENTER)),
                Paragraph(c.get('detail', '')[:120], small_style),
            ]]

            row_table = Table(row_data, colWidths=[4.5*cm, 1.5*cm, 1.8*cm, 8.5*cm])
            row_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), DARK_CARD),
                ('GRID', (0, 0), (-1, -1), 0.3, colors.HexColor('#e0e0e0')),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ]))

            elements = [row_table]

            # Importance row (if failed)
            if not c.get('passed') and importance:
                imp_table = Table([[
                    Paragraph('Why it matters:', ParagraphStyle('wl', fontSize=7.5,
                               fontName='Helvetica-Bold', textColor=GRAY)),
                    Paragraph(importance, importance_style),
                ]], colWidths=[2.5*cm, 13.8*cm])
                imp_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#fafafa')),
                    ('TOPPADDING', (0, 0), (-1, -1), 4),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                    ('LEFTPADDING', (0, 0), (-1, -1), 6),
                ]))
                elements.append(imp_table)

            # Recommendation row (if failed)
            if not c.get('passed') and recommendation:
                rec_table = Table([[
                    Paragraph('Fix:', ParagraphStyle('fl', fontSize=7.5,
                               fontName='Helvetica-Bold', textColor=colors.HexColor('#0052cc'))),
                    Paragraph(recommendation, rec_style),
                ]], colWidths=[2.5*cm, 13.8*cm])
                rec_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f0f7ff')),
                    ('TOPPADDING', (0, 0), (-1, -1), 4),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                    ('LEFTPADDING', (0, 0), (-1, -1), 6),
                ]))
                elements.append(rec_table)

            elements.append(Spacer(1, 0.2*cm))
            story.append(KeepTogether(elements))

    # ── RECOMMENDATIONS SUMMARY ──────────────────────────────
    failed_checks = [c for c in checks if not c.get('passed') and c.get('recommendation')]
    if failed_checks:
        story.append(Paragraph('Recommendations Summary', heading_style))
        story.append(HRFlowable(width='100%', thickness=0.5,
                                 color=LIGHT_GRAY, spaceAfter=8))

        priority_order = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2, 'INFO': 3}
        failed_checks.sort(key=lambda x: priority_order.get(x.get('severity', 'INFO'), 3))

        for i, c in enumerate(failed_checks, 1):
            sev = c.get('severity', 'LOW')
            sev_color = SEVERITY_COLORS.get(sev, GRAY)
            rec_item = Table([[
                Paragraph(f'{i}.', ParagraphStyle('num', fontSize=9,
                           fontName='Helvetica-Bold', textColor=sev_color)),
                Paragraph(f'<b>{c.get("name", "")}</b> [{sev}]', body_style),
                Paragraph(c.get('recommendation', ''), small_style),
            ]], colWidths=[0.6*cm, 5*cm, 10.7*cm])
            rec_item.setStyle(TableStyle([
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('TOPPADDING', (0, 0), (-1, -1), 5),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
                ('LINEBELOW', (0, 0), (-1, -1), 0.3, colors.HexColor('#eeeeee')),
            ]))
            story.append(rec_item)

    # ── FOOTER ──────────────────────────────────────────────
    story.append(Spacer(1, 0.8*cm))
    story.append(HRFlowable(width='100%', thickness=0.5, color=LIGHT_GRAY))
    story.append(Spacer(1, 0.2*cm))
    story.append(Paragraph(
        f'Generated by SecScan  ·  {datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")}  ·  '
        'For authorized security testing only  ·  Based on OWASP security standards',
        footer_style))

    doc.build(story)
    return buffer.getvalue()