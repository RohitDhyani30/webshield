"""
Report Generator.
Produces:
  1. An HTML report (Jinja2-rendered) — used for the in-browser dashboard view.
  2. A PDF report (reportlab) — for download/sharing, e.g. attaching to a viva submission.
"""
import os
from datetime import datetime, timezone
from jinja2 import Environment, FileSystemLoader
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")
REPORTS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports")
os.makedirs(REPORTS_DIR, exist_ok=True)

SEVERITY_COLOR = {
    "CRITICAL": colors.HexColor("#b00020"),
    "HIGH": colors.HexColor("#d35400"),
    "MEDIUM": colors.HexColor("#e0a800"),
    "LOW": colors.HexColor("#2e7d32"),
}


def _context(scan: dict, findings: list[dict], risk: dict):
    return {
        "target_url": scan["target_url"],
        "scan_date": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "pages_crawled": scan["pages_crawled"],
        "forms_found": scan["forms_found"],
        "total_findings": risk["total_findings"],
        "risk_level": risk["risk_level"],
        "security_score": risk["security_score"],
        "severity_counts": risk["severity_counts"],
        "findings": findings,
    }


def generate_html_report(scan: dict, findings: list[dict], risk: dict) -> str:
    env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
    template = env.get_template("report.html")
    html = template.render(**_context(scan, findings, risk))

    out_path = os.path.join(REPORTS_DIR, f"scan_{scan['id']}_report.html")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)
    return out_path


def generate_pdf_report(scan: dict, findings: list[dict], risk: dict) -> str:
    out_path = os.path.join(REPORTS_DIR, f"scan_{scan['id']}_report.pdf")
    doc = SimpleDocTemplate(out_path, pagesize=A4)
    styles = getSampleStyleSheet()
    elements = []

    elements.append(Paragraph("WebShield Security Assessment Report", styles["Title"]))
    elements.append(Spacer(1, 12))
    elements.append(Paragraph(f"<b>Target:</b> {scan['target_url']}", styles["Normal"]))
    elements.append(Paragraph(f"<b>Scan Date:</b> {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}", styles["Normal"]))
    elements.append(Spacer(1, 12))

    elements.append(Paragraph("Executive Summary", styles["Heading2"]))
    summary = (
        f"Pages crawled: {scan['pages_crawled']} | Forms discovered: {scan['forms_found']} | "
        f"Total findings: {risk['total_findings']}<br/>"
        f"Overall Risk Level: <b>{risk['risk_level']}</b> | Security Score: {risk['security_score']}/100<br/>"
        f"Critical: {risk['severity_counts']['CRITICAL']}, High: {risk['severity_counts']['HIGH']}, "
        f"Medium: {risk['severity_counts']['MEDIUM']}, Low: {risk['severity_counts']['LOW']}"
    )
    elements.append(Paragraph(summary, styles["Normal"]))
    elements.append(Spacer(1, 16))

    elements.append(Paragraph("Findings", styles["Heading2"]))
    table_data = [["Severity", "Module", "Title", "Parameter", "Remediation"]]
    for f in findings:
        table_data.append([
            f["severity"], f["module"], f["title"][:60],
            f.get("parameter") or "-", (f.get("remediation") or "")[:80],
        ])

    if len(table_data) > 1:
        t = Table(table_data, repeatRows=1, colWidths=[55, 70, 130, 60, 160])
        style = TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0b3d91")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 7.5),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ])
        for i, f in enumerate(findings, start=1):
            style.add("TEXTCOLOR", (0, i), (0, i), SEVERITY_COLOR.get(f["severity"], colors.black))
        t.setStyle(style)
        elements.append(t)
    else:
        elements.append(Paragraph("No findings detected.", styles["Normal"]))

    doc.build(elements)
    return out_path
