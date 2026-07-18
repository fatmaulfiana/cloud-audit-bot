"""
report.py
Generate laporan audit dalam format PDF menggunakan reportlab.
Laporan berisi: ringkasan skor risiko, tabel jumlah temuan per severity,
dan detail tiap temuan (kategori, deskripsi, rekomendasi mitigasi).
"""

import os
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from config import REPORTS_DIR
from utils import get_logger

logger = get_logger(__name__)

SEVERITY_COLOR = {
    "CRITICAL": colors.HexColor("#B91C1C"),
    "HIGH": colors.HexColor("#D97706"),
    "MEDIUM": colors.HexColor("#CA8A04"),
    "LOW": colors.HexColor("#15803D"),
}


def _styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="FindingTitle", fontSize=11, leading=14, spaceAfter=2, fontName="Helvetica-Bold"))
    styles.add(ParagraphStyle(name="FindingBody", fontSize=9.5, leading=13, spaceAfter=6))
    styles.add(ParagraphStyle(name="ReportSubtitle", fontSize=11, textColor=colors.HexColor("#555555")))
    return styles


def generate_pdf_report(host: str, scan_result: dict, findings: list, risk_score: int) -> str:
    os.makedirs(REPORTS_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_host = host.replace(":", "_").replace("/", "_")
    filepath = os.path.join(REPORTS_DIR, f"audit_report_{safe_host}_{timestamp}.pdf")

    styles = _styles()
    doc = SimpleDocTemplate(
        filepath, pagesize=A4,
        topMargin=2 * cm, bottomMargin=2 * cm, leftMargin=2 * cm, rightMargin=2 * cm,
    )
    story = []

    # --- Header ---
    story.append(Paragraph("Laporan Audit Keamanan Konfigurasi Cloud", styles["Title"]))
    story.append(Paragraph(f"Target: <b>{host}</b>", styles["ReportSubtitle"]))
    story.append(Paragraph(
        f"Waktu scan: {scan_result.get('scanned_at', '-')} | Dibuat: {datetime.now().isoformat()}",
        styles["ReportSubtitle"],
    ))
    story.append(Spacer(1, 14))

    # --- Ringkasan skor risiko ---
    story.append(Paragraph("Ringkasan Risiko", styles["Heading2"]))
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    summary_data = [["Skor Risiko", "Critical", "High", "Medium", "Low"],
                     [f"{risk_score}/100", counts["CRITICAL"], counts["HIGH"], counts["MEDIUM"], counts["LOW"]]]
    summary_table = Table(summary_data, colWidths=[5.5 * cm, 2.5 * cm, 2.5 * cm, 2.5 * cm, 2.5 * cm])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1F2937")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("BACKGROUND", (0, 1), (0, 1), colors.HexColor("#F3F4F6")),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 18))

    # --- Ringkasan teknis hasil scan ---
    story.append(Paragraph("Ringkasan Teknis Scan", styles["Heading2"]))
    ssl_info = scan_result.get("ssl", {})
    dns_info = scan_result.get("dns", {})
    http_info = scan_result.get("http_headers", {})

    abuse_entries = scan_result.get("abuseipdb", [])
    if abuse_entries and any(e.get("checked") for e in abuse_entries):
        abuse_summary = "; ".join(
            f"{e['ip']}: skor {e.get('abuse_confidence_score', 0)}/100 ({e.get('total_reports', 0)} laporan)"
            for e in abuse_entries if e.get("checked")
        )
    elif abuse_entries:
        abuse_summary = "Tidak dicek (ABUSEIPDB_API_KEY belum diatur / kuota habis)"
    else:
        abuse_summary = "-"

    tech_rows = [
        ["Item", "Hasil"],
        ["Resolusi DNS", ", ".join(dns_info.get("ips", [])) or "Gagal resolve"],
        ["Status SSL", "Aktif" if ssl_info.get("present") else "Tidak aktif / bermasalah"],
        ["Sisa masa berlaku SSL", f"{ssl_info.get('days_left', '-')} hari" if ssl_info.get("present") else "-"],
        ["HTTP dapat diakses", "Ya" if http_info.get("reachable") else "Tidak"],
        ["Status code HTTP", str(http_info.get("status_code", "-"))],
        ["Reputasi IP (AbuseIPDB)", abuse_summary],
    ]
    tech_table = Table(tech_rows, colWidths=[6 * cm, 10 * cm])
    tech_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#374151")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F9FAFB")]),
    ]))
    story.append(tech_table)
    story.append(Spacer(1, 18))

    # --- Detail temuan ---
    story.append(Paragraph("Detail Temuan Audit", styles["Heading2"]))

    if not findings:
        story.append(Paragraph("Tidak ada temuan pada saat scan ini dilakukan.", styles["FindingBody"]))
    else:
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        for f in sorted(findings, key=lambda x: order.get(x["severity"], 4)):
            color = SEVERITY_COLOR.get(f["severity"], colors.black)
            title_html = f'<font color="{color.hexval()}">[{f["severity"]}]</font> {f["category"]} — {f["title"]}'
            story.append(Paragraph(title_html, styles["FindingTitle"]))
            story.append(Paragraph(f"<b>Deskripsi:</b> {f['description']}", styles["FindingBody"]))
            story.append(Paragraph(f"<b>Rekomendasi mitigasi:</b> {f['recommendation']}", styles["FindingBody"]))

    story.append(Spacer(1, 14))
    story.append(Paragraph(
        "Laporan ini dihasilkan otomatis oleh Cloud Audit Bot sebagai bagian dari tugas "
        "Perancangan dan Implementasi Sistem Aman Berbasis Cloud.",
        styles["ReportSubtitle"],
    ))

    doc.build(story)
    logger.info(f"Laporan PDF dibuat: {filepath}")
    return filepath
