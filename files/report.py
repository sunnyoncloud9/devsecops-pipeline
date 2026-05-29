"""
DevSecOps Pipeline — PDF Report Generator
Generates a professional security report from scan results.
Author: Sunny Bhardwaj
GitHub: https://github.com/sunnyoncloud9/devsecops-pipeline
"""

import json
import sys
from datetime import datetime
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    HRFlowable, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table,
    TableStyle,
)

SEVERITY_COLORS = {
    "CRITICAL": colors.HexColor("#FF0000"),
    "HIGH":     colors.HexColor("#FF6B35"),
    "MEDIUM":   colors.HexColor("#FFB800"),
    "LOW":      colors.HexColor("#4CAF50"),
    "PASS":     colors.HexColor("#4CAF50"),
    "FAIL":     colors.HexColor("#FF0000"),
}


def load_json(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return {}


def parse_bandit(data: dict) -> list[dict]:
    findings = []
    for issue in data.get("results", []):
        findings.append({
            "tool": "Bandit",
            "stage": "SAST",
            "severity": issue.get("issue_severity", "MEDIUM").upper(),
            "detail": issue.get("issue_text", "")[:120],
            "location": issue.get("filename", "") + ":" + str(issue.get("line_number", "")),
        })
    return findings


def parse_pip_audit(data: dict) -> list[dict]:
    findings = []
    deps = data.get("dependencies", data if isinstance(data, list) else [])
    for dep in deps:
        for vuln in dep.get("vulns", []):
            findings.append({
                "tool": "pip-audit",
                "stage": "SCA",
                "severity": vuln.get("severity", "HIGH").upper(),
                "detail": f"{dep.get('name', '')} {dep.get('version', '')} — {vuln.get('id', '')}",
                "location": "requirements.txt",
            })
    return findings


def summarize(reports_dir: Path) -> tuple[list[dict], dict]:
    all_findings = []
    all_findings.extend(parse_bandit(load_json(reports_dir / "bandit.json")))
    all_findings.extend(parse_pip_audit(load_json(reports_dir / "pip-audit.json")))

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in all_findings:
        sev = f.get("severity", "LOW")
        if sev in counts:
            counts[sev] += 1

    passed = counts["CRITICAL"] == 0 and counts["HIGH"] <= 5
    return all_findings, counts, passed


def generate_pdf(reports_dir: Path):
    findings, counts, passed = summarize(reports_dir)

    output_path = reports_dir / "security_report.pdf"
    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=letter,
        rightMargin=0.75 * inch,
        leftMargin=0.75 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
    )

    styles = getSampleStyleSheet()
    story = []

    # ── Styles ────────────────────────────────────────────────────────────────
    title_style = ParagraphStyle(
        "Title", parent=styles["Title"],
        fontSize=26, textColor=colors.HexColor("#1a1a2e"), spaceAfter=4,
    )
    subtitle_style = ParagraphStyle(
        "Sub", parent=styles["Normal"],
        fontSize=11, textColor=colors.HexColor("#16213e"), spaceAfter=4,
    )
    h1 = ParagraphStyle(
        "H1", parent=styles["Heading1"],
        fontSize=15, textColor=colors.HexColor("#0f3460"),
        spaceBefore=10, spaceAfter=6,
    )
    body = ParagraphStyle(
        "Body", parent=styles["Normal"],
        fontSize=10, textColor=colors.HexColor("#333333"),
        spaceAfter=4, leading=14,
    )
    center = ParagraphStyle(
        "Center", parent=styles["Normal"],
        fontSize=8, textColor=colors.HexColor("#888888"),
        alignment=TA_CENTER,
    )

    scan_date = datetime.now().strftime("%B %d, %Y at %H:%M UTC")
    status = "PASSED ✅" if passed else "FAILED ❌"
    status_color = SEVERITY_COLORS["PASS"] if passed else SEVERITY_COLORS["FAIL"]

    # ── Cover ─────────────────────────────────────────────────────────────────
    story.append(Spacer(1, 1.2 * inch))
    story.append(Paragraph("🛡️ DevSecOps Pipeline", title_style))
    story.append(Paragraph("Automated Security Report", subtitle_style))
    story.append(Spacer(1, 0.2 * inch))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#0f3460")))
    story.append(Spacer(1, 0.2 * inch))

    cover_data = [
        ["Scan Date",       scan_date],
        ["Total Findings",  str(len(findings))],
        ["Gate Status",     status],
        ["Author",          "Sunny Bhardwaj"],
        ["Tool",            "DevSecOps Pipeline v1.0.0"],
        ["Repo",            "github.com/sunnyoncloud9/devsecops-pipeline"],
    ]
    cover_table = Table(cover_data, colWidths=[1.5 * inch, 5 * inch])
    cover_table.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (0, -1), colors.HexColor("#0f3460")),
        ("TEXTCOLOR",   (0, 0), (0, -1), colors.white),
        ("FONTNAME",    (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE",    (0, 0), (-1, -1), 10),
        ("ROWBACKGROUNDS", (1, 0), (1, -1),
         [colors.HexColor("#f8f9fa"), colors.white] * 10),
        ("GRID",        (0, 0), (-1, -1), 0.5, colors.HexColor("#dddddd")),
        ("PADDING",     (0, 0), (-1, -1), 8),
        ("BACKGROUND",  (1, 2), (1, 2), status_color),
        ("TEXTCOLOR",   (1, 2), (1, 2), colors.white),
        ("FONTNAME",    (1, 2), (1, 2), "Helvetica-Bold"),
    ]))
    story.append(cover_table)
    story.append(PageBreak())

    # ── Severity Summary ──────────────────────────────────────────────────────
    story.append(Paragraph("Findings Summary", h1))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#0f3460")))
    story.append(Spacer(1, 0.1 * inch))

    sev_data = [["Severity", "Count", "Threshold", "Status"]]
    for sev, threshold in [("CRITICAL", 0), ("HIGH", 5), ("MEDIUM", "-"), ("LOW", "-")]:
        count = counts.get(sev, 0)
        if isinstance(threshold, int):
            gate_status = "✅ OK" if count <= threshold else "❌ EXCEEDED"
        else:
            gate_status = "ℹ️ Info"
        sev_data.append([sev, str(count), str(threshold), gate_status])

    sev_table = Table(sev_data, colWidths=[1.5 * inch, 1 * inch, 1.2 * inch, 1.5 * inch])
    sev_table.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (-1, 0), colors.HexColor("#0f3460")),
        ("TEXTCOLOR",   (0, 0), (-1, 0), colors.white),
        ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",    (0, 0), (-1, -1), 9),
        ("GRID",        (0, 0), (-1, -1), 0.5, colors.HexColor("#dddddd")),
        ("PADDING",     (0, 0), (-1, -1), 6),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [colors.HexColor("#fff5f5"), colors.HexColor("#fff8f0"),
          colors.HexColor("#fffbf0"), colors.HexColor("#f0fff4")]),
    ]))
    story.append(sev_table)
    story.append(Spacer(1, 0.3 * inch))

    # ── Detailed Findings ─────────────────────────────────────────────────────
    if findings:
        story.append(Paragraph("Detailed Findings", h1))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#0f3460")))
        story.append(Spacer(1, 0.1 * inch))

        for i, f in enumerate(findings, 1):
            sev = f.get("severity", "MEDIUM")
            sev_color = SEVERITY_COLORS.get(sev, colors.gray)

            story.append(Paragraph(
                f"<b>Finding {i}: {f['detail'][:80]}</b>",
                ParagraphStyle("FTitle", parent=styles["Normal"],
                               fontSize=10, textColor=colors.HexColor("#1a1a2e"),
                               spaceBefore=6, spaceAfter=2),
            ))

            row_data = [
                ["Severity", sev],
                ["Stage",    f["stage"]],
                ["Tool",     f["tool"]],
                ["Location", f.get("location", "")[:60]],
            ]
            row_table = Table(row_data, colWidths=[1.2 * inch, 5.3 * inch])
            row_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f0f0f0")),
                ("FONTNAME",   (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTSIZE",   (0, 0), (-1, -1), 8),
                ("GRID",       (0, 0), (-1, -1), 0.3, colors.HexColor("#dddddd")),
                ("PADDING",    (0, 0), (-1, -1), 4),
                ("BACKGROUND", (1, 0), (1, 0), sev_color),
                ("TEXTCOLOR",  (1, 0), (1, 0), colors.white),
                ("FONTNAME",   (1, 0), (1, 0), "Helvetica-Bold"),
            ]))
            story.append(row_table)
            story.append(HRFlowable(width="100%", thickness=0.3,
                                    color=colors.HexColor("#eeeeee")))
    else:
        story.append(Paragraph("✅ No findings detected.", body))

    # ── Footer ────────────────────────────────────────────────────────────────
    story.append(PageBreak())
    story.append(Spacer(1, 2 * inch))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#0f3460")))
    story.append(Spacer(1, 0.2 * inch))
    story.append(Paragraph(
        "Generated by DevSecOps Pipeline v1.0.0 | github.com/sunnyoncloud9/devsecops-pipeline",
        center,
    ))
    story.append(Paragraph(
        "For authorized security use only. Handle with confidentiality.",
        center,
    ))

    doc.build(story)
    print(f"[+] PDF report saved: {output_path}")


if __name__ == "__main__":
    reports_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("reports")
    generate_pdf(reports_dir)
