"""Build CSV and PDF reports from a list of findings."""
import csv, io
from datetime import datetime
from xml.sax.saxutils import escape
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

FIELDS = ["source", "item", "detail", "score", "severity"]


def to_csv(findings):
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=FIELDS, extrasaction="ignore")
    w.writeheader()
    for f in findings:
        # Prefix cells that start with = + - @ so spreadsheets don't run them as formulas.
        w.writerow({k: ("'" + str(v) if str(v)[:1] in "=+-@" else v) for k, v in f.items() if k in FIELDS})
    return buf.getvalue().encode("utf-8")


def to_pdf(findings):
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, title="Security Assessment Report")
    s = getSampleStyleSheet()
    cell = s["BodyText"]; cell.fontSize = 8
    story = [Paragraph("Security Assessment Report", s["Title"]),
             Paragraph("Generated " + datetime.now().strftime("%d %b %Y, %H:%M"), s["Normal"]),
             Paragraph("Educational tool. CVE matches are keyword-based and may include false positives.", s["Italic"]),
             Spacer(1, 12)]
    counts = {}
    for f in findings:
        counts[f.get("severity", "Unknown")] = counts.get(f.get("severity", "Unknown"), 0) + 1
    story.append(Paragraph("Summary: " + (", ".join(f"{v} {k}" for k, v in counts.items()) or "no findings"), s["Heading3"]))
    rows = [["Source", "Item", "Detail", "Score", "Severity"]]
    for f in findings:
        rows.append([Paragraph(escape(str(f.get(k, ""))), cell) for k in FIELDS])
    t = Table(rows, colWidths=[55, 85, 250, 40, 55], repeatRows=1)
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#17233a")),
                           ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                           ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                           ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    story.append(t)
    doc.build(story)
    return buf.getvalue()
