"""
report_generator.py
=====================
Builds a downloadable incident report for a single logged event, in
either CSV (stdlib `csv` module) or PDF (`fpdf2`) format.

An "incident" here is one full detection record as written to
event_log.jsonl by test_engine.py: attack type, target node, detection
time + confidence, ML verdict, rule-engine verdict, severity,
mitigation action + duration, resolution timestamp.
"""

import csv
import io

from fpdf import FPDF

FIELDS = [
    "id", "time", "attack", "attack_id", "target_node", "ml_verdict",
    "ml_confidence", "rule_verdict", "rule_reason", "agreement",
    "severity_band", "severity_score", "mitigation_action",
    "mitigation_seconds", "model_used", "time_to_detect_s",
]


def to_csv_bytes(event):
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=FIELDS, extrasaction="ignore")
    writer.writeheader()
    writer.writerow(event)
    return buf.getvalue().encode("utf-8")


def to_pdf_bytes(event):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Courier", "B", 14)
    pdf.cell(0, 10, "Smart Grid IDS - Incident Report", ln=True)
    pdf.set_font("Courier", "", 9)
    pdf.cell(0, 6, f"Generated for event ID: {event.get('id', 'N/A')}", ln=True)
    pdf.ln(4)

    pdf.set_font("Courier", "B", 11)
    pdf.cell(0, 8, "Summary", ln=True)
    pdf.set_font("Courier", "", 10)
    rows = [
        ("Timestamp", event.get("time", "-")),
        ("Attack Type", event.get("attack", "-")),
        ("Target Node", event.get("target_node", "-")),
        ("Detection Model", event.get("model_used", "-")),
        ("ML Verdict", f"{event.get('ml_verdict', '-')} ({event.get('ml_confidence', '-')})"),
        ("Rule Engine Verdict", f"{event.get('rule_verdict', '-')} - {event.get('rule_reason', '-')}"),
        ("Engines Agree?", str(event.get("agreement", "-"))),
        ("Severity", f"{event.get('severity_band', '-')} (score {event.get('severity_score', '-')})"),
        ("Mitigation Action", event.get("mitigation_action", "-")),
        ("Time to Detect", f"{event.get('time_to_detect_s', '-')}s"),
        ("Mitigation Duration", f"{event.get('mitigation_seconds', '-')}s"),
    ]
    for label, val in rows:
        pdf.set_font("Courier", "B", 10)
        pdf.cell(0, 7, label + ":", ln=True)
        pdf.set_font("Courier", "", 10)
        pdf.set_x(pdf.l_margin)
        pdf.multi_cell(0, 6, str(val))
        pdf.ln(1)

    return bytes(pdf.output(dest="S"))
