"""
Exportable end-of-session report: summary, alert timeline, actions
taken, and recommendations. Supports JSON, HTML, and PDF export.
"""

import json
from datetime import datetime
from pathlib import Path

from .db import Database


def _fmt_ts(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def build_report_data(db: Database, session_id: int) -> dict:
    with db.cursor() as cur:
        cur.execute("SELECT * FROM sessions WHERE id = ?", (session_id,))
        session = dict(cur.fetchone())

    events = db.get_events(session_id)
    actions = db.get_actions(session_id)

    for e in events:
        e["evidence"] = json.loads(e["evidence_json"])
        del e["evidence_json"]

    severity_counts = {}
    for e in events:
        severity_counts[e["severity"]] = severity_counts.get(e["severity"], 0) + 1

    return {
        "session": session,
        "events": events,
        "actions": actions,
        "summary": {
            "total_events": len(events),
            "severity_counts": severity_counts,
            "seals_applied": sum(1 for a in actions if a["action"] == "seal"),
        },
        "generated_at": _fmt_ts(__import__("time").time()),
    }


def export_json(data: dict, out_path: str):
    Path(out_path).write_text(json.dumps(data, indent=2), encoding="utf-8")
    return out_path


def export_html(data: dict, out_path: str):
    rows = "".join(
        f"<tr><td>{_fmt_ts(e['ts'])}</td><td>{e['detection_type']}</td>"
        f"<td>{e['source_ip'] or ''}</td><td>{e['severity']}</td>"
        f"<td>{e['confidence']:.2f}</td><td>{e['risk_score']}</td>"
        f"<td>{e['recommended_action'] or ''}</td></tr>"
        for e in data["events"]
    )
    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Arpie Session Report</title>
<style>
body {{ font-family: system-ui, sans-serif; margin: 2rem; color: #1a1a1a; }}
h1 {{ color: #0b3d91; }}
table {{ border-collapse: collapse; width: 100%; margin-top: 1rem; }}
th, td {{ border: 1px solid #ccc; padding: 6px 10px; text-align: left; font-size: 0.9rem; }}
th {{ background: #0b3d91; color: white; }}
.summary {{ background: #f4f6fb; padding: 1rem; border-radius: 8px; }}
</style></head><body>
<h1>Arpie — Session Report</h1>
<div class="summary">
<p><strong>Network:</strong> {data['session']['network_ssid']} ({data['session']['network_context']})</p>
<p><strong>Started:</strong> {_fmt_ts(data['session']['started_at'])}</p>
<p><strong>Total events:</strong> {data['summary']['total_events']}</p>
<p><strong>Seal Mode actions applied:</strong> {data['summary']['seals_applied']}</p>
</div>
<h2>Event Timeline</h2>
<table>
<tr><th>Time</th><th>Type</th><th>Source IP</th><th>Severity</th>
<th>Confidence</th><th>Risk Score</th><th>Recommended Action</th></tr>
{rows}
</table>
<p style="margin-top:2rem;color:#888;font-size:0.8rem;">Generated {data['generated_at']} by Arpie.</p>
</body></html>"""
    Path(out_path).write_text(html, encoding="utf-8")
    return out_path


def export_pdf(data: dict, out_path: str):
    """Requires `reportlab` (see requirements.txt)."""
    from reportlab.lib.pagesizes import letter
    from reportlab.lib import colors
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet

    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(out_path, pagesize=letter)
    story = [
        Paragraph("Arpie — Session Report", styles["Title"]),
        Spacer(1, 12),
        Paragraph(f"Network: {data['session']['network_ssid']} "
                  f"({data['session']['network_context']})", styles["Normal"]),
        Paragraph(f"Started: {_fmt_ts(data['session']['started_at'])}", styles["Normal"]),
        Paragraph(f"Total events: {data['summary']['total_events']}", styles["Normal"]),
        Spacer(1, 16),
    ]

    table_data = [["Time", "Type", "Source IP", "Severity", "Confidence", "Risk", "Action"]]
    for e in data["events"]:
        table_data.append([
            _fmt_ts(e["ts"]), e["detection_type"], e["source_ip"] or "",
            e["severity"], f"{e['confidence']:.2f}", str(e["risk_score"]),
            (e["recommended_action"] or "")[:40],
        ])
    table = Table(table_data, repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0b3d91")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 7),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
    ]))
    story.append(table)
    doc.build(story)
    return out_path
