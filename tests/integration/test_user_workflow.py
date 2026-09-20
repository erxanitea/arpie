import json

from arpie.infrastructure.report import build_report_data, export_html, export_json, export_pdf
from arpie.models import Database
from arpie.security.seal import SealManager


def test_session_alert_seal_and_report_workflow(tmp_path, monkeypatch):
    db = Database(str(tmp_path / "workflow.db"))
    session_id = db.start_session("Arpie-Demo", "public-untrusted", "wlan0", operator_id=None)
    event_id = db.log_event(
        session_id,
        "port_scan",
        "192.168.1.50",
        "192.168.1.9",
        "medium",
        0.9,
        42,
        {"ports": [22, 80, 443]},
        "Review source",
    )

    manager = SealManager(db, session_id, auto_restore_seconds=60)
    monkeypatch.setattr(manager, "_apply_block", lambda target: type("Result", (), {"success": True, "message": "blocked"})())
    monkeypatch.setattr(manager, "_remove_block", lambda target: type("Result", (), {"success": True, "message": "restored"})())
    assert manager.seal("192.168.1.50", event_id, confirmed_by_user=True).success
    assert manager.sealed_targets() == ["192.168.1.50"]
    assert manager.unseal("192.168.1.50").success

    report = build_report_data(db, session_id)
    assert report["summary"]["total_events"] == 1
    assert report["summary"]["seals_applied"] == 1
    assert report["events"][0]["evidence"] == {"ports": [22, 80, 443]}

    json_path = tmp_path / "report.json"
    html_path = tmp_path / "report.html"
    pdf_path = tmp_path / "report.pdf"
    export_json(report, str(json_path))
    export_html(report, str(html_path))
    export_pdf(report, str(pdf_path))
    assert json.loads(json_path.read_text())["summary"]["total_events"] == 1
    assert "Arpie" in html_path.read_text()
    assert pdf_path.stat().st_size > 0