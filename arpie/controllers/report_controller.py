from pathlib import Path

from ..network import detect_network_context
from ..reporting import build_report_data, export_html, export_json, export_pdf


class ReportController:

    def __init__(self, app):
        self.app = app

    def export(self, fmt: str, target_session_id=None):
        app = self.app
        sid = target_session_id or app.session_id
        if not sid:
            ctx = detect_network_context()
            sid = app.db.start_session(ctx.ssid, ctx.classification, ctx.interface, source="export", operator_id=app.operator_id)
            app.session_id = sid
        if sid is None:
            return
        out_path = str(Path(app.reports_dir) / f"arpie_session_{sid}.{fmt}")
        data = build_report_data(app.db, sid)
        exporters = {"json": export_json, "html": export_html, "pdf": export_pdf}
        exporters[fmt](data, out_path)
        app.status_toast = f"Exported arpie_session_{sid}.{fmt} to {app.reports_dir.name}/"
        app.update_view_content()
        app.page.update()