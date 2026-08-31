from datetime import datetime
import flet as ft


def _fmt_time(ts: float) -> str:
    try:
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")
    except Exception:
        return "Unknown"


def _compute_report_risk(alerts_list):
    if not alerts_list:
        return 0
    severity_weights = {"low": 5, "medium": 15, "high": 30, "critical": 45}
    scores = [severity_weights.get(a.get("severity", "").lower(), 0) for a in alerts_list]
    base = max(scores) if scores else 0
    distinct_types = {a.get("type", "") for a in alerts_list}
    bonus = min(20, (len(distinct_types) - 1) * 8) if len(distinct_types) > 1 else 0
    return max(0, min(100, base + bonus))


def _risk_label(score):
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH RISK"
    if score >= 25:
        return "MED RISK"
    return "LOW RISK"


def render_reports_view(app) -> ft.Column:
    def export_fmt(fmt, target_sid=None):
        app.export_report(fmt, target_session_id=target_sid)

    status_widget = ft.Container(
        content=ft.Row([
            ft.Icon(ft.Icons.CHECK_CIRCLE_ROUNDED, color="#10B981", size=18),
            ft.Text(app.status_toast or "Ready to generate session audit logs.", size=13, color="#0F172A"),
        ], spacing=8),
        bgcolor="#ECFDF5", border=ft.Border.all(1, "#A7F3D0"), border_radius=8, padding=12,
    ) if app.status_toast else ft.Container()

    # Retrieve past sessions for this operator from the database
    past_sessions = app.db.get_operator_sessions(app.operator_id)
    history_rows = []
    for s in past_sessions[:10]:
        sid = s["id"]
        is_active = (app.session_id == sid)
        started_str = _fmt_time(s.get("started_at", 0))
        ssid_str = s.get("network_ssid") or "Unknown"
        ctx_str = (s.get("network_context") or "unknown").upper()
        ev_cnt = s.get("event_count", 0)

        history_rows.append(
            ft.DataRow(
                cells=[
                    ft.DataCell(ft.Text(f"#{sid}", size=12, weight=ft.FontWeight.BOLD, color="#0F172A")),
                    ft.DataCell(ft.Text(started_str, size=12, color="#475569")),
                    ft.DataCell(ft.Text(f"{ssid_str} ({ctx_str})", size=12, color="#0F172A")),
                    ft.DataCell(ft.Container(
                        content=ft.Text(f"{ev_cnt} events", size=10, weight=ft.FontWeight.BOLD, color="#DC2626" if ev_cnt > 0 else "#10B981"),
                        bgcolor="#FEE2E2" if ev_cnt > 0 else "#ECFDF5",
                        border_radius=4, padding=ft.Padding.symmetric(horizontal=6, vertical=2),
                    )),
                    ft.DataCell(
                        ft.Row([
                            ft.IconButton(ft.Icons.PICTURE_AS_PDF_ROUNDED, icon_color="#DC2626", icon_size=16, tooltip="Export PDF", on_click=lambda e, sid=sid: export_fmt("pdf", sid)),
                            ft.IconButton(ft.Icons.HTML_ROUNDED, icon_color="#0284C7", icon_size=16, tooltip="Export HTML", on_click=lambda e, sid=sid: export_fmt("html", sid)),
                            ft.IconButton(ft.Icons.DATA_OBJECT_ROUNDED, icon_color="#8B5CF6", icon_size=16, tooltip="Export JSON", on_click=lambda e, sid=sid: export_fmt("json", sid)),
                        ], spacing=2)
                    ),
                ]
            )
        )

    history_table = ft.DataTable(
        columns=[
            ft.DataColumn(label=ft.Text("SESSION", size=11, weight=ft.FontWeight.BOLD, color="#94A3B8")),
            ft.DataColumn(label=ft.Text("DATE / TIME", size=11, weight=ft.FontWeight.BOLD, color="#94A3B8")),
            ft.DataColumn(label=ft.Text("NETWORK", size=11, weight=ft.FontWeight.BOLD, color="#94A3B8")),
            ft.DataColumn(label=ft.Text("THREATS", size=11, weight=ft.FontWeight.BOLD, color="#94A3B8")),
            ft.DataColumn(label=ft.Text("EXPORT", size=11, weight=ft.FontWeight.BOLD, color="#94A3B8")),
        ],
        rows=history_rows,
        heading_row_height=38,
        data_row_min_height=40,
        horizontal_lines=ft.BorderSide(1, "#F1F5F9"),
    ) if history_rows else ft.Text("No previous sessions recorded yet for this account.", size=12, color="#94A3B8")

    return ft.Column([
        ft.Container(
            content=ft.Column([
                ft.Text("Forensic Incident Reports & Session Exports", size=20, weight=ft.FontWeight.BOLD, color="#0F172A"),
                ft.Text(f"Logged in as: {app.user_name} ({app.operator_username or 'admin'}) · Historical sessions and evidence logs", size=13, color="#64748B"),
                ft.Divider(color="#E2E8F0", height=16),
                status_widget,
                ft.Row([
                    ft.ElevatedButton(
                        "Export Active PDF",
                        icon=ft.Icons.PICTURE_AS_PDF_ROUNDED,
                        on_click=lambda e: export_fmt("pdf"),
                        style=ft.ButtonStyle(bgcolor="#DC2626", color="#FFFFFF", padding=14),
                    ),
                    ft.OutlinedButton(
                        "Export Active HTML",
                        icon=ft.Icons.HTML_ROUNDED,
                        on_click=lambda e: export_fmt("html"),
                        style=ft.ButtonStyle(padding=14),
                    ),
                    ft.OutlinedButton(
                        "Export Active JSON",
                        icon=ft.Icons.DATA_OBJECT_ROUNDED,
                        on_click=lambda e: export_fmt("json"),
                        style=ft.ButtonStyle(padding=14),
                    ),
                ], spacing=12),
                ft.Divider(color="#E2E8F0", height=16),
                ft.Text("Active Session Executive Summary", size=15, weight=ft.FontWeight.BOLD, color="#0F172A"),
                ft.Container(
                    content=ft.Column([
                        ft.Text(f"Session ID: #{app.session_id or 'N/A'} (Current Active)", size=13, weight=ft.FontWeight.BOLD, color="#0F172A"),
                        ft.Text(
                            f"Network: {app.network_context.ssid or 'Unknown'} ({(app.network_context.classification or 'unknown').upper().replace('PUBLIC-UNTRUSTED', 'PUBLIC / UNTRUSTED')})"
                            if app.network_context else "Network: Not detected",
                            size=12, color="#475569",
                        ),
                        ft.Text(f"Detected Threats: {len(app.all_alerts_list)} security incidents", size=12, color="#475569"),
                        ft.Text(
                            f"Overall Risk Index: {_compute_report_risk(app.all_alerts_list)} / 100 ({_risk_label(_compute_report_risk(app.all_alerts_list))})",
                            size=12, weight=ft.FontWeight.BOLD,
                            color="#DC2626" if _compute_report_risk(app.all_alerts_list) >= 50 else "#D97706" if _compute_report_risk(app.all_alerts_list) >= 25 else "#10B981",
                        ),
                    ], spacing=4),
                    bgcolor="#F8FAFC", border=ft.Border.all(1, "#E2E8F0"), border_radius=8, padding=16,
                ),
                ft.Divider(color="#E2E8F0", height=16),
                ft.Text("Past Monitoring Sessions & Audit History", size=15, weight=ft.FontWeight.BOLD, color="#0F172A"),
                ft.Text("Retrieve and re-export past session reports recorded for your account.", size=12, color="#64748B"),
                ft.Container(
                    content=history_table,
                    padding=ft.Padding.only(top=8),
                )
            ], spacing=12),
            bgcolor="#FFFFFF", border=ft.Border.all(1, "#E2E8F0"), border_radius=12, padding=24,
        )
    ], spacing=14, scroll=ft.ScrollMode.AUTO)
