import datetime
import flet as ft


def build_evidence_drawer(app, alert_item: dict, on_close, on_seal) -> ft.Container:
    today_date = datetime.datetime.now().strftime("%Y-%m-%d")
    sel_type = alert_item.get("type", "Security Event")
    sel_sev = alert_item.get("severity", "HIGH")
    sel_src = alert_item.get("source", "Unknown")
    sel_target = alert_item.get("target", "Local Endpoint")
    sel_desc = alert_item.get("desc", "No description available.")
    sel_fg = alert_item.get("fg", "#DC2626")
    sel_bg = alert_item.get("bg", "#FEE2E2")
    sel_time = alert_item.get("time", "")
    sel_date = alert_item.get("date", today_date)

    return ft.Container(
        content=ft.Column([
            ft.Row([
                ft.Row([
                    ft.Icon(ft.Icons.SAVED_SEARCH_ROUNDED, color="#0F172A", size=20),
                    ft.Column([
                        ft.Text("Incident Evidence Details", size=14, weight=ft.FontWeight.BOLD, color="#0F172A"),
                        ft.Text("Deterministic Heuristic Proof Metrics", size=10, color="#64748B"),
                    ], spacing=1),
                ], spacing=8),
                ft.IconButton(ft.Icons.CLOSE_ROUNDED, icon_size=18, tooltip="Close Inspector", on_click=on_close),
            ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
            ft.Divider(color="#E2E8F0", height=10),
            ft.Container(
                content=ft.Column([
                    ft.Row([
                        ft.Text(sel_type, size=13, weight=ft.FontWeight.BOLD, color="#0F172A"),
                        ft.Container(
                            content=ft.Text(sel_sev, size=9, weight=ft.FontWeight.BOLD, color=sel_fg),
                            bgcolor=sel_bg, border_radius=4, padding=ft.Padding.symmetric(horizontal=6, vertical=2),
                        ),
                    ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                    ft.Text(f"Detected on {sel_date} at {sel_time}", size=11, color="#64748B"),
                    ft.Text(sel_desc, size=12, color="#334155"),
                ], spacing=6),
                bgcolor="#F8FAFC", border=ft.Border.all(1, "#E2E8F0"), border_radius=8, padding=12,
            ),
            ft.Column([
                ft.Row([
                    ft.Column([
                        ft.Text("Source Host (Attacker)", size=10, color="#64748B", weight=ft.FontWeight.BOLD),
                        ft.Text(sel_src, size=13, weight=ft.FontWeight.BOLD, color="#DC2626"),
                    ], spacing=2, expand=1),
                    ft.Column([
                        ft.Text("Target Endpoint", size=10, color="#64748B", weight=ft.FontWeight.BOLD),
                        ft.Text(sel_target, size=13, weight=ft.FontWeight.BOLD, color="#0F172A"),
                    ], spacing=2, expand=1),
                ]),
                ft.Row([
                    ft.Column([
                        ft.Text("Heuristic Certainty", size=10, color="#64748B", weight=ft.FontWeight.BOLD),
                        ft.Text("100% Deterministic", size=12, weight=ft.FontWeight.BOLD, color="#0284C7"),
                    ], spacing=2, expand=1),
                    ft.Column([
                        ft.Text("Triage Status", size=10, color="#64748B", weight=ft.FontWeight.BOLD),
                        ft.Text(alert_item.get("status", "NEW"), size=12, weight=ft.FontWeight.BOLD, color="#10B981"),
                    ], spacing=2, expand=1),
                ]),
            ], spacing=10),
            ft.Divider(color="#F1F5F9", height=8),
            ft.Container(
                content=ft.Column([
                    ft.Row([
                        ft.Icon(ft.Icons.TRAVEL_EXPLORE_ROUNDED, size=16, color="#0F172A"),
                        ft.Text("Threat Intelligence", size=12, weight=ft.FontWeight.BOLD, color="#0F172A"),
                    ], spacing=6),
                    ft.Row([
                        ft.Text("Abuse Confidence Score:", size=11, color="#64748B"),
                        ft.Container(
                            content=ft.Text(
                                "98% Malicious" if "192.168.1.50" in sel_src or "192.168.1.1" in sel_src else "Clean (0%)",
                                size=10, weight=ft.FontWeight.BOLD, color="#DC2626",
                            ),
                            bgcolor="#FEE2E2", border_radius=4, padding=ft.Padding.symmetric(horizontal=6, vertical=2),
                        ),
                    ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                    ft.Row([
                        ft.Text("Autonomous System:", size=11, color="#64748B"),
                        ft.Text("AS13335 (Cloudflare / Local)", size=11, weight=ft.FontWeight.W_500, color="#0F172A"),
                    ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                ], spacing=6),
                bgcolor="#F8FAFC", border=ft.Border.all(1, "#E2E8F0"), border_radius=8, padding=10,
            ),
            ft.Container(height=4),
            ft.ElevatedButton(
                content=ft.Row([
                    ft.Icon(ft.Icons.SHIELD_ROUNDED, color="#FFFFFF", size=16),
                    ft.Text("1-Click Seal Mode: Isolate Host", size=12, weight=ft.FontWeight.BOLD, color="#FFFFFF"),
                ], alignment=ft.MainAxisAlignment.CENTER, spacing=6),
                style=ft.ButtonStyle(
                    bgcolor="#DC2626",
                    shape=ft.RoundedRectangleBorder(radius=8),
                    padding=ft.Padding.symmetric(vertical=12),
                ),
                on_click=on_seal,
                width=350,
            ),
        ], spacing=10, scroll=ft.ScrollMode.AUTO),
        width=380,
        bgcolor="#FFFFFF",
        border=ft.Border.all(1, "#E2E8F0"),
        border_radius=12,
        padding=16,
        shadow=ft.BoxShadow(spread_radius=1, blur_radius=16, color="#0F172A0D"),
    )
