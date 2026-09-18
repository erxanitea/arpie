"""Incident investigation dialog: shows the evidence behind one alert."""

import flet as ft


def show_evidence_dialog(app, a_type: str, sev: str, src: str, desc: str):
    sev_color = "#DC2626" if sev.upper() in ["HIGH", "CRITICAL"] else ("#D97706" if sev.upper() == "MEDIUM" else "#10B981")
    dlg = ft.AlertDialog(
        title=ft.Row([
            ft.Icon(ft.Icons.POLICY_ROUNDED, size=20, color="#0F172A"),
            ft.Text(f"Incident Investigation: {a_type}", size=16, weight=ft.FontWeight.BOLD, color="#0F172A"),
        ], spacing=8),
        content=ft.Container(
            content=ft.Column([
                ft.Row([
                    ft.Text("Severity Level:", size=12, weight=ft.FontWeight.BOLD, color="#64748B"),
                    ft.Container(
                        content=ft.Text(sev.upper(), size=11, weight=ft.FontWeight.BOLD, color="#FFFFFF"),
                        bgcolor=sev_color, border_radius=6, padding=ft.Padding.symmetric(horizontal=8, vertical=2),
                    ),
                    ft.Container(width=10),
                    ft.Text("Source Address:", size=12, weight=ft.FontWeight.BOLD, color="#64748B"),
                    ft.Text(src, size=12, weight=ft.FontWeight.BOLD, color="#0F172A", font_family="monospace"),
                ], spacing=6),
                ft.Divider(color="#E2E8F0", height=8),
                ft.Text("Recorded Packet Evidence:", size=12, weight=ft.FontWeight.BOLD, color="#475569"),
                ft.Container(
                    content=ft.Text(desc, size=12, color="#334155", selectable=True),
                    bgcolor="#F8FAFC", border=ft.Border.all(1, "#E2E8F0"), border_radius=6, padding=12,
                    expand=True,
                ),
            ], spacing=6),
            width=460, height=220,
        ),
        actions=[
            ft.TextButton("Close", on_click=lambda e: app.close_dialog(dlg), style=ft.ButtonStyle(color="#64748B")),
            ft.Button(
                "Block & Isolate Host",
                icon=ft.Icons.BLOCK_ROUNDED,
                style=ft.ButtonStyle(bgcolor="#DC2626", color="#FFFFFF"),
                on_click=lambda e: app.block_ip(src, dlg),
            ),
        ],
    )
    app.open_dialog(dlg)
