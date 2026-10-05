"""Confirmation dialog for activating emergency Seal Mode."""

import flet as ft


def show_seal_dialog(app, target_ip=None, event_id=None):
    dlg = ft.AlertDialog(
        title=ft.Row([
            ft.Icon(ft.Icons.SHIELD_ROUNDED, size=22, color="#DC2626"),
            ft.Text("Activate Emergency Seal Mode?", size=16, weight=ft.FontWeight.BOLD, color="#0F172A"),
        ], spacing=8),
        content=ft.Container(
            content=ft.Column([
                ft.Container(
                    content=ft.Column([
                        ft.Row([
                            ft.Icon(ft.Icons.WARNING_AMBER_ROUNDED, size=16, color="#DC2626"),
                            ft.Text("Active Network Containment", size=12, weight=ft.FontWeight.BOLD, color="#DC2626"),
                        ], spacing=6),
                        ft.Text("This will immediately drop hostile network traffic and isolate untrusted connections using local firewall rules.", size=11, color="#64748B"),
                    ], spacing=4),
                    bgcolor="#FEE2E2", border=ft.Border.all(1, "#FECACA"), border_radius=8, padding=12,
                ),
            ], spacing=8),
            width=380,
            height=112,
        ),
        actions=[
            ft.TextButton("Cancel", on_click=lambda e: app.close_dialog(dlg), style=ft.ButtonStyle(color="#64748B")),
            ft.Button(
                "Confirm & Seal Network",
                icon=ft.Icons.LOCK_ROUNDED,
                style=ft.ButtonStyle(bgcolor="#DC2626", color="#FFFFFF"),
                on_click=lambda e: app.activate_seal(dlg, target_ip=target_ip, event_id=event_id),
            ),
        ],
    )
    app.open_dialog(dlg)
