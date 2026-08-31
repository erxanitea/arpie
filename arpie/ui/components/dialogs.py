import flet as ft


def show_evidence_dialog(app, a_type: str, sev: str, src: str, desc: str):
    dlg = ft.AlertDialog(
        title=ft.Text(f"Alert Investigation: {a_type}", size=18, weight=ft.FontWeight.BOLD),
        content=ft.Column([
            ft.Text(f"Severity: {sev}", size=13, weight=ft.FontWeight.BOLD, color="#DC2626"),
            ft.Text(f"Source IP: {src}", size=13, color="#0F172A"),
            ft.Divider(color="#E2E8F0", height=10),
            ft.Text("Evidence Data:", size=12, weight=ft.FontWeight.BOLD, color="#64748B"),
            ft.Container(
                content=ft.Text(desc, size=12, color="#334155"),
                bgcolor="#F8FAFC", border=ft.Border.all(1, "#E2E8F0"), border_radius=6, padding=10,
            ),
        ], spacing=8, width=420, height=180),
        actions=[
            ft.TextButton("Dismiss", on_click=lambda e: app.close_dialog(dlg)),
            ft.ElevatedButton("Block Host (Seal)", icon=ft.Icons.LOCK_ROUNDED, style=ft.ButtonStyle(bgcolor="#DC2626", color="#FFFFFF"), on_click=lambda e: app.block_ip(src, dlg)),
        ],
    )
    app.open_dialog(dlg)


def show_seal_dialog(app):
    dlg = ft.AlertDialog(
        title=ft.Text("Activate Emergency Seal Mode?", size=18, weight=ft.FontWeight.BOLD, color="#DC2626"),
        content=ft.Text("This will immediately drop hostile network traffic and isolate untrusted connections using local firewall rules.", size=13, color="#475569"),
        actions=[
            ft.TextButton("Cancel", on_click=lambda e: app.close_dialog(dlg)),
            ft.ElevatedButton("Confirm & Seal", style=ft.ButtonStyle(bgcolor="#DC2626", color="#FFFFFF"), on_click=lambda e: app.activate_seal(dlg)),
        ],
    )
    app.open_dialog(dlg)



