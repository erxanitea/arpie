import flet as ft


def build_topbar(app) -> ft.Container:
    ssid = "Not Connected"
    if app.network_context and app.network_context.ssid:
        ssid = f"Connected: {app.network_context.ssid}"

    ctx_label = "UNKNOWN"
    ctx_color = "#64748B"
    if app.network_context:
        cl = app.network_context.classification
        if cl == "trusted":
            ctx_label = "TRUSTED"
            ctx_color = "#10B981"
        elif cl == "public-untrusted":
            ctx_label = "PUBLIC / UNTRUSTED"
            ctx_color = "#DC2626"
        else:
            ctx_label = "UNKNOWN"
            ctx_color = "#64748B"

    is_evaluator = (app.user_role == "Evaluator/Administrator")

    right_controls: list[ft.Control] = []
    if is_evaluator:
        right_controls.append(
            ft.TextButton(
                "⚡ Simulate Attack",
                icon=ft.Icons.BOLT_ROUNDED,
                on_click=lambda e: app.simulate_demo_threat(),
                style=ft.ButtonStyle(color="#DC2626"),
            )
        )

    right_controls.extend([
        ft.Row([
            ft.Icon(ft.Icons.WIFI_ROUNDED, color="#64748B", size=16),
            ft.Text(ssid, size=12, weight=ft.FontWeight.W_500, color="#475569"),
        ], spacing=4),
        ft.Container(
            content=ft.Row([
                ft.Icon(ft.Icons.SHIELD_ROUNDED, color="#FFFFFF", size=12),
                ft.Text(ctx_label, size=11, weight=ft.FontWeight.BOLD, color="#FFFFFF"),
            ], spacing=4),
            bgcolor=ctx_color, border_radius=6, padding=ft.Padding.symmetric(horizontal=8, vertical=4),
        ),
    ])

    return ft.Container(
        content=ft.Row([
            ft.Column([
                app.top_bar_title,
                app.top_bar_subtitle,
            ], spacing=2),
            ft.Row(right_controls, spacing=14)
        ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
        padding=ft.Padding.symmetric(horizontal=24, vertical=16),
        border=ft.Border(bottom=ft.BorderSide(1, "#E2E8F0")),
        bgcolor="#FFFFFF",
        height=65,
    )
