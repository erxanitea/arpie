import flet as ft
from ..theme import LOGO_PATH


def build_sidebar(app) -> ft.Container:
    is_evaluator = (app.user_role == "Evaluator/Administrator")
    nav_items = [
        ("dashboard", "Dashboard", ft.Icons.DASHBOARD_OUTLINED, ft.Icons.DASHBOARD_ROUNDED, None),
        ("alerts", "Alerts", ft.Icons.NOTIFICATIONS_OUTLINED, ft.Icons.NOTIFICATIONS_ROUNDED, str(len(app.all_alerts_list))),
        ("inventory", "Network", ft.Icons.HUB_OUTLINED, ft.Icons.HUB_ROUNDED, None),
        ("packets", "Packet Logs", ft.Icons.ARTICLE_OUTLINED, ft.Icons.ARTICLE_ROUNDED, None),
        ("seal", "Seal Mode", ft.Icons.SECURITY_OUTLINED, ft.Icons.SECURITY_ROUNDED, str(len(app.active_blocks))),
        ("reports", "Reports", ft.Icons.INSERT_CHART_OUTLINED, ft.Icons.INSERT_CHART_ROUNDED, None),
    ]
    if is_evaluator:
        nav_items.append(("users", "Users", ft.Icons.PEOPLE_OUTLINED, ft.Icons.PEOPLE_ROUNDED, None))
    nav_items.append(("settings", "Settings", ft.Icons.SETTINGS_OUTLINED, ft.Icons.SETTINGS_ROUNDED, None))

    app.sidebar_btn_refs = []
    nav_controls: list[ft.Control] = []
    for v_id, label, icon_off, icon_on, badge in nav_items:
        is_active = (app.current_view == v_id)
        icon_ctrl = ft.Icon(icon_on if is_active else icon_off, color="#FFFFFF" if is_active else "#94A3B8", size=18)
        text_ctrl = ft.Text(label, size=13, weight=ft.FontWeight.W_600 if is_active else ft.FontWeight.W_500, color="#FFFFFF" if is_active else "#94A3B8")

        row_content: list[ft.Control] = [icon_ctrl, text_ctrl]
        if badge:
            row_content.extend([
                ft.Container(expand=True),
                ft.Container(
                    content=ft.Text(badge, size=10, weight=ft.FontWeight.BOLD, color="#FFFFFF"),
                    bgcolor="#DC2626", border_radius=10, padding=ft.Padding.symmetric(horizontal=6, vertical=2),
                )
            ])

        btn = ft.Container(
            content=ft.Row(row_content, spacing=10),
            padding=ft.Padding.symmetric(horizontal=14, vertical=10),
            border_radius=8,
            bgcolor="#1E293B" if is_active else "transparent",
            ink=True,
            on_click=lambda e, vid=v_id: app.nav_to(vid),
        )
        app.sidebar_btn_refs.append((v_id, btn, icon_ctrl, text_ctrl, icon_on, icon_off))
        nav_controls.append(btn)

    monitoring_widget = ft.Container(
        content=ft.Column([
            ft.Row([
                ft.Text("MONITORING", size=10, weight=ft.FontWeight.BOLD, color="#94A3B8"),
                ft.Row([
                    ft.Container(width=6, height=6, border_radius=3, bgcolor="#10B981" if app.is_monitoring else "#64748B"),
                    ft.Text("ACTIVE" if app.is_monitoring else "PAUSED", size=10, weight=ft.FontWeight.BOLD, color="#10B981" if app.is_monitoring else "#94A3B8"),
                ], spacing=4)
            ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
            app.sidebar_timer_text,
            ft.ElevatedButton(
                content=ft.Row([
                    ft.Icon(ft.Icons.STOP_ROUNDED if app.is_monitoring else ft.Icons.PLAY_ARROW_ROUNDED, color="#FFFFFF", size=16),
                    ft.Text("Stop Monitoring" if app.is_monitoring else "Resume", size=12, weight=ft.FontWeight.BOLD, color="#FFFFFF"),
                ], alignment=ft.MainAxisAlignment.CENTER, spacing=6),
                style=ft.ButtonStyle(
                    bgcolor="#DC2626" if app.is_monitoring else "#10B981",
                    shape=ft.RoundedRectangleBorder(radius=6),
                ),
                on_click=lambda e: app.toggle_monitoring(),
                width=200,
            )
        ], spacing=6),
        padding=12,
        border_radius=10,
        bgcolor="#1E293B",
        border=ft.Border.all(1, "#334155"),
    )

    user_footer = ft.Container(
        content=ft.Row([
            ft.Row([
                ft.Container(
                    content=ft.Icon(ft.Icons.PERSON_ROUNDED, color="#FFFFFF", size=14),
                    bgcolor="#334155", border_radius=14, padding=4,
                ),
                ft.Column([
                    ft.Text(app.user_name or app.operator_username or "Operator", size=11, weight=ft.FontWeight.BOLD, color="#FFFFFF", max_lines=1, overflow=ft.TextOverflow.ELLIPSIS),
                    ft.Text("Evaluator" if app.user_role == "Evaluator/Administrator" else "End User", size=9, color="#94A3B8"),
                ], spacing=1, expand=True),
            ], spacing=6, expand=True),
            ft.IconButton(
                icon=ft.Icons.LOGOUT_ROUNDED,
                icon_color="#EF4444",
                icon_size=16,
                tooltip="Sign Out",
                on_click=lambda e: app.logout(),
            ),
        ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
        padding=ft.Padding.symmetric(horizontal=8, vertical=4),
        bgcolor="#1E293B",
        border_radius=8,
        border=ft.Border.all(1, "#334155"),
    )

    return ft.Container(
        content=ft.Column([
            ft.Row([
                ft.Container(
                    content=ft.Image(src=LOGO_PATH, width=34, height=34, fit=ft.BoxFit.CONTAIN),
                    bgcolor="#FFFFFF",
                    border_radius=8,
                    padding=3,
                    border=ft.Border.all(1, "#334155"),
                ),
                ft.Column([
                    ft.Text("ARPIE", size=16, weight=ft.FontWeight.W_900, color="#FFFFFF"),
                    ft.Text("The Tech-Savvy Seal", size=10, color="#94A3B8"),
                ], spacing=1),
            ], spacing=10),

            ft.Divider(color="#1E293B", height=14),
            ft.Column(nav_controls, spacing=3, expand=True),
            monitoring_widget,
            ft.Container(height=4),
            user_footer,
        ]),
        width=230,
        bgcolor="#0F172A",
        padding=14,
    )
