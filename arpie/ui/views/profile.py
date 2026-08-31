import flet as ft
from ..theme import LOGO_PATH


def _make_rule_switch(app, label: str, icon, rule_key: str) -> ft.Container:
    is_evaluator = getattr(app, "is_evaluator", False)
    return ft.Container(
        content=ft.Row([
            ft.Row([
                ft.Icon(icon, size=18, color="#64748B"),
                ft.Text(label, size=13, weight=ft.FontWeight.W_600, color="#0F172A"),
            ], spacing=8),
            ft.Switch(
                value=app.detection_rules.get(rule_key, True),
                active_color="#DC2626",
                disabled=not is_evaluator,
                on_change=lambda e, k=rule_key: app.toggle_rule(k, e.control.value),
            )
        ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
        padding=10, border=ft.Border.all(1, "#E2E8F0"), border_radius=8,
    )


def _make_param_field(app, label: str, default_val: str, unit: str, param_key: str) -> ft.Container:
    is_evaluator = getattr(app, "is_evaluator", False)
    return ft.Container(
        content=ft.Row([
            ft.Text(label, size=13, weight=ft.FontWeight.W_500, color="#0F172A"),
            ft.Row([
                ft.TextField(
                    value=app.thresholds.get(param_key, default_val),
                    width=70, dense=True, text_size=12, text_align=ft.TextAlign.CENTER,
                    border_color="#CBD5E1", border_radius=6,
                    read_only=not is_evaluator,
                    on_change=lambda e, k=param_key: app.set_threshold(k, e.control.value),
                ),
                ft.Text(unit, size=12, color="#64748B"),
            ], spacing=6)
        ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
        padding=10, border=ft.Border.all(1, "#E2E8F0"), border_radius=8,
    )


def render_profile_screen(app) -> ft.Container:
    def select_profile(prof_name):
        app.selected_profile = prof_name
        app.render()

    def on_start_monitoring(e):
        app.current_screen = "app_shell"
        app.current_view = "dashboard"
        app.render()
        app.start_monitoring()

    profile_cards = ft.Row([
        ft.Container(
            content=ft.Column([
                ft.Row([
                    ft.Icon(ft.Icons.BALANCE_ROUNDED, size=24, color="#64748B"),
                    ft.Icon(ft.Icons.RADIO_BUTTON_UNCHECKED, size=18, color="#CBD5E1"),
                ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                ft.Text("Balanced", size=16, weight=ft.FontWeight.BOLD, color="#0F172A"),
                ft.Text("Recommended for everyday use and trusted offices.", size=12, color="#64748B"),
            ], spacing=6),
            bgcolor="#FFFFFF" if app.selected_profile != "Balanced" else "#FEF2F2",
            border=ft.Border.all(2 if app.selected_profile == "Balanced" else 1, "#DC2626" if app.selected_profile == "Balanced" else "#E2E8F0"),
            border_radius=12, padding=16, expand=1, on_click=lambda e: select_profile("Balanced"),
        ),
        ft.Container(
            content=ft.Column([
                ft.Row([
                    ft.Icon(ft.Icons.WIFI_LOCK_ROUNDED, size=24, color="#DC2626"),
                    ft.Row([
                        ft.Container(
                            content=ft.Text("★ Recommended", size=10, weight=ft.FontWeight.BOLD, color="#FFFFFF"),
                            bgcolor="#DC2626", padding=ft.Padding.symmetric(horizontal=6, vertical=2), border_radius=4,
                        ),
                        ft.Icon(ft.Icons.RADIO_BUTTON_CHECKED if app.selected_profile == "Public Wi-Fi" else ft.Icons.RADIO_BUTTON_UNCHECKED, size=18, color="#DC2626" if app.selected_profile == "Public Wi-Fi" else "#CBD5E1"),
                    ], spacing=6)
                ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                ft.Text("Public Wi-Fi", size=16, weight=ft.FontWeight.BOLD, color="#0F172A"),
                ft.Text("Higher sensitivity tuned for unfamiliar networks.", size=12, color="#64748B"),
            ], spacing=6),
            bgcolor="#FEF2F2" if app.selected_profile == "Public Wi-Fi" else "#FFFFFF",
            border=ft.Border.all(2 if app.selected_profile == "Public Wi-Fi" else 1, "#DC2626" if app.selected_profile == "Public Wi-Fi" else "#E2E8F0"),
            border_radius=12, padding=16, expand=1, on_click=lambda e: select_profile("Public Wi-Fi"),
        ),
        ft.Container(
            content=ft.Column([
                ft.Row([
                    ft.Icon(ft.Icons.TUNE_ROUNDED, size=24, color="#64748B"),
                    ft.Icon(ft.Icons.RADIO_BUTTON_CHECKED if app.selected_profile == "Custom" else ft.Icons.RADIO_BUTTON_UNCHECKED, size=18, color="#DC2626" if app.selected_profile == "Custom" else "#CBD5E1"),
                ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                ft.Text("Custom", size=16, weight=ft.FontWeight.BOLD, color="#0F172A"),
                ft.Text("Configure detection rules and thresholds manually.", size=12, color="#64748B"),
            ], spacing=6),
            bgcolor="#FEF2F2" if app.selected_profile == "Custom" else "#FFFFFF",
            border=ft.Border.all(2 if app.selected_profile == "Custom" else 1, "#DC2626" if app.selected_profile == "Custom" else "#E2E8F0"),
            border_radius=12, padding=16, expand=1, on_click=lambda e: select_profile("Custom"),
        ),
    ], spacing=16)

    rules_panel = ft.Container(
        content=ft.Column([
            ft.Row([
                ft.Icon(ft.Icons.WIFI_ROUNDED, color="#DC2626", size=18),
                ft.Text(f"{app.selected_profile} Profile", size=16, weight=ft.FontWeight.BOLD, color="#0F172A"),
            ], spacing=8),
            ft.Text("Enhanced detection tuned for shared and untrusted networks.", size=12, color="#64748B"),
            ft.Divider(color="#E2E8F0", height=20),
            ft.Row([
                ft.Column([
                    ft.Text("DETECTION RULES", size=11, weight=ft.FontWeight.BOLD, color="#94A3B8"),
                    _make_rule_switch(app, "ARP Detection", ft.Icons.HUB_OUTLINED, "arp"),
                    _make_rule_switch(app, "Port Scan Detection", ft.Icons.GRID_VIEW_ROUNDED, "port_scan"),
                    _make_rule_switch(app, "Traffic Anomaly", ft.Icons.SHOW_CHART_ROUNDED, "traffic_rate"),
                    _make_rule_switch(app, "Gateway Monitoring", ft.Icons.ROUTER_OUTLINED, "gateway"),
                ], expand=1, spacing=10),
                ft.VerticalDivider(color="#E2E8F0", width=24),
                ft.Column([
                    ft.Text("PARAMETERS", size=11, weight=ft.FontWeight.BOLD, color="#94A3B8"),
                    _make_param_field(app, "Traffic Threshold", "100", "packets/sec", "traffic"),
                    _make_param_field(app, "Port Threshold", "15", "ports / 10 sec", "port"),
                    _make_param_field(app, "ARP Window", "5", "minutes", "arp_window"),
                ], expand=1, spacing=14)
            ], expand=True),
        ]),
        bgcolor="#FFFFFF", padding=24, border_radius=14, border=ft.Border.all(1, "#E2E8F0"), expand=True,
    )

    return ft.Container(
        content=ft.Column([
            ft.Row([
                ft.Row([
                    ft.Container(
                        content=ft.Image(src=LOGO_PATH, width=32, height=32, fit=ft.BoxFit.CONTAIN),
                        border_radius=8,
                    ),
                    ft.Column([
                        ft.Text("ARPIE", size=16, weight=ft.FontWeight.BOLD, color="#0F172A"),
                        ft.Text("The Tech-Savvy Seal", size=11, color="#64748B"),
                    ], spacing=1),
                ], spacing=8),
                ft.Container(
                    content=ft.Row([
                        ft.Icon(ft.Icons.SHIELD_ROUNDED, color="#DC2626" if not app.network_context or app.network_context.classification != "trusted" else "#10B981", size=14),
                        ft.Text(
                            f"Network Context: {(app.network_context.classification or 'unknown').upper().replace('PUBLIC-UNTRUSTED', 'PUBLIC / UNTRUSTED')}" if app.network_context else "Network Context: UNKNOWN",
                            size=12, weight=ft.FontWeight.BOLD,
                            color="#DC2626" if not app.network_context or app.network_context.classification != "trusted" else "#10B981",
                        ),
                    ], spacing=6),
                    bgcolor="#FEF2F2" if not app.network_context or app.network_context.classification != "trusted" else "#ECFDF5",
                    border=ft.Border.all(1, "#FECACA" if not app.network_context or app.network_context.classification != "trusted" else "#A7F3D0"),
                    border_radius=6, padding=ft.Padding.symmetric(horizontal=10, vertical=4),
                )
            ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
            ft.Container(height=6),
            ft.Text("Select Monitoring Profile", size=24, weight=ft.FontWeight.BOLD, color="#0F172A"),
            ft.Text("Choose how Arpie should monitor this connection.", size=13, color="#64748B"),
            ft.Container(height=10),
            profile_cards,
            ft.Container(height=10),
            rules_panel,
            ft.Container(height=10),
            ft.Row([
                ft.OutlinedButton("← Back to Context", on_click=lambda e: app.go_to_context()),
                ft.ElevatedButton(
                    content=ft.Row([
                        ft.Icon(ft.Icons.PLAY_ARROW_ROUNDED, color="#FFFFFF", size=18),
                        ft.Text("Start Monitoring", size=14, weight=ft.FontWeight.BOLD, color="#FFFFFF"),
                    ], spacing=6),
                    style=ft.ButtonStyle(bgcolor="#DC2626", shape=ft.RoundedRectangleBorder(radius=8), padding=14),
                    on_click=on_start_monitoring,
                )
            ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN)
        ], expand=True),
        padding=30, expand=True, bgcolor="#FAFAFC",
    )
