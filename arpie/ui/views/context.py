import flet as ft
import psutil
from ...network_context import detect_network_context
from ..theme import LOGO_PATH


def _make_detail_row(icon, label: str, val: str) -> ft.Container:
    return ft.Container(
        content=ft.Row([
            ft.Row([
                ft.Icon(icon, color="#64748B", size=18),
                ft.Text(label, size=13, color="#475569", weight=ft.FontWeight.W_500),
            ], spacing=8),
            ft.Text(val, size=13, weight=ft.FontWeight.BOLD, color="#0F172A"),
        ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
        padding=ft.Padding.symmetric(vertical=6),
        border=ft.Border(bottom=ft.BorderSide(1, "#F1F5F9")),
    )


def render_context_screen(app) -> ft.Container:
    if not app.network_context:
        app.network_context = detect_network_context()

    ssid = app.network_context.ssid or "Unknown Network"
    gateway = app.network_context.gateway_ip or "Unknown"
    iface = app.network_context.interface or "Unknown"

    local_ip = "Unknown"
    try:
        addrs = psutil.net_if_addrs()
        if iface in addrs:
            for addr in addrs[iface]:
                if addr.family.name == "AF_INET":
                    local_ip = addr.address
                    break
        if local_ip == "Unknown":
            for name, addr_list in addrs.items():
                if name.lower().startswith("lo"):
                    continue
                for addr in addr_list:
                    if addr.family.name == "AF_INET":
                        local_ip = addr.address
                        break
                if local_ip != "Unknown":
                    break
    except Exception:
        pass

    cl = app.network_context.classification
    if cl == "trusted":
        detected_type = "TRUSTED"
        type_color = "#10B981"
        type_bg = "#ECFDF5"
        type_border = "#A7F3D0"
    elif cl == "public-untrusted":
        detected_type = "PUBLIC / UNTRUSTED"
        type_color = "#DC2626"
        type_bg = "#FEF2F2"
        type_border = "#FECACA"
    else:
        detected_type = "UNKNOWN"
        type_color = "#64748B"
        type_bg = "#F8FAFC"
        type_border = "#E2E8F0"

    classification_rg = ft.RadioGroup(
        content=ft.Column([
            ft.Container(
                content=ft.Row([
                    ft.Radio(value="public", active_color="#DC2626"),
                    ft.Icon(ft.Icons.WARNING_AMBER_ROUNDED, color="#DC2626", size=20),
                    ft.Column([
                        ft.Text("Public / Untrusted", size=14, weight=ft.FontWeight.BOLD, color="#0F172A"),
                        ft.Text("Enhanced monitoring recommended", size=12, color="#64748B"),
                    ], spacing=2)
                ], spacing=10),
                padding=10, border=ft.Border.all(1, "#DC2626"), border_radius=8, bgcolor="#FEF2F2",
            ),
            ft.Container(
                content=ft.Row([
                    ft.Radio(value="trusted", active_color="#10B981"),
                    ft.Icon(ft.Icons.SHIELD_OUTLINED, color="#10B981", size=20),
                    ft.Column([
                        ft.Text("Trusted", size=14, weight=ft.FontWeight.BOLD, color="#0F172A"),
                        ft.Text("Home or known network", size=12, color="#64748B"),
                    ], spacing=2)
                ], spacing=10),
                padding=10, border=ft.Border.all(1, "#E2E8F0"), border_radius=8,
            ),
            ft.Container(
                content=ft.Row([
                    ft.Radio(value="unknown", active_color="#64748B"),
                    ft.Icon(ft.Icons.HELP_OUTLINE_ROUNDED, color="#64748B", size=20),
                    ft.Column([
                        ft.Text("Unknown", size=14, weight=ft.FontWeight.BOLD, color="#0F172A"),
                        ft.Text("Could not classify confidently", size=12, color="#64748B"),
                    ], spacing=2)
                ], spacing=10),
                padding=10, border=ft.Border.all(1, "#E2E8F0"), border_radius=8,
            ),
        ], spacing=10),
        value="public",
    )

    def on_continue(e):
        app.current_screen = "profile"
        app.render()

    header_bar = ft.Row([
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
    ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN)

    left_col = ft.Container(
        content=ft.Column([
            ft.Text("Connection Details", size=16, weight=ft.FontWeight.BOLD, color="#0F172A"),
            ft.Text("Information gathered from your active interface.", size=12, color="#64748B"),
            ft.Container(height=8),
            _make_detail_row(ft.Icons.WIFI_ROUNDED, "Connected Network", ssid),
            _make_detail_row(ft.Icons.ROUTER_ROUNDED, "Gateway", gateway),
            _make_detail_row(ft.Icons.COMPUTER_ROUNDED, "Local IP", local_ip),
            _make_detail_row(ft.Icons.PUBLIC_ROUNDED, "Interface", iface),
        ], spacing=10),
        bgcolor="#FFFFFF",
        padding=24,
        border_radius=14,
        border=ft.Border.all(1, "#E2E8F0"),
        expand=1,
    )

    right_col = ft.Column([
        ft.Container(
            content=ft.Column([
                ft.Text("NETWORK TYPE", size=11, weight=ft.FontWeight.BOLD, color="#94A3B8"),
                ft.Row([
                    ft.Container(
                        content=ft.Row([
                            ft.Icon(ft.Icons.WARNING_ROUNDED, color="#FFFFFF", size=14),
                            ft.Text(detected_type, size=12, weight=ft.FontWeight.BOLD, color="#FFFFFF"),
                        ], spacing=6),
                        bgcolor=type_color, padding=ft.Padding.symmetric(horizontal=10, vertical=4), border_radius=6,
                    ),
                    ft.Container(
                        content=ft.Row([
                            ft.Icon(ft.Icons.CHECK_CIRCLE_OUTLINE_ROUNDED, color="#0F172A", size=14),
                            ft.Text("Confidence: High", size=12, weight=ft.FontWeight.BOLD, color="#0F172A"),
                        ], spacing=6),
                        bgcolor="#F1F5F9", padding=ft.Padding.symmetric(horizontal=10, vertical=4), border_radius=6,
                    )
                ]),
                ft.Container(
                    content=ft.Row([
                        ft.Icon(ft.Icons.INFO_OUTLINE_ROUNDED, color="#64748B", size=16),
                        ft.Text("Why? This network appears to be a shared/public environment.", size=12, color="#475569"),
                    ], spacing=8),
                    bgcolor="#FFFFFF", padding=10, border_radius=8, border=ft.Border.all(1, "#E2E8F0"),
                )
            ], spacing=10),
            bgcolor=type_bg, padding=18, border_radius=14, border=ft.Border.all(1, type_border),
        ),
        ft.Container(
            content=ft.Column([
                ft.Text("Classification", size=16, weight=ft.FontWeight.BOLD, color="#0F172A"),
                ft.Text("Confirm or override the detected context.", size=12, color="#64748B"),
                ft.Container(height=6),
                classification_rg,
            ], spacing=8),
            bgcolor="#FFFFFF", padding=20, border_radius=14, border=ft.Border.all(1, "#E2E8F0"),
        )
    ], expand=1, spacing=14)

    return ft.Container(
        content=ft.Column([
            header_bar,
            ft.Container(height=10),
            ft.Row([
                ft.Icon(ft.Icons.WIFI_ROUNDED, color="#DC2626", size=28),
                ft.Column([
                    ft.Text("Network Context", size=24, weight=ft.FontWeight.BOLD, color="#0F172A"),
                    ft.Text("We detected your current network environment.", size=13, color="#64748B"),
                ], spacing=2),
            ], spacing=12),
            ft.Container(height=14),
            ft.Row([left_col, right_col], expand=True, spacing=20),
            ft.Container(height=14),
            ft.Row([
                ft.Row([
                    ft.Icon(ft.Icons.LOCK_OUTLINE_ROUNDED, size=14, color="#94A3B8"),
                    ft.Text("Local monitoring enabled · v1.0.0", size=12, color="#94A3B8"),
                ], spacing=6),
                ft.ElevatedButton(
                    content=ft.Row([
                        ft.Text("Continue to Monitoring", size=14, weight=ft.FontWeight.BOLD, color="#FFFFFF"),
                        ft.Icon(ft.Icons.ARROW_FORWARD_ROUNDED, color="#FFFFFF", size=16),
                    ], spacing=6),
                    style=ft.ButtonStyle(bgcolor="#DC2626", shape=ft.RoundedRectangleBorder(radius=8), padding=14),
                    on_click=on_continue,
                )
            ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN)
        ], expand=True),
        padding=30,
        expand=True,
        bgcolor="#FAFAFC",
    )
