import flet as ft
import psutil
from arpie.network import detect_network_context
from arpie.views.theme import LOGO_PATH


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
    if not app.network_context or not app.local_ip:
        app.refresh_network_context()

    ssid = app.network_context.ssid or "Unknown Network"
    gateway = app.network_context.gateway_ip or "Unknown"
    iface = app.network_context.interface or "Unknown"

    local_ip = app.local_ip or "Unknown"
    try:
        if local_ip == "Unknown":
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
        if local_ip != "Unknown" and not app.local_ip:
            app.local_ip = local_ip
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

    type_badge_icon = ft.Icon(
        ft.Icons.VERIFIED_USER_ROUNDED if cl == "trusted" else (ft.Icons.HELP_OUTLINE_ROUNDED if cl == "unknown" else ft.Icons.WARNING_ROUNDED),
        color="#FFFFFF", size=14
    )
    type_badge_text = ft.Text(detected_type, size=12, weight=ft.FontWeight.BOLD, color="#FFFFFF")
    type_badge_container = ft.Container(
        content=ft.Row([type_badge_icon, type_badge_text], spacing=6),
        bgcolor=type_color,
        padding=ft.Padding.symmetric(horizontal=10, vertical=4),
        border_radius=6,
    )
    why_text = ft.Text(
        "Why? This SSID is on your trusted list — reduced sensitivity applied."
        if cl == "trusted" else
        "Why? SSID could not be determined, so context is uncertain."
        if cl == "unknown" else
        "Why? This network is not on your trusted list — treated as public/shared.",
        size=12, color="#475569"
    )
    summary_box = ft.Container(
        content=ft.Column([
            ft.Text("NETWORK TYPE", size=11, weight=ft.FontWeight.BOLD, color="#94A3B8"),
            ft.Row([
                type_badge_container,
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
                    why_text,
                ], spacing=8),
                bgcolor="#FFFFFF", padding=10, border_radius=8, border=ft.Border.all(1, "#E2E8F0"),
            )
        ], spacing=10),
        bgcolor=type_bg, padding=18, border_radius=14, border=ft.Border.all(1, type_border),
    )

    card_public = ft.Container(
        content=ft.Row([
            ft.Radio(value="public", active_color="#DC2626"),
            ft.Icon(ft.Icons.WARNING_AMBER_ROUNDED, color="#DC2626", size=20),
            ft.Column([
                ft.Text("Public / Untrusted", size=14, weight=ft.FontWeight.BOLD, color="#0F172A"),
                ft.Text("Enhanced monitoring recommended", size=12, color="#64748B"),
            ], spacing=2)
        ], spacing=10),
        padding=10,
        border=ft.Border.all(1, "#DC2626" if cl == "public-untrusted" else "#E2E8F0"),
        border_radius=8,
        bgcolor="#FEF2F2" if cl == "public-untrusted" else "#FFFFFF",
    )

    card_trusted = ft.Container(
        content=ft.Row([
            ft.Radio(value="trusted", active_color="#10B981"),
            ft.Icon(ft.Icons.SHIELD_OUTLINED, color="#10B981", size=20),
            ft.Column([
                ft.Text("Trusted", size=14, weight=ft.FontWeight.BOLD, color="#0F172A"),
                ft.Text("Home or known network", size=12, color="#64748B"),
            ], spacing=2)
        ], spacing=10),
        padding=10,
        border=ft.Border.all(1, "#10B981" if cl == "trusted" else "#E2E8F0"),
        border_radius=8,
        bgcolor="#ECFDF5" if cl == "trusted" else "#FFFFFF",
    )

    card_unknown = ft.Container(
        content=ft.Row([
            ft.Radio(value="unknown", active_color="#64748B"),
            ft.Icon(ft.Icons.HELP_OUTLINE_ROUNDED, color="#64748B", size=20),
            ft.Column([
                ft.Text("Unknown", size=14, weight=ft.FontWeight.BOLD, color="#0F172A"),
                ft.Text("Could not classify confidently", size=12, color="#64748B"),
            ], spacing=2)
        ], spacing=10),
        padding=10,
        border=ft.Border.all(1, "#64748B" if cl == "unknown" else "#E2E8F0"),
        border_radius=8,
        bgcolor="#F8FAFC" if cl == "unknown" else "#FFFFFF",
    )

    already_trusted = bool(app.network_context.ssid) and app.network_context.ssid in app.get_trusted_ssids()
    remember_cb = ft.Checkbox(
        label="Remember this network as trusted for next time",
        value=already_trusted or (cl == "trusted"),
        active_color="#10B981",
    )

    def on_classification_change(e):
        val = classification_rg.value
        is_t = (val == "trusted")
        remember_cb.value = is_t
        if remember_cb.page:
            remember_cb.update()

        card_public.border = ft.Border.all(1, "#DC2626" if val == "public" else "#E2E8F0")
        card_public.bgcolor = "#FEF2F2" if val == "public" else "#FFFFFF"
        card_trusted.border = ft.Border.all(1, "#10B981" if val == "trusted" else "#E2E8F0")
        card_trusted.bgcolor = "#ECFDF5" if val == "trusted" else "#FFFFFF"
        card_unknown.border = ft.Border.all(1, "#64748B" if val == "unknown" else "#E2E8F0")
        card_unknown.bgcolor = "#F8FAFC" if val == "unknown" else "#FFFFFF"

        if is_t:
            type_badge_icon.icon = ft.Icons.VERIFIED_USER_ROUNDED
            type_badge_text.value = "TRUSTED"
            type_badge_container.bgcolor = "#10B981"
            summary_box.bgcolor = "#ECFDF5"
            summary_box.border = ft.Border.all(1, "#A7F3D0")
            why_text.value = "Why? Selected as trusted network — standard sensitivity applied."
        elif val == "public":
            type_badge_icon.icon = ft.Icons.WARNING_ROUNDED
            type_badge_text.value = "PUBLIC / UNTRUSTED"
            type_badge_container.bgcolor = "#DC2626"
            summary_box.bgcolor = "#FEF2F2"
            summary_box.border = ft.Border.all(1, "#FECACA")
            why_text.value = "Why? Treated as public/untrusted — enhanced monitoring recommended."
        else:
            type_badge_icon.icon = ft.Icons.HELP_OUTLINE_ROUNDED
            type_badge_text.value = "UNKNOWN"
            type_badge_container.bgcolor = "#64748B"
            summary_box.bgcolor = "#F8FAFC"
            summary_box.border = ft.Border.all(1, "#E2E8F0")
            why_text.value = "Why? SSID could not be determined, so context is uncertain."

        if app.page:
            app.page.update()

    classification_rg = ft.RadioGroup(
        content=ft.Column([card_public, card_trusted, card_unknown], spacing=10),
        value={"trusted": "trusted", "public-untrusted": "public"}.get(cl, "unknown"),
        on_change=on_classification_change,
    )

    def on_continue(e):
        selected_cl = classification_rg.value or "public"
        app.apply_classification(selected_cl, remember=bool(remember_cb.value))
        if selected_cl == "trusted":
            app.selected_profile = "Balanced"
            app.thresholds["traffic"] = "250"
            app.thresholds["port"] = "30"
            app.thresholds["arp_window"] = "10"
        else:
            app.selected_profile = "Public Wi-Fi"
            app.thresholds["traffic"] = "100"
            app.thresholds["port"] = "15"
            app.thresholds["arp_window"] = "5"
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
        summary_box,
        ft.Container(
            content=ft.Column([
                ft.Text("Classification", size=16, weight=ft.FontWeight.BOLD, color="#0F172A"),
                ft.Text("Confirm or override the detected context.", size=12, color="#64748B"),
                ft.Container(height=6),
                classification_rg,
                ft.Container(height=2),
                remember_cb,
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
                ft.Button(
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
