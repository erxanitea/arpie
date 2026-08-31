import datetime
import flet as ft
from ...network_context import detect_network_context
from ..theme import LOGO_PATH


def render_login_screen(app) -> ft.Container:
    error_msg = ft.Text("", size=11, color="#DC2626", visible=False, weight=ft.FontWeight.W_600)

    identifier_field = ft.TextField(
        hint_text="Enter username or email",
        value="",
        prefix_icon=ft.Icons.ACCOUNT_CIRCLE_OUTLINED,
        dense=True,
        border_radius=10,
        bgcolor="#F8FAFC",
        border_color="#E2E8F0",
        focused_border_color="#DC2626",
        text_size=13,
    )
    password_field = ft.TextField(
        hint_text="Enter your password",
        value="",
        password=True,
        can_reveal_password=True,
        prefix_icon=ft.Icons.LOCK_OUTLINE_ROUNDED,
        dense=True,
        border_radius=10,
        bgcolor="#F8FAFC",
        border_color="#E2E8F0",
        focused_border_color="#DC2626",
        text_size=13,
    )

    def on_sign_in(e):
        entered_id = (identifier_field.value or "").strip()
        entered_p = (password_field.value or "").strip()

        if not entered_id or not entered_p:
            error_msg.value = "Please enter both username/email and password."
            error_msg.visible = True
            app.page.update()
            return

        operator = app.db.authenticate_operator(entered_id, entered_p)
        if operator:
            app.operator_id = operator.get("id")
            app.user_name = operator.get("display_name") or operator.get("username", "")
            app.user_role = operator.get("role", "End User")
            app.operator_username = operator.get("username", "")
            app.operator_email = operator.get("email", "")
            app.operator_last_login = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
            app.network_context = detect_network_context()
            app.current_screen = "context"
            app.render()
        else:
            error_msg.value = "Invalid username/email or password."
            error_msg.visible = True
            app.page.update()

    def go_to_register(e):
        app.current_screen = "register"
        app.render()

    identifier_field.on_submit = on_sign_in
    password_field.on_submit = on_sign_in

    pill = lambda icon, label, color: ft.Container(
        content=ft.Row([
            ft.Icon(icon, size=15, color=color),
            ft.Text(label, size=11, weight=ft.FontWeight.W_600, color="#1E293B"),
        ], spacing=6, alignment=ft.MainAxisAlignment.CENTER),
        bgcolor="#FFFFFF",
        border=ft.Border.all(1, "#E2E8F0"),
        border_radius=20,
        padding=ft.Padding.symmetric(horizontal=12, vertical=6),
        shadow=ft.BoxShadow(spread_radius=0, blur_radius=4, color="#0F172A08"),
    )

    left_branding = ft.Container(
        content=ft.Column([
            ft.Container(
                content=ft.Image(
                    src=LOGO_PATH,
                    width=380,
                    height=320,
                    fit=ft.BoxFit.CONTAIN,
                ),
                padding=0,
            ),
            ft.Text("Safe. Secure. Sealed.", size=20, weight=ft.FontWeight.W_800, color="#DC2626", text_align=ft.TextAlign.CENTER),
            ft.Text("Endpoint Network Intrusion Detection & Threat Response System", size=12, color="#64748B", text_align=ft.TextAlign.CENTER),
            ft.Container(height=10),
            ft.Row([
                pill(ft.Icons.WIFI_LOCK_ROUNDED, "Public Wi-Fi Guard", "#10B981"),
                pill(ft.Icons.RADAR_ROUNDED, "Real-Time Sniffing", "#0284C7"),
            ], spacing=8, alignment=ft.MainAxisAlignment.CENTER),
            ft.Row([
                pill(ft.Icons.SECURITY_ROUNDED, "Reversible Seal Mode", "#DC2626"),
                pill(ft.Icons.ASSESSMENT_OUTLINED, "Forensic Reports", "#8B5CF6"),
            ], spacing=8, alignment=ft.MainAxisAlignment.CENTER),
        ], alignment=ft.MainAxisAlignment.CENTER, horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=4),
        expand=1,
        alignment=ft.Alignment(0, 0),
    )

    login_card = ft.Container(
        content=ft.Column([
            ft.Row([
                ft.Container(
                    content=ft.Icon(ft.Icons.SHIELD_ROUNDED, color="#FFFFFF", size=20),
                    bgcolor="#0F172A",
                    border_radius=10,
                    padding=8,
                )
            ]),
            ft.Text("Welcome to Arpie", size=22, weight=ft.FontWeight.BOLD, color="#0F172A"),
            ft.Text("Protect your connection. Understand your network.\nStay aware.", size=12, color="#64748B"),
            error_msg,
            ft.Container(height=4),
            ft.Column([
                ft.Text("Username or Email", size=12, weight=ft.FontWeight.W_600, color="#0F172A"),
                identifier_field,
            ], spacing=4, tight=True),
            ft.Column([
                ft.Text("Password", size=12, weight=ft.FontWeight.W_600, color="#0F172A"),
                password_field,
            ], spacing=4, tight=True),
            ft.Container(height=4),
            ft.ElevatedButton(
                content=ft.Row([
                    ft.Icon(ft.Icons.LOGIN_ROUNDED, color="#FFFFFF", size=16),
                    ft.Text("Sign In", size=14, weight=ft.FontWeight.BOLD, color="#FFFFFF"),
                ], alignment=ft.MainAxisAlignment.CENTER, spacing=6),
                style=ft.ButtonStyle(
                    bgcolor="#DC2626",
                    shape=ft.RoundedRectangleBorder(radius=10),
                    padding=ft.Padding.symmetric(vertical=14),
                ),
                on_click=on_sign_in,
                width=340,
            ),
            ft.Container(
                content=ft.TextButton(
                    "Don't have an account? Create one",
                    on_click=go_to_register,
                    style=ft.ButtonStyle(color="#64748B"),
                ),
                alignment=ft.Alignment(0, 0),
                padding=ft.Padding.only(top=2),
            )
        ], spacing=10, tight=True),
        width=380,
        bgcolor="#FFFFFF",
        padding=28,
        border_radius=20,
        border=ft.Border.all(1, "#E2E8F0"),
        shadow=ft.BoxShadow(spread_radius=1, blur_radius=24, color="#0F172A0D"),
    )

    right_col = ft.Container(
        content=login_card,
        expand=1,
        alignment=ft.Alignment(0, 0),
    )

    return ft.Container(
        content=ft.Column([
            ft.Container(
                content=ft.Row(
                    [left_branding, right_col],
                    expand=True,
                    alignment=ft.MainAxisAlignment.CENTER,
                    vertical_alignment=ft.CrossAxisAlignment.CENTER,
                ),
                expand=True,
            ),
            ft.Container(
                content=ft.Row([
                    ft.Icon(ft.Icons.LOCK_OUTLINE_ROUNDED, size=14, color="#94A3B8"),
                    ft.Text("Arpie Endpoint NIDS · Version 1.0.0 · Local Sniffing & Threat Response", size=12, color="#94A3B8"),
                ], alignment=ft.MainAxisAlignment.CENTER, spacing=6),
                padding=16,
            )
        ], expand=True),
        expand=True,
        bgcolor="#FAFAFC",
    )
