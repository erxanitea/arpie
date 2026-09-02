import datetime
import re
import flet as ft
from ...network_context import detect_network_context
from ..theme import LOGO_PATH


def render_register_screen(app) -> ft.Container:
    is_initial_setup = not app.db.has_operators()

    error_msg = ft.Text("", size=11, color="#DC2626", visible=False, weight=ft.FontWeight.W_600)
    success_msg = ft.Text("", size=11, color="#10B981", visible=False, weight=ft.FontWeight.W_600)

    fullname_field = ft.TextField(
        hint_text="Enter full name (e.g. Jane Doe)",
        prefix_icon=ft.Icons.BADGE_OUTLINED,
        dense=True,
        border_radius=10,
        bgcolor="#F8FAFC",
        border_color="#E2E8F0",
        focused_border_color="#DC2626",
        text_size=13,
    )
    username_field = ft.TextField(
        hint_text="Choose a username",
        prefix_icon=ft.Icons.PERSON_OUTLINE_ROUNDED,
        dense=True,
        border_radius=10,
        bgcolor="#F8FAFC",
        border_color="#E2E8F0",
        focused_border_color="#DC2626",
        text_size=13,
    )
    email_field = ft.TextField(
        hint_text="Enter your email address",
        prefix_icon=ft.Icons.EMAIL_OUTLINED,
        dense=True,
        border_radius=10,
        bgcolor="#F8FAFC",
        border_color="#E2E8F0",
        focused_border_color="#DC2626",
        text_size=13,
    )
    password_field = ft.TextField(
        hint_text="Create a password (min 4 chars)",
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
    confirm_pw_field = ft.TextField(
        hint_text="Confirm your password",
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

    def on_register(e):
        error_msg.visible = False
        success_msg.visible = False

        fname = (fullname_field.value or "").strip()
        uname = (username_field.value or "").strip()
        email = (email_field.value or "").strip()
        pw = password_field.value or ""
        cpw = confirm_pw_field.value or ""

        if not fname:
            error_msg.value = "Full Name is required."
            error_msg.visible = True
            app.page.update()
            return
        if not uname:
            error_msg.value = "Username is required."
            error_msg.visible = True
            app.page.update()
            return
        if len(uname) < 3:
            error_msg.value = "Username must be at least 3 characters."
            error_msg.visible = True
            app.page.update()
            return
        if not email or not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
            error_msg.value = "Please enter a valid email address."
            error_msg.visible = True
            app.page.update()
            return
        if len(pw) < 4:
            error_msg.value = "Password must be at least 4 characters."
            error_msg.visible = True
            app.page.update()
            return
        if pw != cpw:
            error_msg.value = "Passwords do not match."
            error_msg.visible = True
            app.page.update()
            return

        if app.db.get_operator_by_username(uname):
            error_msg.value = f"Username '{uname}' is already taken."
            error_msg.visible = True
            app.page.update()
            return

        if app.db.get_operator_by_email(email):
            error_msg.value = f"Email '{email}' is already registered."
            error_msg.visible = True
            app.page.update()
            return

        target_role = "Evaluator/Administrator" if is_initial_setup else "End User"
        try:
            op_id = app.db.create_operator(uname, email, pw, display_name=fname, role=target_role)
            if is_initial_setup:
                app.operator_id = op_id
                app.user_name = fname
                app.user_role = target_role
                app.operator_username = uname
                app.operator_email = email
                app.operator_last_login = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
                app.network_context = detect_network_context()
                app.current_screen = "context"
            else:
                app.current_screen = "login"
            app.render()
        except Exception as exc:
            error_msg.value = f"Registration failed: {exc}"
            error_msg.visible = True
            app.page.update()

    def go_to_login(e):
        app.current_screen = "login"
        app.render()

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

    card_title = "Setup Administrator" if is_initial_setup else "Create Your Account"
    card_subtitle = "Configure primary evaluator credentials." if is_initial_setup else "Register an endpoint user account to start monitoring."
    btn_text = "Initialize System" if is_initial_setup else "Create Account"
    top_icon = ft.Icons.ADMIN_PANEL_SETTINGS_ROUNDED if is_initial_setup else ft.Icons.PERSON_ADD_ROUNDED

    card_items: list[ft.Control] = [
        ft.Row([
            ft.Container(
                content=ft.Icon(top_icon, color="#FFFFFF", size=20),
                bgcolor="#0F172A",
                border_radius=10,
                padding=8,
            )
        ]),
        ft.Text(card_title, size=22, weight=ft.FontWeight.BOLD, color="#0F172A"),
        ft.Text(card_subtitle, size=12, color="#64748B"),
        error_msg,
        success_msg,
        ft.Container(height=2),
        ft.Column([
            ft.Text("Full Name", size=12, weight=ft.FontWeight.W_600, color="#0F172A"),
            fullname_field,
        ], spacing=3, tight=True),
        ft.Column([
            ft.Text("Username", size=12, weight=ft.FontWeight.W_600, color="#0F172A"),
            username_field,
        ], spacing=3, tight=True),
        ft.Column([
            ft.Text("Email", size=12, weight=ft.FontWeight.W_600, color="#0F172A"),
            email_field,
        ], spacing=3, tight=True),
        ft.Column([
            ft.Text("Password", size=12, weight=ft.FontWeight.W_600, color="#0F172A"),
            password_field,
        ], spacing=3, tight=True),
        ft.Column([
            ft.Text("Confirm Password", size=12, weight=ft.FontWeight.W_600, color="#0F172A"),
            confirm_pw_field,
        ], spacing=3, tight=True),
        ft.Container(height=4),
        ft.ElevatedButton(
            content=ft.Row([
                ft.Icon(top_icon, color="#FFFFFF", size=16),
                ft.Text(btn_text, size=14, weight=ft.FontWeight.BOLD, color="#FFFFFF"),
            ], alignment=ft.MainAxisAlignment.CENTER, spacing=6),
            style=ft.ButtonStyle(
                bgcolor="#DC2626",
                shape=ft.RoundedRectangleBorder(radius=10),
                padding=ft.Padding.symmetric(vertical=14),
            ),
            on_click=on_register,
            width=340,
        ),
    ]

    if not is_initial_setup:
        card_items.append(
            ft.Container(
                content=ft.TextButton(
                    "Already have an account? Sign In",
                    on_click=go_to_login,
                    style=ft.ButtonStyle(color="#64748B"),
                ),
                alignment=ft.Alignment(0, 0),
                padding=ft.Padding.only(top=2),
            )
        )

    register_card = ft.Container(
        content=ft.Column(card_items, spacing=6, tight=True),
        width=380,
        bgcolor="#FFFFFF",
        padding=28,
        border_radius=20,
        border=ft.Border.all(1, "#E2E8F0"),
        shadow=ft.BoxShadow(spread_radius=1, blur_radius=24, color="#0F172A0D"),
    )

    right_col = ft.Container(
        content=register_card,
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
