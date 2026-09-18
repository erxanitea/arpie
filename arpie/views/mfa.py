import flet as ft
from ..templates.theme import LOGO_PATH


def render_mfa_challenge_screen(app) -> ft.Container:
    error_msg = ft.Text("", size=11, color="#DC2626", visible=False, weight=ft.FontWeight.W_600)
    recovery_mode = [False]

    title_text = ft.Text("Two-Factor Authentication", size=22, weight=ft.FontWeight.BOLD, color="#0F172A")
    subtitle_text = ft.Text(
        "Enter the 6-digit code from your authenticator app (Google Authenticator, Authy, etc.).",
        size=12, color="#64748B", text_align=ft.TextAlign.CENTER,
    )

    code_field = ft.TextField(
        label="Authentication Code",
        hint_text="000000",
        prefix_icon=ft.Icons.PASSWORD_ROUNDED,
        max_length=6,
        keyboard_type=ft.KeyboardType.NUMBER,
        text_align=ft.TextAlign.CENTER,
        border_radius=8,
        border_color="#CBD5E1",
        dense=True,
    )

    verify_btn_text = ft.Text("Verify & Sign In", size=14, weight=ft.FontWeight.BOLD, color="#FFFFFF")

    mode_switch_btn = ft.OutlinedButton(
        content=ft.Row([
            ft.Icon(ft.Icons.KEY_ROUNDED, size=16, color="#475569"),
            ft.Text("Use an emergency recovery code", size=12, weight=ft.FontWeight.W_600, color="#475569"),
        ], alignment=ft.MainAxisAlignment.CENTER, spacing=6),
        style=ft.ButtonStyle(
            shape=ft.RoundedRectangleBorder(radius=8),
            side=ft.BorderSide(1, "#CBD5E1"),
            padding=12,
        ),
        width=320,
    )

    def toggle_mode(e):
        recovery_mode[0] = not recovery_mode[0]
        error_msg.visible = False
        code_field.value = ""
        if recovery_mode[0]:
            title_text.value = "Emergency Recovery Code"
            subtitle_text.value = "Enter one of your 8-character recovery codes. Each code can only be used once."
            code_field.label = "Recovery Code"
            code_field.hint_text = "e.g. a1b2-c3d4"
            code_field.prefix_icon = ft.Icons.VPN_KEY_ROUNDED
            code_field.max_length = 12
            code_field.keyboard_type = ft.KeyboardType.TEXT
            verify_btn_text.value = "Verify Recovery Code"
            mode_switch_btn.content = ft.Row([
                ft.Icon(ft.Icons.SMARTPHONE_ROUNDED, size=16, color="#475569"),
                ft.Text("Use authenticator app code", size=12, weight=ft.FontWeight.W_600, color="#475569"),
            ], alignment=ft.MainAxisAlignment.CENTER, spacing=6)
        else:
            title_text.value = "Two-Factor Authentication"
            subtitle_text.value = "Enter the 6-digit code from your authenticator app (Google Authenticator, Authy, etc.)."
            code_field.label = "Authentication Code"
            code_field.hint_text = "000000"
            code_field.prefix_icon = ft.Icons.PASSWORD_ROUNDED
            code_field.max_length = 6
            code_field.keyboard_type = ft.KeyboardType.NUMBER
            verify_btn_text.value = "Verify & Sign In"
            mode_switch_btn.content = ft.Row([
                ft.Icon(ft.Icons.KEY_ROUNDED, size=16, color="#475569"),
                ft.Text("Use an emergency recovery code", size=12, weight=ft.FontWeight.W_600, color="#475569"),
            ], alignment=ft.MainAxisAlignment.CENTER, spacing=6)
        app.page.update()

    mode_switch_btn.on_click = toggle_mode

    def on_verify(e):
        val = (code_field.value or "").strip()
        if not val:
            error_msg.value = "Please enter a code."
            error_msg.visible = True
            app.page.update()
            return
        ok, msg = app.verify_mfa_login(val)
        if not ok:
            error_msg.value = msg
            error_msg.visible = True
            code_field.value = ""
            app.page.update()

    def on_cancel(e):
        app.cancel_mfa_login()

    code_field.on_submit = on_verify

    or_divider = ft.Row([
        ft.Container(expand=True, height=1, bgcolor="#E2E8F0"),
        ft.Text("OR", size=11, weight=ft.FontWeight.BOLD, color="#94A3B8"),
        ft.Container(expand=True, height=1, bgcolor="#E2E8F0"),
    ], spacing=10, width=320)

    card = ft.Container(
        content=ft.Column([
            ft.Container(
                content=ft.Image(src=LOGO_PATH, width=44, height=44, fit=ft.BoxFit.CONTAIN),
                alignment=ft.Alignment(0, 0),
            ),
            title_text,
            subtitle_text,
            ft.Container(height=4),
            error_msg,
            code_field,
            ft.Container(height=2),
            ft.ElevatedButton(
                content=ft.Row([
                    ft.Icon(ft.Icons.VERIFIED_USER_ROUNDED, color="#FFFFFF", size=16),
                    verify_btn_text,
                ], alignment=ft.MainAxisAlignment.CENTER, spacing=6),
                style=ft.ButtonStyle(bgcolor="#0F172A", shape=ft.RoundedRectangleBorder(radius=8), padding=14),
                on_click=on_verify,
                width=320,
            ),
            or_divider,
            mode_switch_btn,
            ft.TextButton(
                "← Cancel and return to login",
                on_click=on_cancel,
                style=ft.ButtonStyle(color="#64748B"),
            ),
        ], spacing=10, horizontal_alignment=ft.CrossAxisAlignment.CENTER, tight=True),
        width=420,
        bgcolor="#FFFFFF",
        padding=32,
        border_radius=16,
        border=ft.Border.all(1, "#E2E8F0"),
    )

    return ft.Container(
        content=ft.Column([card], alignment=ft.MainAxisAlignment.CENTER,
                          horizontal_alignment=ft.CrossAxisAlignment.CENTER, expand=True),
        alignment=ft.Alignment(0, 0),
        expand=True,
        bgcolor="#FAFAFC",
        padding=30,
    )
