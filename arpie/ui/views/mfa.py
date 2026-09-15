import flet as ft
from ..theme import LOGO_PATH


def render_mfa_challenge_screen(app) -> ft.Container:
    """Second-factor prompt shown after a correct password when the account has
    TOTP 2FA enabled."""
    error_msg = ft.Text("", size=11, color="#DC2626", visible=False, weight=ft.FontWeight.W_600)

    code_field = ft.TextField(
        hint_text="6-digit code",
        prefix_icon=ft.Icons.PASSWORD_ROUNDED,
        max_length=6,
        keyboard_type=ft.KeyboardType.NUMBER,
        text_align=ft.TextAlign.CENTER,
        border_radius=8,
        border_color="#E2E8F0",
    )

    def on_verify(e):
        ok, msg = app.verify_mfa_login((code_field.value or "").strip())
        if not ok:
            error_msg.value = msg
            error_msg.visible = True
            code_field.value = ""
            app.page.update()

    def on_cancel(e):
        app.cancel_mfa_login()

    code_field.on_submit = on_verify

    who = app._pending_operator.get("username", "") if app._pending_operator else ""

    card = ft.Container(
        content=ft.Column([
            ft.Container(
                content=ft.Image(src=LOGO_PATH, width=40, height=40, fit=ft.BoxFit.CONTAIN),
                alignment=ft.Alignment(0, 0),
            ),
            ft.Text("Two-Factor Authentication", size=22, weight=ft.FontWeight.BOLD, color="#0F172A"),
            ft.Text(f"Enter the 6-digit code from your authenticator app for {who}.",
                    size=12, color="#64748B", text_align=ft.TextAlign.CENTER),
            ft.Container(height=8),
            error_msg,
            code_field,
            ft.ElevatedButton(
                content=ft.Row([
                    ft.Icon(ft.Icons.VERIFIED_USER_ROUNDED, color="#FFFFFF", size=16),
                    ft.Text("Verify & Sign In", size=14, weight=ft.FontWeight.BOLD, color="#FFFFFF"),
                ], alignment=ft.MainAxisAlignment.CENTER, spacing=6),
                style=ft.ButtonStyle(bgcolor="#DC2626", shape=ft.RoundedRectangleBorder(radius=8), padding=14),
                on_click=on_verify,
                width=320,
            ),
            ft.TextButton("Back to login", on_click=on_cancel),
        ], spacing=10, horizontal_alignment=ft.CrossAxisAlignment.CENTER, tight=True),
        width=400,
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
