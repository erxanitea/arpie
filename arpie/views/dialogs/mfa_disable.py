"""Password-confirmed dialog for turning TOTP back off."""

import flet as ft


def show_mfa_disable_dialog(app, on_success=None):
    pw_field = ft.TextField(
        label="Confirm Password",
        hint_text="Enter your password",
        password=True,
        can_reveal_password=True,
        border_radius=8,
        border_color="#CBD5E1",
        dense=True,
        prefix_icon=ft.Icons.LOCK_OUTLINE_ROUNDED,
        width=340,
    )
    pw_error = ft.Text("", size=11, color="#DC2626", visible=False, weight=ft.FontWeight.W_600)

    def _on_confirm_disable(e):
        pw = (pw_field.value or "").strip()
        if not pw:
            pw_error.value = "Password is required."
            pw_error.visible = True
            app.page.update()
            return
        verified = app.db.authenticate_operator(app.operator_username, pw)
        if not verified:
            pw_error.value = "Incorrect password. Please try again."
            pw_error.visible = True
            pw_field.value = ""
            app.page.update()
            return
        app.disable_totp(app.operator_username)
        app.page.pop_dialog()
        if on_success:
            on_success()
        else:
            app.update_view_content()
            app.page.update()

    dlg = ft.AlertDialog(
        modal=True,
        title=ft.Row([
            ft.Icon(ft.Icons.WARNING_ROUNDED, size=20, color="#DC2626"),
            ft.Text("Disable Two-Factor Authentication", size=16, weight=ft.FontWeight.BOLD, color="#0F172A"),
        ], spacing=8),
        content=ft.Container(
            content=ft.Column([
                ft.Container(
                    content=ft.Column([
                        ft.Row([
                            ft.Icon(ft.Icons.SECURITY_UPDATE_WARNING_ROUNDED, size=16, color="#DC2626"),
                            ft.Text("Decreased Account Security", size=12, weight=ft.FontWeight.BOLD, color="#DC2626"),
                        ], spacing=6),
                        ft.Text("Disabling 2FA removes two-factor protection from your account.", size=11, color="#64748B"),
                    ], spacing=4),
                    bgcolor="#FEE2E2", border=ft.Border.all(1, "#FECACA"), border_radius=8, padding=12,
                ),
                pw_error,
                pw_field,
            ], spacing=12, tight=True),
            width=340,
        ),
        actions=[
            ft.TextButton("Cancel", on_click=lambda e: app.page.pop_dialog(), style=ft.ButtonStyle(color="#64748B")),
            ft.Button(
                "Disable 2FA",
                icon=ft.Icons.LOCK_OPEN_ROUNDED,
                on_click=_on_confirm_disable,
                style=ft.ButtonStyle(bgcolor="#DC2626", color="#FFFFFF", padding=12),
            ),
        ],
    )
    app.page.show_dialog(dlg)
