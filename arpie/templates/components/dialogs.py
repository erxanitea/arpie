import flet as ft


def show_evidence_dialog(app, a_type: str, sev: str, src: str, desc: str):
    sev_color = "#DC2626" if sev.upper() in ["HIGH", "CRITICAL"] else ("#D97706" if sev.upper() == "MEDIUM" else "#10B981")
    dlg = ft.AlertDialog(
        title=ft.Row([
            ft.Icon(ft.Icons.POLICY_ROUNDED, size=20, color="#0F172A"),
            ft.Text(f"Incident Investigation: {a_type}", size=16, weight=ft.FontWeight.BOLD, color="#0F172A"),
        ], spacing=8),
        content=ft.Container(
            content=ft.Column([
                ft.Row([
                    ft.Text("Severity Level:", size=12, weight=ft.FontWeight.BOLD, color="#64748B"),
                    ft.Container(
                        content=ft.Text(sev.upper(), size=11, weight=ft.FontWeight.BOLD, color="#FFFFFF"),
                        bgcolor=sev_color, border_radius=6, padding=ft.Padding.symmetric(horizontal=8, vertical=2),
                    ),
                    ft.Container(width=10),
                    ft.Text("Source Address:", size=12, weight=ft.FontWeight.BOLD, color="#64748B"),
                    ft.Text(src, size=12, weight=ft.FontWeight.BOLD, color="#0F172A", font_family="monospace"),
                ], spacing=6),
                ft.Divider(color="#E2E8F0", height=8),
                ft.Text("Recorded Packet Evidence:", size=12, weight=ft.FontWeight.BOLD, color="#475569"),
                ft.Container(
                    content=ft.Text(desc, size=12, color="#334155", selectable=True),
                    bgcolor="#F8FAFC", border=ft.Border.all(1, "#E2E8F0"), border_radius=6, padding=12,
                    expand=True,
                ),
            ], spacing=6),
            width=460, height=220,
        ),
        actions=[
            ft.TextButton("Close", on_click=lambda e: app.close_dialog(dlg), style=ft.ButtonStyle(color="#64748B")),
            ft.ElevatedButton(
                "Block & Isolate Host",
                icon=ft.Icons.BLOCK_ROUNDED,
                style=ft.ButtonStyle(bgcolor="#DC2626", color="#FFFFFF"),
                on_click=lambda e: app.block_ip(src, dlg),
            ),
        ],
    )
    app.open_dialog(dlg)


def show_seal_dialog(app):
    dlg = ft.AlertDialog(
        title=ft.Row([
            ft.Icon(ft.Icons.SHIELD_ROUNDED, size=22, color="#DC2626"),
            ft.Text("Activate Emergency Seal Mode?", size=16, weight=ft.FontWeight.BOLD, color="#0F172A"),
        ], spacing=8),
        content=ft.Container(
            content=ft.Column([
                ft.Container(
                    content=ft.Column([
                        ft.Row([
                            ft.Icon(ft.Icons.WARNING_AMBER_ROUNDED, size=16, color="#DC2626"),
                            ft.Text("Active Network Containment", size=12, weight=ft.FontWeight.BOLD, color="#DC2626"),
                        ], spacing=6),
                        ft.Text("This will immediately drop hostile network traffic and isolate untrusted connections using local firewall rules.", size=11, color="#64748B"),
                    ], spacing=4),
                    bgcolor="#FEE2E2", border=ft.Border.all(1, "#FECACA"), border_radius=8, padding=12,
                ),
            ], spacing=8),
            width=380,
            height=112,
        ),
        actions=[
            ft.TextButton("Cancel", on_click=lambda e: app.close_dialog(dlg), style=ft.ButtonStyle(color="#64748B")),
            ft.ElevatedButton(
                "Confirm & Seal Network",
                icon=ft.Icons.LOCK_ROUNDED,
                style=ft.ButtonStyle(bgcolor="#DC2626", color="#FFFFFF"),
                on_click=lambda e: app.activate_seal(dlg),
            ),
        ],
    )
    app.open_dialog(dlg)


def show_mfa_setup_dialog(app, on_success=None):
    from ...middleware.mfa import generate_secret, provisioning_uri, generate_qr_base64, generate_recovery_codes, verify as mfa_verify

    secret = generate_secret()
    account = app.operator_email or app.operator_username
    uri = provisioning_uri(secret, account)
    qr_src = generate_qr_base64(uri)
    recovery_codes = generate_recovery_codes(8)

    verify_field = ft.TextField(
        hint_text="Enter 6-digit code from your app",
        prefix_icon=ft.Icons.PASSWORD_ROUNDED,
        max_length=6,
        keyboard_type=ft.KeyboardType.NUMBER,
        text_align=ft.TextAlign.CENTER,
        border_radius=8,
        border_color="#E2E8F0",
        width=260,
    )
    verify_error = ft.Text("", size=11, color="#DC2626", visible=False, weight=ft.FontWeight.W_600)

    step_container = ft.Column([], spacing=12, horizontal_alignment=ft.CrossAxisAlignment.CENTER, scroll=ft.ScrollMode.AUTO)

    def _build_step_header(active_step: int) -> ft.Row:
        steps = ["1. Scan QR", "2. Verify", "3. Backup Codes"]
        chips: list[ft.Control] = []
        for idx, label in enumerate(steps, start=1):
            is_active = (idx == active_step)
            is_done = (idx < active_step)
            bg = "#0F172A" if is_active else ("#E2E8F0" if is_done else "#F1F5F9")
            fg = "#FFFFFF" if is_active else ("#0F172A" if is_done else "#94A3B8")
            chips.append(
                ft.Container(
                    content=ft.Text(f"✓ {label}" if is_done else label, size=11, weight=ft.FontWeight.BOLD, color=fg),
                    bgcolor=bg, border_radius=12, padding=ft.Padding.symmetric(horizontal=10, vertical=4),
                )
            )
        return ft.Row(chips, alignment=ft.MainAxisAlignment.CENTER, spacing=6)

    def _build_step_scan():
        qr_controls: list[ft.Control] = []
        if qr_src:
            qr_controls.append(
                ft.Container(
                    content=ft.Image(src=qr_src, width=190, height=190, fit=ft.BoxFit.CONTAIN),
                    bgcolor="#FFFFFF", border=ft.Border.all(1, "#E2E8F0"), border_radius=8, padding=6,
                )
            )
        else:
            qr_controls.append(ft.Text("QR generator unavailable. Use manual secret below.", size=12, color="#D97706"))

        formatted_secret = " ".join([secret[i:i+4] for i in range(0, len(secret), 4)])

        return [
            _build_step_header(1),
            ft.Container(height=4),
            ft.Text("Step 1: Scan with Authenticator App", size=16, weight=ft.FontWeight.BOLD, color="#0F172A"),
            ft.Text("Open Google Authenticator, Authy, or Microsoft Authenticator and scan this QR code:", size=12, color="#64748B", text_align=ft.TextAlign.CENTER),
            ft.Container(height=2),
            *qr_controls,
            ft.Container(height=4),
            ft.Text("Manual Entry Key (if unable to scan):", size=11, weight=ft.FontWeight.BOLD, color="#475569"),
            ft.Container(
                content=ft.Text(formatted_secret, size=13, weight=ft.FontWeight.BOLD, color="#0F172A", selectable=True, font_family="monospace"),
                bgcolor="#F8FAFC", border=ft.Border.all(1, "#E2E8F0"), border_radius=8, padding=10,
            ),
            ft.Container(height=4),
            ft.ElevatedButton(
                "Continue to Verification →",
                icon=ft.Icons.ARROW_FORWARD_ROUNDED,
                on_click=lambda e: _go_to_verify(),
                style=ft.ButtonStyle(bgcolor="#0F172A", color="#FFFFFF", padding=14),
                width=280,
            ),
        ]

    def _go_to_verify():
        step_container.controls = _build_step_verify()
        app.page.update()

    def _build_step_verify():
        return [
            _build_step_header(2),
            ft.Container(height=4),
            ft.Text("Step 2: Verify Setup", size=16, weight=ft.FontWeight.BOLD, color="#0F172A"),
            ft.Text("Enter the 6-digit verification code currently shown in your authenticator app to confirm setup.", size=12, color="#64748B", text_align=ft.TextAlign.CENTER),
            ft.Container(height=6),
            verify_error,
            ft.TextField(
                label="6-Digit Verification Code",
                hint_text="000000",
                prefix_icon=ft.Icons.PASSWORD_ROUNDED,
                max_length=6,
                keyboard_type=ft.KeyboardType.NUMBER,
                text_align=ft.TextAlign.CENTER,
                border_radius=8,
                border_color="#CBD5E1",
                dense=True,
                width=280,
                value=verify_field.value,
                on_change=lambda e: setattr(verify_field, "value", e.control.value),
                on_submit=lambda e: _on_verify_activate(),
            ),
            ft.Container(height=4),
            ft.ElevatedButton(
                "Confirm & Activate 2FA",
                icon=ft.Icons.CHECK_CIRCLE_ROUNDED,
                on_click=lambda e: _on_verify_activate(),
                style=ft.ButtonStyle(bgcolor="#10B981", color="#FFFFFF", padding=14),
                width=280,
            ),
            ft.TextButton("← Back to QR Code", on_click=lambda e: _go_to_scan(), style=ft.ButtonStyle(color="#64748B")),
        ]

    def _go_to_scan():
        verify_error.visible = False
        verify_field.value = ""
        step_container.controls = _build_step_scan()
        app.page.update()

    def _on_verify_activate():
        entered = (verify_field.value or "").strip()
        if not entered or len(entered) != 6 or not entered.isdigit():
            verify_error.value = "Please enter a valid 6-digit code."
            verify_error.visible = True
            app.page.update()
            return

        if not mfa_verify(secret, entered):
            verify_error.value = "Incorrect code. Check your authenticator and try again."
            verify_error.visible = True
            verify_field.value = ""
            app.page.update()
            return

        app.db.set_totp_secret(app.operator_username, secret)
        app.db.set_recovery_codes(app.operator_username, recovery_codes)

        step_container.controls = _build_step_recovery()
        app.page.update()

    def _build_step_recovery():
        code_rows: list[ft.Control] = []
        for i in range(0, len(recovery_codes), 2):
            row_items: list[ft.Control] = [ft.Text(recovery_codes[i], size=13, weight=ft.FontWeight.BOLD, color="#0F172A", font_family="monospace", expand=1)]
            if i + 1 < len(recovery_codes):
                row_items.append(ft.Text(recovery_codes[i + 1], size=13, weight=ft.FontWeight.BOLD, color="#0F172A", font_family="monospace", expand=1))
            code_rows.append(ft.Row(row_items, spacing=12))

        return [
            _build_step_header(3),
            ft.Container(height=4),
            ft.Text("2FA Successfully Enabled!", size=16, weight=ft.FontWeight.BOLD, color="#10B981"),
            ft.Container(
                content=ft.Column([
                    ft.Row([
                        ft.Icon(ft.Icons.WARNING_AMBER_ROUNDED, size=16, color="#D97706"),
                        ft.Text("Save your recovery codes", size=13, weight=ft.FontWeight.BOLD, color="#D97706"),
                    ], spacing=6),
                    ft.Text("If you lose access to your authenticator app, these emergency codes are the only way to log in. Each code can only be used once.", size=11, color="#64748B"),
                ], spacing=4),
                bgcolor="#FEF3C7", border=ft.Border.all(1, "#FDE68A"), border_radius=8, padding=12,
            ),
            ft.Container(
                content=ft.Column(code_rows, spacing=6),
                bgcolor="#F8FAFC", border=ft.Border.all(1, "#E2E8F0"), border_radius=8, padding=14,
            ),
            ft.Container(height=8),
            ft.ElevatedButton(
                "Done",
                icon=ft.Icons.CHECK_ROUNDED,
                on_click=lambda e: _finish_setup(),
                style=ft.ButtonStyle(bgcolor="#0F172A", color="#FFFFFF", padding=14),
                width=260,
            ),
        ]

    def _finish_setup():
        app.page.pop_dialog()
        if on_success:
            on_success()
        else:
            app.update_view_content()
            app.page.update()

    step_container.controls = _build_step_scan()

    dlg = ft.AlertDialog(
        modal=True,
        title=ft.Row([
            ft.Icon(ft.Icons.SECURITY_ROUNDED, size=20, color="#0F172A"),
            ft.Text("Two-Factor Authentication Setup", size=16, weight=ft.FontWeight.BOLD, color="#0F172A"),
        ], spacing=8),
        content=ft.Container(content=step_container, width=380, height=480),
        actions=[
            ft.TextButton("Close", on_click=lambda e: app.page.pop_dialog(), style=ft.ButtonStyle(color="#64748B")),
        ],
    )
    app.page.show_dialog(dlg)


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
            ft.ElevatedButton(
                "Disable 2FA",
                icon=ft.Icons.LOCK_OPEN_ROUNDED,
                on_click=_on_confirm_disable,
                style=ft.ButtonStyle(bgcolor="#DC2626", color="#FFFFFF", padding=12),
            ),
        ],
    )
    app.page.show_dialog(dlg)




