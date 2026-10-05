import flet as ft
from arpie.middleware import can_manage_system_settings
from arpie.forms.auth import validate_password
from arpie.security import secrets_store
from arpie.middleware.mfa import provisioning_uri
from arpie.views.profile import _make_param_field


def render_settings_view(app) -> ft.Column:
    is_evaluator = can_manage_system_settings(app)

    # --- Operator Credentials Fields ---
    op_user_field = ft.TextField(
        label="Display Name",
        value=app.user_name or app.operator_username,
        border_radius=8,
        dense=True,
        prefix_icon=ft.Icons.PERSON_OUTLINE_ROUNDED,
    )
    current_pw_field = ft.TextField(
        label="Current Password",
        password=True,
        can_reveal_password=True,
        border_radius=8,
        dense=True,
        prefix_icon=ft.Icons.LOCK_OUTLINE_ROUNDED,
        hint_text="Enter current password to verify",
    )
    new_pw_field = ft.TextField(
        label="New Password",
        password=True,
        can_reveal_password=True,
        border_radius=8,
        dense=True,
        prefix_icon=ft.Icons.LOCK_OUTLINE_ROUNDED,
        hint_text="Leave blank to keep unchanged",
    )
    op_status_text = ft.Text("", size=12, weight=ft.FontWeight.W_600, visible=False)

    def on_update_credentials(e):
        cur_pw = current_pw_field.value or ""
        new_pw = new_pw_field.value or ""
        new_display_name = (op_user_field.value or "").strip()

        if not cur_pw:
            op_status_text.value = "Current password is required to verify identity."
            op_status_text.color = "#DC2626"
            op_status_text.visible = True
            app.page.update()
            return

        verified = app.db.authenticate_operator(app.operator_username, cur_pw)
        if not verified:
            op_status_text.value = "Incorrect current password."
            op_status_text.color = "#DC2626"
            op_status_text.visible = True
            app.page.update()
            return

        if new_pw:
            pw_ok, pw_err = validate_password(new_pw, username=app.operator_username, email=app.operator_email)
            if not pw_ok:
                op_status_text.value = pw_err
                op_status_text.color = "#DC2626"
                op_status_text.visible = True
                app.page.update()
                return
            app.db.update_operator_password(app.operator_username, new_pw)

        if new_display_name and new_display_name != app.user_name:
            app.db.update_operator_display_name(app.operator_username, new_display_name)
            app.user_name = new_display_name

        op_status_text.value = "Credentials successfully updated!"
        op_status_text.color = "#10B981"
        op_status_text.visible = True
        current_pw_field.value = ""
        new_pw_field.value = ""
        app.update_view_content()
        app.page.update()

    role_badge_bg = "#F5F3FF" if is_evaluator else "#ECFDF5"
    role_badge_color = "#8B5CF6" if is_evaluator else "#10B981"

    operator_card = ft.Container(
        content=ft.Column([
            ft.Row([
                ft.Row([
                    ft.Icon(ft.Icons.BADGE_ROUNDED, color="#0F172A", size=22),
                    ft.Column([
                        ft.Text("Account & Security Profile", size=16, weight=ft.FontWeight.BOLD, color="#0F172A"),
                        ft.Text(f"Logged in as {app.user_name or app.operator_username or 'Operator'}", size=12, color="#64748B"),
                    ], spacing=1),
                ], spacing=10),
                ft.Container(
                    content=ft.Row([
                        ft.Icon(ft.Icons.SECURITY_ROUNDED, size=12, color=role_badge_color),
                        ft.Text(app.user_role, size=11, weight=ft.FontWeight.BOLD, color=role_badge_color),
                    ], spacing=4),
                    bgcolor=role_badge_bg, border_radius=6, padding=ft.Padding.symmetric(horizontal=8, vertical=4),
                )
            ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
            ft.Divider(color="#E2E8F0", height=12),
            ft.Row([
                ft.Column([
                    ft.Text("Account Role:", size=11, color="#64748B", weight=ft.FontWeight.W_500),
                    ft.Text(app.user_role, size=13, weight=ft.FontWeight.BOLD, color="#0F172A"),
                ], spacing=2),
                ft.Column([
                    ft.Text("Email:", size=11, color="#64748B", weight=ft.FontWeight.W_500),
                    ft.Text(app.operator_email or "Not configured", size=13, weight=ft.FontWeight.BOLD, color="#0F172A"),
                ], spacing=2),
                ft.Column([
                    ft.Text("Last Login:", size=11, color="#64748B", weight=ft.FontWeight.W_500),
                    ft.Text(app.operator_last_login or "Active Session", size=13, weight=ft.FontWeight.BOLD, color="#0F172A"),
                ], spacing=2),
            ], spacing=30),
            ft.Divider(color="#F1F5F9", height=8),
            op_user_field,
            ft.Row([
                ft.Container(content=current_pw_field, expand=1),
                ft.Container(content=new_pw_field, expand=1),
            ], spacing=12),
            op_status_text,
            ft.Button(
                "Update Credentials",
                icon=ft.Icons.CHECK_ROUNDED,
                on_click=on_update_credentials,
                style=ft.ButtonStyle(bgcolor="#0F172A", color="#FFFFFF", padding=12),
            ),
        ], spacing=12),
        bgcolor="#FFFFFF", border=ft.Border.all(1, "#E2E8F0"), border_radius=12, padding=20,
    )

    cards: list[ft.Control] = [operator_card]

    has_totp = app.db.get_totp_secret(app.operator_username) is not None
    totp_status = ft.Text(
        "✅ Enabled" if has_totp else "Disabled",
        size=12, weight=ft.FontWeight.BOLD,
        color="#10B981" if has_totp else "#94A3B8",
    )

    def _refresh_mfa():
        new_has_totp = app.db.get_totp_secret(app.operator_username) is not None
        totp_status.value = "✅ Enabled" if new_has_totp else "Disabled"
        totp_status.color = "#10B981" if new_has_totp else "#94A3B8"
        app.update_view_content()
        app.page.update()

    def _on_setup_click(e):
        from arpie.views.dialogs import show_mfa_setup_dialog
        show_mfa_setup_dialog(app, on_success=_refresh_mfa)

    def _on_disable_click(e):
        from arpie.views.dialogs import show_mfa_disable_dialog
        show_mfa_disable_dialog(app, on_success=_refresh_mfa)

    mfa_card = ft.Container(
        content=ft.Column([
            ft.Row([
                ft.Icon(ft.Icons.VERIFIED_USER_ROUNDED, color="#0F172A", size=22),
                ft.Column([
                    ft.Text("Two-Factor Authentication (TOTP)", size=16, weight=ft.FontWeight.BOLD, color="#0F172A"),
                    ft.Text("Secure your account with an authenticator app (Google Authenticator, Authy, etc.).", size=12, color="#64748B"),
                ], spacing=1),
            ], spacing=10),
            ft.Divider(color="#E2E8F0", height=12),
            ft.Row([
                ft.Text("Status:", size=13, color="#475569"),
                totp_status,
            ], spacing=8),
            ft.Button(
                "Disable 2FA" if has_totp else "Set Up 2FA",
                icon=ft.Icons.LOCK_OPEN_ROUNDED if has_totp else ft.Icons.LOCK_ROUNDED,
                on_click=_on_disable_click if has_totp else _on_setup_click,
                style=ft.ButtonStyle(
                    bgcolor="#DC2626" if has_totp else "#0F172A",
                    color="#FFFFFF", padding=12,
                ),
            ),
        ], spacing=12),
        bgcolor="#FFFFFF", border=ft.Border.all(1, "#E2E8F0"), border_radius=12, padding=20,
    )
    cards.append(mfa_card)

    if is_evaluator:
        stored_abuse = secrets_store.get_secret("ABUSEIPDB_API_KEY") or ""
        stored_ipinfo = secrets_store.get_secret("IPINFO_API_KEY") or ""
        abuse_field = ft.TextField(
            label="AbuseIPDB API Key", password=True, can_reveal_password=True,
            value=stored_abuse, border_radius=8, dense=True,
            hint_text="Paste your AbuseIPDB key",
        )
        ipinfo_field = ft.TextField(
            label="IPInfo Token", password=True, can_reveal_password=True,
            value=stored_ipinfo, border_radius=8, dense=True,
            hint_text="Paste your IPInfo token",
        )

        api_status = ft.Text("", size=12, weight=ft.FontWeight.W_600, visible=False)

        def save_conf(e):
            abuse_val = (abuse_field.value or "").strip()
            ipinfo_val = (ipinfo_field.value or "").strip()
            saved_any = False
            if abuse_val and secrets_store.set_secret("ABUSEIPDB_API_KEY", abuse_val):
                saved_any = True
                import os
                os.environ["ABUSEIPDB_API_KEY"] = abuse_val
            if ipinfo_val and secrets_store.set_secret("IPINFO_API_KEY", ipinfo_val):
                saved_any = True
                import os
                os.environ["IPINFO_API_KEY"] = ipinfo_val

            for key, value in app.thresholds.items():
                app.db.set_config(f"detection_threshold_{key}", str(value))
            for key, enabled in app.detection_rules.items():
                app.db.set_config(f"detection_rule_{key}", "1" if enabled else "0")

            if saved_any and secrets_store.available():
                api_status.value = "API keys saved to OS keyring."
                api_status.color = "#10B981"
            else:
                api_status.value = "Keys applied for this session (keyring unavailable — set env vars for persistence)."
                api_status.color = "#F59E0B"
            api_status.visible = True
            app.status_toast = "Detection configuration saved."
            app.update_view_content()
            app.page.update()

        config_card = ft.Container(
            content=ft.Column([
                ft.Row([
                    ft.Icon(ft.Icons.TUNE_ROUNDED, color="#0F172A", size=22),
                    ft.Column([
                        ft.Text("Detection Thresholds & Threat Intel Feeds (Evaluator Tools)", size=16, weight=ft.FontWeight.BOLD, color="#0F172A"),
                        ft.Text("Configure heuristic sensitivity and external threat intelligence APIs.", size=12, color="#64748B"),
                    ], spacing=1),
                ], spacing=10),
                ft.Divider(color="#E2E8F0", height=12),
                ft.Row([
                    ft.Container(content=abuse_field, expand=1),
                    ft.Container(content=ipinfo_field, expand=1),
                ], spacing=12),
                api_status,
                ft.Divider(color="#F1F5F9", height=8),
                ft.Text("Detection Rule Thresholds", size=14, weight=ft.FontWeight.BOLD, color="#0F172A"),
                _make_param_field(app, "Traffic Anomaly Threshold", app.thresholds.get("traffic", "100"), "packets/sec", "traffic"),
                _make_param_field(app, "Port Scan Trigger Threshold", app.thresholds.get("port", "15"), "ports / 10 sec", "port"),
                _make_param_field(app, "ARP Identity Window", app.thresholds.get("arp_window", "5"), "minutes", "arp_window"),
                _make_param_field(app, "Gateway Change Window", app.thresholds.get("gw_window", "10"), "minutes", "gw_window"),
                ft.Container(height=4),
                ft.Button("Save Detection Settings", icon=ft.Icons.SAVE_ROUNDED, on_click=save_conf, style=ft.ButtonStyle(bgcolor="#DC2626", color="#FFFFFF", padding=12)),
            ], spacing=12),
            bgcolor="#FFFFFF", border=ft.Border.all(1, "#E2E8F0"), border_radius=12, padding=20,
        )
        cards.append(config_card)
    else:
        about_card = ft.Container(
            content=ft.Column([
                ft.Row([
                    ft.Icon(ft.Icons.INFO_OUTLINE_ROUNDED, color="#0F172A", size=22),
                    ft.Column([
                        ft.Text("Automatic Endpoint Protection", size=16, weight=ft.FontWeight.BOLD, color="#0F172A"),
                        ft.Text("Context-aware heuristic sensitivity managed automatically.", size=12, color="#64748B"),
                    ], spacing=1),
                ], spacing=10),
                ft.Divider(color="#E2E8F0", height=12),
                ft.Text(
                    "Arpie automatically calibrates its detection rules based on your active network context "
                    "(e.g., Public Wi-Fi vs. Trusted Home Network). To change sensitivity, adjust your profile "
                    "when initiating a new session.",
                    size=13, color="#475569",
                ),
            ], spacing=12),
            bgcolor="#FFFFFF", border=ft.Border.all(1, "#E2E8F0"), border_radius=12, padding=20,
        )
        cards.append(about_card)

    return ft.Column(cards, spacing=14, scroll=ft.ScrollMode.AUTO)


