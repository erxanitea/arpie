import datetime
import time
import flet as ft
from .profile import _make_param_field


def render_settings_view(app) -> ft.Column:
    is_evaluator = (app.user_role == "Evaluator/Administrator")

    # --- Operator Credentials Fields ---
    op_user_field = ft.TextField(
        label="Username",
        value=app.operator_username,
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
        prefix_icon=ft.Icons.KEY_ROUNDED,
        hint_text="Leave blank to keep unchanged",
    )
    op_status_text = ft.Text("", size=12, weight=ft.FontWeight.W_600, visible=False)

    def on_update_credentials(e):
        cur_pw = current_pw_field.value or ""
        new_pw = new_pw_field.value or ""
        new_uname = op_user_field.value or ""

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
            if len(new_pw) < 4:
                op_status_text.value = "New password must be at least 4 characters."
                op_status_text.color = "#DC2626"
                op_status_text.visible = True
                app.page.update()
                return
            app.db.update_operator_password(app.operator_username, new_pw)

        if new_uname and new_uname != app.operator_username:
            app.db.update_operator_display_name(app.operator_username, new_uname)
            app.operator_username = new_uname
            app.user_name = new_uname

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
            ft.ElevatedButton(
                "Update Credentials",
                icon=ft.Icons.CHECK_ROUNDED,
                on_click=on_update_credentials,
                style=ft.ButtonStyle(bgcolor="#0F172A", color="#FFFFFF", padding=12),
            ),
        ], spacing=12),
        bgcolor="#FFFFFF", border=ft.Border.all(1, "#E2E8F0"), border_radius=12, padding=20,
    )

    # --- User Account Information Table Card ---
    operators_list = app.db.list_operators() if hasattr(app.db, "list_operators") else []
    if not operators_list:
        operators_list = [{
            "id": app.operator_id or 1,
            "display_name": app.user_name or "Operator",
            "username": app.operator_username or "admin",
            "email": app.operator_email or "admin@arpie.local",
            "role": app.user_role,
            "created_at": time.time(),
            "last_login_at": time.time(),
        }]

    user_rows = []
    for op in operators_list:
        last_str = datetime.datetime.fromtimestamp(op.get("last_login_at") or time.time()).strftime("%Y-%m-%d %H:%M") if op.get("last_login_at") else "Active"
        role_label = op.get("role", "End User")
        user_rows.append(
            ft.DataRow(cells=[
                ft.DataCell(ft.Text(str(op.get("id")), size=12, color="#64748B")),
                ft.DataCell(ft.Text(op.get("display_name") or op.get("username", "User"), size=12, weight=ft.FontWeight.BOLD, color="#0F172A")),
                ft.DataCell(ft.Text(op.get("username", ""), size=12, color="#0F172A")),
                ft.DataCell(ft.Text(op.get("email", ""), size=12, color="#475569")),
                ft.DataCell(ft.Container(
                    content=ft.Text(role_label, size=10, weight=ft.FontWeight.BOLD, color="#8B5CF6" if "Evaluator" in role_label else "#10B981"),
                    bgcolor="#F5F3FF" if "Evaluator" in role_label else "#ECFDF5",
                    border_radius=4, padding=ft.Padding.symmetric(horizontal=6, vertical=2),
                )),
                ft.DataCell(ft.Container(
                    content=ft.Text("Active", size=10, weight=ft.FontWeight.BOLD, color="#10B981"),
                    bgcolor="#ECFDF5",
                    border_radius=4, padding=ft.Padding.symmetric(horizontal=6, vertical=2),
                )),
                ft.DataCell(ft.Text(last_str, size=12, color="#64748B")),
            ])
        )

    user_table = ft.DataTable(
        columns=[
            ft.DataColumn(label=ft.Text("UserID", size=11, weight=ft.FontWeight.BOLD)),
            ft.DataColumn(label=ft.Text("FullName", size=11, weight=ft.FontWeight.BOLD)),
            ft.DataColumn(label=ft.Text("Username", size=11, weight=ft.FontWeight.BOLD)),
            ft.DataColumn(label=ft.Text("Email", size=11, weight=ft.FontWeight.BOLD)),
            ft.DataColumn(label=ft.Text("Role", size=11, weight=ft.FontWeight.BOLD)),
            ft.DataColumn(label=ft.Text("Status", size=11, weight=ft.FontWeight.BOLD)),
            ft.DataColumn(label=ft.Text("LastLogin", size=11, weight=ft.FontWeight.BOLD)),
        ],
        rows=user_rows,
        heading_row_height=40,
        data_row_min_height=42,
    )

    user_table_card = ft.Container(
        content=ft.Column([
            ft.Row([
                ft.Icon(ft.Icons.PEOPLE_ROUNDED, color="#0F172A", size=22),
                ft.Column([
                    ft.Text("User Account Information", size=16, weight=ft.FontWeight.BOLD, color="#0F172A"),
                    ft.Text("Registered system operators and RBAC role assignments.", size=12, color="#64748B"),
                ], spacing=1),
            ], spacing=10),
            ft.Divider(color="#E2E8F0", height=12),
            ft.Row([user_table], scroll=ft.ScrollMode.AUTO),
        ], spacing=10),
        bgcolor="#FFFFFF", border=ft.Border.all(1, "#E2E8F0"), border_radius=12, padding=20,
    )

    cards: list[ft.Control] = [operator_card, user_table_card]

    if is_evaluator:
        abuse_field = ft.TextField(label="AbuseIPDB API Key", password=True, can_reveal_password=True, value="••••••••••••••••••••••••", border_radius=8, dense=True)
        ipinfo_field = ft.TextField(label="IPInfo Token", password=True, can_reveal_password=True, value="••••••••••••••••••••••••", border_radius=8, dense=True)

        def save_conf(e):
            app.status_toast = "Detection configuration successfully saved to database."
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
                ft.Divider(color="#F1F5F9", height=8),
                ft.Text("Detection Rule Thresholds", size=14, weight=ft.FontWeight.BOLD, color="#0F172A"),
                _make_param_field(app, "Traffic Anomaly Threshold", app.thresholds.get("traffic", "100"), "packets/sec", "traffic"),
                _make_param_field(app, "Port Scan Trigger Threshold", app.thresholds.get("port", "15"), "ports / 10 sec", "port"),
                _make_param_field(app, "ARP Identity Window", app.thresholds.get("arp_window", "5"), "minutes", "arp_window"),
                _make_param_field(app, "Gateway Change Window", app.thresholds.get("gw_window", "10"), "minutes", "gw_window"),
                ft.Container(height=4),
                ft.ElevatedButton("Save Detection Settings", icon=ft.Icons.SAVE_ROUNDED, on_click=save_conf, style=ft.ButtonStyle(bgcolor="#DC2626", color="#FFFFFF", padding=12)),
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
