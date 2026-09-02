import datetime
import time
import flet as ft


def _make_role_filter_chip(app, label: str) -> ft.Container:
    current_filter = getattr(app, "active_user_role_filter", "All")
    is_sel = (current_filter == label)
    return ft.Container(
        content=ft.Text(label, size=12, weight=ft.FontWeight.BOLD if is_sel else ft.FontWeight.W_500, color="#FFFFFF" if is_sel else "#475569"),
        bgcolor="#0F172A" if is_sel else "#FFFFFF",
        border=ft.Border.all(1, "#0F172A" if is_sel else "#E2E8F0"),
        border_radius=20,
        padding=ft.Padding.symmetric(horizontal=14, vertical=6),
        on_click=lambda e, l=label: _set_user_filter(app, l),
    )


def _set_user_filter(app, label: str):
    app.active_user_role_filter = label
    app.update_view_content()
    app.page.update()


def _make_stat_card(icon, label: str, value: str, color: str, bg: str, tooltip_text: str = "") -> ft.Container:
    return ft.Container(
        content=ft.Row([
            ft.Container(
                content=ft.Icon(icon, color=color, size=20),
                bgcolor=bg,
                border_radius=10,
                padding=10,
            ),
            ft.Column([
                ft.Row([
                    ft.Text(label, size=11, weight=ft.FontWeight.W_500, color="#64748B"),
                    ft.Icon(ft.Icons.INFO_OUTLINE_ROUNDED, size=12, color="#94A3B8") if tooltip_text else ft.Container(),
                ], spacing=4),
                ft.Text(value, size=18, weight=ft.FontWeight.BOLD, color="#0F172A"),
            ], spacing=2),
        ], spacing=12),
        bgcolor="#FFFFFF",
        border=ft.Border.all(1, "#E2E8F0"),
        border_radius=12,
        padding=16,
        expand=1,
        tooltip=tooltip_text if tooltip_text else None,
    )


def render_users_view(app) -> ft.Column:
    if app.user_role != "Evaluator/Administrator":
        return ft.Column([
            ft.Container(
                content=ft.Column([
                    ft.Icon(ft.Icons.LOCK_ROUNDED, color="#DC2626", size=48),
                    ft.Text("Administrator Privileges Required", size=18, weight=ft.FontWeight.BOLD, color="#0F172A"),
                    ft.Text("User management and RBAC directory access is restricted to Evaluator / Administrator accounts.", size=13, color="#64748B", text_align=ft.TextAlign.CENTER),
                    ft.Container(height=8),
                    ft.ElevatedButton("Return to Dashboard", icon=ft.Icons.DASHBOARD_ROUNDED, on_click=lambda e: app.nav_to("dashboard"), style=ft.ButtonStyle(bgcolor="#0F172A", color="#FFFFFF", padding=12)),
                ], horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=10),
                bgcolor="#FFFFFF", border=ft.Border.all(1, "#E2E8F0"), border_radius=12, padding=40,
                alignment=ft.Alignment(0, 0),
            )
        ], alignment=ft.MainAxisAlignment.CENTER)

    if not hasattr(app, "active_user_role_filter"):
        app.active_user_role_filter = "All"
    if not hasattr(app, "user_search_query"):
        app.user_search_query = ""

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

    total_count = len(operators_list)
    evaluator_count = sum(1 for o in operators_list if "Evaluator" in str(o.get("role", "")))
    end_user_count = total_count - evaluator_count

    eval_tooltip = (
        "Evaluator / Administrator Privileges:\n"
        "• ✓ Full Promiscuous Packet Sniffing & Live Capture\n"
        "• ✓ Heuristic Rule Sensitivity & Detection Threshold Tuning\n"
        "• ✓ Threat Intelligence API Integrations (AbuseIPDB)\n"
        "• ✓ 1-Click Seal Mode: Host Isolation & Active Blocking\n"
        "• ✓ Automated Forensic Report Generation (HTML, PDF, JSON)\n"
        "• ✓ Operator Accounts & RBAC Access Management"
    )

    user_tooltip = (
        "End User Privileges:\n"
        "• ✓ Real-Time Threat Alerts & Health Status Dashboard\n"
        "• ✓ Network Device Discovery & Gateway MAC Posture\n"
        "• ✓ Context-Aware Automatic Heuristic Calibration\n"
        "• ✓ Deterministic Heuristic Evidence & Proof Inspection\n"
        "• ✗ Restricted from modifying detection rules or API keys"
    )

    stats_row = ft.Row([
        _make_stat_card(
            ft.Icons.GROUP_ROUNDED,
            "Total System Users",
            str(total_count),
            "#0F172A",
            "#F1F5F9",
            "System Operator Directory:\n• Total active operators registered in SQLite database\n• Access control enforced via Arpie RBAC engine",
        ),
        _make_stat_card(
            ft.Icons.ADMIN_PANEL_SETTINGS_ROUNDED,
            "Evaluator / Admins",
            str(evaluator_count),
            "#8B5CF6",
            "#F5F3FF",
            eval_tooltip,
        ),
        _make_stat_card(
            ft.Icons.PERSON_ROUNDED,
            "End Users",
            str(end_user_count),
            "#10B981",
            "#ECFDF5",
            user_tooltip,
        ),
    ], spacing=14)

    filter_row = ft.Row([
        _make_role_filter_chip(app, "All"),
        _make_role_filter_chip(app, "Evaluator/Administrator"),
        _make_role_filter_chip(app, "End User"),
    ], spacing=8)

    def on_user_search(val: str):
        app.user_search_query = val
        app.update_view_content()
        app.page.update()

    search_input = ft.TextField(
        hint_text="Search user accounts by username, email, role or display name...",
        prefix_icon=ft.Icons.SEARCH_ROUNDED,
        dense=True,
        border_radius=8,
        border_color="#E2E8F0",
        expand=True,
        value=app.user_search_query,
        on_change=lambda e: on_user_search(e.control.value),
    )

    user_rows = []
    for op in operators_list:
        uname = str(op.get("username") or "")
        email = str(op.get("email") or "")
        disp = str(op.get("display_name") or uname)
        role_label = str(op.get("role") or "End User")

        if app.active_user_role_filter != "All" and role_label != app.active_user_role_filter:
            continue
        if app.user_search_query and (
            app.user_search_query.lower() not in uname.lower()
            and app.user_search_query.lower() not in email.lower()
            and app.user_search_query.lower() not in disp.lower()
        ):
            continue

        is_eval = ("Evaluator" in role_label)
        initials = (disp[:2] if len(disp) >= 2 else (uname[:2] if len(uname) >= 2 else "OP")).upper()
        avatar_bg = "#8B5CF6" if is_eval else "#10B981"

        created_ts = float(op.get("created_at") or time.time())
        created_str = datetime.datetime.fromtimestamp(created_ts).strftime("%Y-%m-%d")

        last_login_raw = op.get("last_login_at")
        if last_login_raw:
            last_dt = datetime.datetime.fromtimestamp(float(last_login_raw))
            last_date_str = last_dt.strftime("%Y-%m-%d")
            last_time_str = last_dt.strftime("%H:%M:%S")
        else:
            last_date_str = "Active"
            last_time_str = "Session"

        user_rows.append(
            ft.DataRow(cells=[
                ft.DataCell(ft.Text(f"#{op.get('id')}", size=12, weight=ft.FontWeight.BOLD, color="#64748B")),
                ft.DataCell(
                    ft.Row([
                        ft.Container(
                            content=ft.Text(initials, size=11, weight=ft.FontWeight.BOLD, color="#FFFFFF"),
                            bgcolor=avatar_bg,
                            width=30, height=30,
                            border_radius=15,
                            alignment=ft.Alignment(0, 0),
                        ),
                        ft.Column([
                            ft.Text(disp, size=12, weight=ft.FontWeight.BOLD, color="#0F172A"),
                            ft.Text(f"@{uname}", size=10, color="#64748B"),
                        ], spacing=1, alignment=ft.MainAxisAlignment.CENTER),
                    ], spacing=10)
                ),
                ft.DataCell(ft.Text(uname, size=12, color="#0F172A")),
                ft.DataCell(
                    ft.Row([
                        ft.Icon(ft.Icons.ALTERNATE_EMAIL_ROUNDED, size=13, color="#94A3B8"),
                        ft.Text(email, size=12, color="#475569"),
                    ], spacing=4)
                ),
                ft.DataCell(
                    ft.Container(
                        content=ft.Row([
                            ft.Icon(ft.Icons.SECURITY_ROUNDED if is_eval else ft.Icons.PERSON_ROUNDED, size=12, color="#8B5CF6" if is_eval else "#10B981"),
                            ft.Text(role_label, size=10, weight=ft.FontWeight.BOLD, color="#8B5CF6" if is_eval else "#10B981"),
                        ], spacing=4),
                        bgcolor="#F5F3FF" if is_eval else "#ECFDF5",
                        border=ft.Border.all(1, "#DDD6FE" if is_eval else "#A7F3D0"),
                        border_radius=6,
                        padding=ft.Padding.symmetric(horizontal=8, vertical=4),
                    )
                ),
                ft.DataCell(
                    ft.Container(
                        content=ft.Row([
                            ft.Container(width=6, height=6, border_radius=3, bgcolor="#10B981"),
                            ft.Text("Active", size=10, weight=ft.FontWeight.BOLD, color="#065F46"),
                        ], spacing=5),
                        bgcolor="#D1FAE5",
                        border_radius=6,
                        padding=ft.Padding.symmetric(horizontal=8, vertical=4),
                    )
                ),
                ft.DataCell(
                    ft.Column([
                        ft.Text(last_time_str, size=12, weight=ft.FontWeight.W_600, color="#0F172A"),
                        ft.Text(last_date_str, size=10, color="#94A3B8"),
                    ], spacing=1, alignment=ft.MainAxisAlignment.CENTER)
                ),
            ])
        )

    user_table = ft.DataTable(
        columns=[
            ft.DataColumn(label=ft.Text("UserID", size=11, weight=ft.FontWeight.BOLD, color="#94A3B8")),
            ft.DataColumn(label=ft.Text("FullName", size=11, weight=ft.FontWeight.BOLD, color="#94A3B8")),
            ft.DataColumn(label=ft.Text("Username", size=11, weight=ft.FontWeight.BOLD, color="#94A3B8")),
            ft.DataColumn(label=ft.Text("Email", size=11, weight=ft.FontWeight.BOLD, color="#94A3B8")),
            ft.DataColumn(label=ft.Text("Role", size=11, weight=ft.FontWeight.BOLD, color="#94A3B8")),
            ft.DataColumn(label=ft.Text("Status", size=11, weight=ft.FontWeight.BOLD, color="#94A3B8")),
            ft.DataColumn(label=ft.Text("LastLogin", size=11, weight=ft.FontWeight.BOLD, color="#94A3B8")),
        ],
        rows=user_rows,
        heading_row_height=42,
        data_row_min_height=52,
        data_row_max_height=56,
        column_spacing=46,
        horizontal_lines=ft.BorderSide(1, "#F1F5F9"),
        show_checkbox_column=False,
    )

    user_table_card = ft.Container(
        content=ft.Column([
            ft.Row([
                ft.Row([
                    ft.Icon(ft.Icons.GROUP_ROUNDED, color="#0F172A", size=20),
                    ft.Column([
                        ft.Text("User Account Information", size=15, weight=ft.FontWeight.BOLD, color="#0F172A"),
                        ft.Text("Registered system operators and RBAC role assignments", size=11, color="#64748B"),
                    ], spacing=1),
                ], spacing=8),
                ft.Container(
                    content=ft.Row([
                        ft.Icon(ft.Icons.LOCK_PERSON_ROUNDED, size=13, color="#8B5CF6"),
                        ft.Text(f"{len(user_rows)} Operators Managed", size=11, weight=ft.FontWeight.BOLD, color="#8B5CF6"),
                    ], spacing=4),
                    bgcolor="#F5F3FF", border_radius=6, padding=ft.Padding.symmetric(horizontal=8, vertical=4),
                ),
            ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
            ft.Divider(color="#E2E8F0", height=12),
            ft.Row([user_table], scroll=ft.ScrollMode.AUTO),
            ft.Divider(color="#F1F5F9", height=10),
            ft.Row([
                ft.Text(f"Showing {len(user_rows)} user accounts in SQLite database", size=12, color="#94A3B8"),
                ft.Row([
                    ft.Icon(ft.Icons.VERIFIED_USER_ROUNDED, size=14, color="#10B981"),
                    ft.Text("Role privileges verified via Arpie RBAC engine", size=12, color="#64748B"),
                ], spacing=4),
            ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN)
        ]),
        bgcolor="#FFFFFF", border=ft.Border.all(1, "#E2E8F0"), border_radius=12, padding=16,
    )

    return ft.Column([
        stats_row,
        ft.Row([
            filter_row,
            ft.Container(
                content=ft.Row([
                    ft.Icon(ft.Icons.BADGE_ROUNDED, color="#0F172A", size=14),
                    ft.Text(f"{total_count} Accounts Registered", size=12, weight=ft.FontWeight.BOLD, color="#0F172A"),
                ], spacing=4),
                bgcolor="#F1F5F9", border_radius=6, padding=ft.Padding.symmetric(horizontal=8, vertical=4),
            )
        ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
        ft.Container(
            content=search_input,
            bgcolor="#FFFFFF", padding=12, border_radius=10, border=ft.Border.all(1, "#E2E8F0"),
        ),
        user_table_card,
    ], spacing=14, scroll=ft.ScrollMode.AUTO)
