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


def _make_stat_card(icon, label: str, value: str, color: str, bg: str) -> ft.Container:
    return ft.Container(
        content=ft.Row([
            ft.Container(
                content=ft.Icon(icon, color=color, size=20),
                bgcolor=bg, border_radius=10, padding=10,
            ),
            ft.Column([
                ft.Text(label, size=11, weight=ft.FontWeight.W_500, color="#64748B"),
                ft.Text(value, size=18, weight=ft.FontWeight.BOLD, color="#0F172A"),
            ], spacing=2),
        ], spacing=12),
        bgcolor="#FFFFFF", border=ft.Border.all(1, "#E2E8F0"), border_radius=12, padding=16, expand=1,
    )


def render_users_view(app) -> ft.Column:
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
    evaluator_count = sum(1 for o in operators_list if "Evaluator" in o.get("role", ""))
    end_user_count = total_count - evaluator_count

    stats_row = ft.Row([
        _make_stat_card(ft.Icons.GROUP_ROUNDED, "Total Users", str(total_count), "#0F172A", "#F1F5F9"),
        _make_stat_card(ft.Icons.ADMIN_PANEL_SETTINGS_ROUNDED, "Evaluator / Admins", str(evaluator_count), "#8B5CF6", "#F5F3FF"),
        _make_stat_card(ft.Icons.PERSON_ROUNDED, "End Users", str(end_user_count), "#10B981", "#ECFDF5"),
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
        hint_text="Search user accounts by username, email or display name...",
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
        uname = op.get("username", "")
        email = op.get("email", "")
        disp = op.get("display_name") or uname
        role_label = op.get("role", "End User")

        if app.active_user_role_filter != "All" and role_label != app.active_user_role_filter:
            continue
        if app.user_search_query and (
            app.user_search_query.lower() not in uname.lower()
            and app.user_search_query.lower() not in email.lower()
            and app.user_search_query.lower() not in disp.lower()
        ):
            continue

        created_str = datetime.datetime.fromtimestamp(op.get("created_at") or time.time()).strftime("%Y-%m-%d %H:%M")
        last_str = datetime.datetime.fromtimestamp(op.get("last_login_at") or time.time()).strftime("%Y-%m-%d %H:%M") if op.get("last_login_at") else "Active Session"

        user_rows.append(
            ft.DataRow(cells=[
                ft.DataCell(ft.Text(str(op.get("id")), size=12, color="#64748B")),
                ft.DataCell(ft.Text(disp, size=12, weight=ft.FontWeight.BOLD, color="#0F172A")),
                ft.DataCell(ft.Text(uname, size=12, color="#0F172A")),
                ft.DataCell(ft.Text(email, size=12, color="#475569")),
                ft.DataCell(ft.Container(
                    content=ft.Text(role_label, size=10, weight=ft.FontWeight.BOLD, color="#8B5CF6" if "Evaluator" in role_label else "#10B981"),
                    bgcolor="#F5F3FF" if "Evaluator" in role_label else "#ECFDF5",
                    border_radius=4, padding=ft.Padding.symmetric(horizontal=8, vertical=3),
                )),
                ft.DataCell(ft.Container(
                    content=ft.Text("Active", size=10, weight=ft.FontWeight.BOLD, color="#10B981"),
                    bgcolor="#ECFDF5",
                    border_radius=4, padding=ft.Padding.symmetric(horizontal=8, vertical=3),
                )),
                ft.DataCell(ft.Text(last_str, size=12, color="#64748B")),
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
        data_row_min_height=48,
        data_row_max_height=52,
        column_spacing=52,
        horizontal_lines=ft.BorderSide(1, "#F1F5F9"),
        show_checkbox_column=False,
    )

    user_table_card = ft.Container(
        content=ft.Column([
            ft.Row([
                ft.Row([
                    ft.Icon(ft.Icons.GROUP_ROUNDED, color="#0F172A", size=20),
                    ft.Text("User Account Information", size=15, weight=ft.FontWeight.BOLD, color="#0F172A"),
                ], spacing=8),
                ft.Text(f"{len(user_rows)} Operators Registered", size=12, color="#64748B"),
            ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
            ft.Divider(color="#E2E8F0", height=12),
            ft.Row([user_table], scroll=ft.ScrollMode.AUTO),
            ft.Divider(color="#F1F5F9", height=10),
            ft.Row([
                ft.Text(f"Showing {len(user_rows)} user accounts in database", size=12, color="#94A3B8"),
                ft.Row([
                    ft.Icon(ft.Icons.SECURITY_ROUNDED, size=14, color="#94A3B8"),
                    ft.Text("Role privileges enforced via Arpie RBAC engine", size=12, color="#94A3B8"),
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
                    ft.Text(f"{total_count} Accounts", size=12, weight=ft.FontWeight.BOLD, color="#0F172A"),
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
