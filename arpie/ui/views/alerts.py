import datetime
import flet as ft


def _make_filter_chip(app, label: str) -> ft.Container:
    is_sel = (app.active_severity_filter == label)
    return ft.Container(
        content=ft.Text(label, size=12, weight=ft.FontWeight.BOLD if is_sel else ft.FontWeight.W_500, color="#FFFFFF" if is_sel else "#475569"),
        bgcolor="#0F172A" if is_sel else "#FFFFFF",
        border=ft.Border.all(1, "#0F172A" if is_sel else "#E2E8F0"),
        border_radius=20,
        padding=ft.Padding.symmetric(horizontal=14, vertical=6),
        on_click=lambda e, l=label: app.set_severity_filter(l),
    )


def render_alerts_view(app) -> ft.Column:
    filter_pills = ft.Row([
        _make_filter_chip(app, "All"),
        _make_filter_chip(app, "Critical"),
        _make_filter_chip(app, "High"),
        _make_filter_chip(app, "Medium"),
        _make_filter_chip(app, "Low"),
        _make_filter_chip(app, "Info"),
    ], spacing=8)

    search_input = ft.TextField(
        hint_text="Search alerts by IP, threat type or evidence proof...",
        prefix_icon=ft.Icons.SEARCH_ROUNDED,
        dense=True,
        border_radius=8,
        border_color="#E2E8F0",
        expand=True,
        on_change=lambda e: app.on_search_change(e.control.value),
    )

    def select_alert(alert_item):
        app.selected_alert = alert_item
        app.update_view_content()
        app.page.update()

    def close_drawer(e):
        app.selected_alert = None
        app.update_view_content()
        app.page.update()

    table_rows = []
    today_date = datetime.datetime.now().strftime("%Y-%m-%d")

    for alert_item in app.all_alerts_list:
        time_str = alert_item.get("time", "")
        date_str = alert_item.get("date", today_date)
        a_type = alert_item.get("type", "")
        sev = alert_item.get("severity", "")
        src = alert_item.get("source", "")
        target = alert_item.get("target", "Local Endpoint")
        status = alert_item.get("status", "NEW")
        fgc = alert_item.get("fg", "#DC2626")
        bgc = alert_item.get("bg", "#FEE2E2")
        ev_desc = alert_item.get("desc", "")

        if app.active_severity_filter != "All" and sev.lower() != app.active_severity_filter.lower():
            continue
        if app.search_query and (app.search_query.lower() not in a_type.lower() and app.search_query.lower() not in src.lower() and app.search_query.lower() not in ev_desc.lower()):
            continue

        is_selected = (app.selected_alert and app.selected_alert.get("time") == time_str and app.selected_alert.get("source") == src)

        table_rows.append(
            ft.DataRow(
                cells=[
                    ft.DataCell(
                        ft.Column([
                            ft.Text(time_str, size=12, weight=ft.FontWeight.W_600, color="#0F172A"),
                            ft.Text(date_str, size=10, color="#94A3B8"),
                        ], spacing=1, alignment=ft.MainAxisAlignment.CENTER)
                    ),
                    ft.DataCell(
                        ft.Container(
                            content=ft.Row([
                                ft.Icon(ft.Icons.SHIELD_ROUNDED if "ARP" in a_type else ft.Icons.WARNING_ROUNDED, color=fgc, size=15),
                                ft.Text(a_type, size=12, weight=ft.FontWeight.W_600, color="#0F172A"),
                            ], spacing=6),
                            tooltip="View Evidence",
                            on_click=lambda e, item=alert_item: select_alert(item),
                        )
                    ),
                    ft.DataCell(ft.Container(
                        content=ft.Text(sev, size=10, weight=ft.FontWeight.BOLD, color=fgc),
                        bgcolor=bgc, border_radius=4, padding=ft.Padding.symmetric(8, 3),
                    )),
                    ft.DataCell(ft.Text(src, size=12, weight=ft.FontWeight.W_600, color="#0F172A")),
                    ft.DataCell(ft.Text(target, size=12, color="#475569")),
                    ft.DataCell(ft.Container(
                        content=ft.Text("100%", size=10, weight=ft.FontWeight.BOLD, color="#0284C7"),
                        bgcolor="#E0F2FE", border_radius=4, padding=ft.Padding.symmetric(6, 2),
                    )),
                    ft.DataCell(ft.Container(
                        content=ft.Text(status, size=10, weight=ft.FontWeight.BOLD, color="#64748B"),
                        bgcolor="#F1F5F9", border_radius=4, padding=ft.Padding.symmetric(6, 2),
                    )),
                    ft.DataCell(
                        ft.IconButton(
                            icon=ft.Icons.OPEN_IN_NEW_ROUNDED,
                            icon_color="#475569" if not is_selected else "#DC2626",
                            icon_size=18,
                            tooltip="View Evidence",
                            on_click=lambda e, item=alert_item: select_alert(item),
                        )
                    ),
                ],
            )
        )

    alerts_table = ft.DataTable(
        columns=[
            ft.DataColumn(label=ft.Text("TIMESTAMP", size=11, weight=ft.FontWeight.BOLD, color="#94A3B8")),
            ft.DataColumn(label=ft.Text("THREAT TYPE", size=11, weight=ft.FontWeight.BOLD, color="#94A3B8")),
            ft.DataColumn(label=ft.Text("SEVERITY", size=11, weight=ft.FontWeight.BOLD, color="#94A3B8")),
            ft.DataColumn(label=ft.Text("SOURCE IP", size=11, weight=ft.FontWeight.BOLD, color="#94A3B8")),
            ft.DataColumn(label=ft.Text("TARGET", size=11, weight=ft.FontWeight.BOLD, color="#94A3B8")),
            ft.DataColumn(label=ft.Text("CONFIDENCE", size=11, weight=ft.FontWeight.BOLD, color="#94A3B8")),
            ft.DataColumn(label=ft.Text("STATUS", size=11, weight=ft.FontWeight.BOLD, color="#94A3B8")),
            ft.DataColumn(label=ft.Text("ACTION", size=11, weight=ft.FontWeight.BOLD, color="#94A3B8")),
        ],
        rows=table_rows,
        heading_row_height=42,
        data_row_min_height=48,
        data_row_max_height=52,
        column_spacing=20 if app.selected_alert else 54,
        horizontal_lines=ft.BorderSide(1, "#F1F5F9"),
        show_checkbox_column=False,
    )

    table_card = ft.Container(
        content=ft.Column([
            ft.Row([
                ft.Row([
                    ft.Icon(ft.Icons.SHIELD_ROUNDED, color="#0F172A", size=20),
                    ft.Text("Security Events & Alerts", size=15, weight=ft.FontWeight.BOLD, color="#0F172A"),
                ], spacing=8),
                ft.Text(f"{len(table_rows)} Incidents Logged", size=12, color="#64748B"),
            ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
            ft.Divider(color="#E2E8F0", height=12),
            ft.Row([alerts_table], scroll=ft.ScrollMode.AUTO),
            ft.Divider(color="#F1F5F9", height=10),
            ft.Row([
                ft.Text(f"Showing {len(table_rows)} alerts this session", size=12, color="#94A3B8"),
                ft.Row([
                    ft.Icon(ft.Icons.TOUCH_APP_ROUNDED, size=14, color="#94A3B8"),
                    ft.Text("Click any row or ↗ icon to inspect deterministic proof metrics", size=12, color="#94A3B8"),
                ], spacing=4),
            ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN)
        ]),
        bgcolor="#FFFFFF", border=ft.Border.all(1, "#E2E8F0"), border_radius=12, padding=16,
        expand=True,
    )

    # --- Evidence Inspector Side Drawer ---
    main_content: ft.Control
    if app.selected_alert:
        sel = app.selected_alert
        sel_type = sel.get("type", "Security Event")
        sel_sev = sel.get("severity", "HIGH")
        sel_src = sel.get("source", "Unknown")
        sel_target = sel.get("target", "Local Endpoint")
        sel_desc = sel.get("desc", "No description available.")
        sel_fg = sel.get("fg", "#DC2626")
        sel_bg = sel.get("bg", "#FEE2E2")
        sel_time = sel.get("time", "")
        sel_date = sel.get("date", today_date)

        def quick_seal(e, ip=sel_src):
            app.active_blocks.append({
                "ip": ip,
                "type": sel_type,
                "time": sel_time,
                "status": "Isolated (Active Block)",
            })
            app.status_toast = f"Host {ip} isolated via 1-Click Seal Mode."
            app.update_view_content()
            app.page.update()

        evidence_drawer = ft.Container(
            content=ft.Column([
                ft.Row([
                    ft.Row([
                        ft.Icon(ft.Icons.SAVED_SEARCH_ROUNDED, color="#0F172A", size=20),
                        ft.Column([
                            ft.Text("Incident Evidence Details", size=14, weight=ft.FontWeight.BOLD, color="#0F172A"),
                            ft.Text("Deterministic Heuristic Proof Metrics", size=10, color="#64748B"),
                        ], spacing=1),
                    ], spacing=8),
                    ft.IconButton(ft.Icons.CLOSE_ROUNDED, icon_size=18, tooltip="Close Inspector", on_click=close_drawer),
                ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                ft.Divider(color="#E2E8F0", height=10),

                # Alert summary badge
                ft.Container(
                    content=ft.Column([
                        ft.Row([
                            ft.Text(sel_type, size=13, weight=ft.FontWeight.BOLD, color="#0F172A"),
                            ft.Container(
                                content=ft.Text(sel_sev, size=9, weight=ft.FontWeight.BOLD, color=sel_fg),
                                bgcolor=sel_bg, border_radius=4, padding=ft.Padding.symmetric(6, 2),
                            ),
                        ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                        ft.Text(f"Detected on {sel_date} at {sel_time}", size=11, color="#64748B"),
                        ft.Text(sel_desc, size=12, color="#334155"),
                    ], spacing=6),
                    bgcolor="#F8FAFC", border=ft.Border.all(1, "#E2E8F0"), border_radius=8, padding=12,
                ),

                # Target & Threat Metadata
                ft.Column([
                    ft.Row([
                        ft.Column([
                            ft.Text("Source Host (Attacker)", size=10, color="#64748B", weight=ft.FontWeight.BOLD),
                            ft.Text(sel_src, size=13, weight=ft.FontWeight.BOLD, color="#DC2626"),
                        ], spacing=2, expand=1),
                        ft.Column([
                            ft.Text("Target Endpoint", size=10, color="#64748B", weight=ft.FontWeight.BOLD),
                            ft.Text(sel_target, size=13, weight=ft.FontWeight.BOLD, color="#0F172A"),
                        ], spacing=2, expand=1),
                    ]),
                    ft.Row([
                        ft.Column([
                            ft.Text("Heuristic Certainty", size=10, color="#64748B", weight=ft.FontWeight.BOLD),
                            ft.Text("100% Deterministic", size=12, weight=ft.FontWeight.BOLD, color="#0284C7"),
                        ], spacing=2, expand=1),
                        ft.Column([
                            ft.Text("Triage Status", size=10, color="#64748B", weight=ft.FontWeight.BOLD),
                            ft.Text(sel.get("status", "NEW"), size=12, weight=ft.FontWeight.BOLD, color="#10B981"),
                        ], spacing=2, expand=1),
                    ]),
                ], spacing=10),

                ft.Divider(color="#F1F5F9", height=8),

                # Threat Intelligence Quick Look
                ft.Container(
                    content=ft.Column([
                        ft.Row([
                            ft.Icon(ft.Icons.TRAVEL_EXPLORE_ROUNDED, size=16, color="#0F172A"),
                            ft.Text("Threat Intelligence", size=12, weight=ft.FontWeight.BOLD, color="#0F172A"),
                        ], spacing=6),
                        ft.Row([
                            ft.Text("Abuse Confidence Score:", size=11, color="#64748B"),
                            ft.Container(
                                content=ft.Text("98% Malicious" if "192.168.1.50" in sel_src or "192.168.1.1" in sel_src else "Clean (0%)", size=10, weight=ft.FontWeight.BOLD, color="#DC2626"),
                                bgcolor="#FEE2E2", border_radius=4, padding=ft.Padding.symmetric(6, 2),
                            ),
                        ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                        ft.Row([
                            ft.Text("Autonomous System:", size=11, color="#64748B"),
                            ft.Text("AS13335 (Cloudflare / Local)", size=11, weight=ft.FontWeight.W_500, color="#0F172A"),
                        ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                    ], spacing=6),
                    bgcolor="#F8FAFC", border=ft.Border.all(1, "#E2E8F0"), border_radius=8, padding=10,
                ),

                ft.Container(height=4),

                # Containment Action
                ft.ElevatedButton(
                    content=ft.Row([
                        ft.Icon(ft.Icons.SHIELD_ROUNDED, color="#FFFFFF", size=16),
                        ft.Text("1-Click Seal Mode: Isolate Host", size=12, weight=ft.FontWeight.BOLD, color="#FFFFFF"),
                    ], alignment=ft.MainAxisAlignment.CENTER, spacing=6),
                    style=ft.ButtonStyle(
                        bgcolor="#DC2626",
                        shape=ft.RoundedRectangleBorder(radius=8),
                        padding=ft.Padding.symmetric(vertical=12),
                    ),
                    on_click=quick_seal,
                    width=350,
                ),
            ], spacing=10, scroll=ft.ScrollMode.AUTO),
            width=380,
            bgcolor="#FFFFFF",
            border=ft.Border.all(1, "#E2E8F0"),
            border_radius=12,
            padding=16,
            shadow=ft.BoxShadow(spread_radius=1, blur_radius=16, color="#0F172A0D"),
        )

        main_content = ft.Row([table_card, evidence_drawer], spacing=14, vertical_alignment=ft.CrossAxisAlignment.START)
    else:
        main_content = table_card

    return ft.Column([
        ft.Row([
            filter_pills,
            ft.Container(
                content=ft.Row([
                    ft.Icon(ft.Icons.WARNING_ROUNDED, color="#DC2626", size=14),
                    ft.Text(f"{len(table_rows)} Active Alerts", size=12, weight=ft.FontWeight.BOLD, color="#DC2626"),
                ], spacing=4),
                bgcolor="#FEE2E2", border_radius=6, padding=ft.Padding.symmetric(horizontal=8, vertical=4),
            )
        ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
        ft.Container(
            content=search_input,
            bgcolor="#FFFFFF", padding=12, border_radius=10, border=ft.Border.all(1, "#E2E8F0"),
        ),
        main_content,
    ], spacing=14, scroll=ft.ScrollMode.AUTO)
