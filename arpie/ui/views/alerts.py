import flet as ft
from ..components.dialogs import show_evidence_dialog


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
        hint_text="Search alerts by IP, type or evidence...",
        prefix_icon=ft.Icons.SEARCH_ROUNDED,
        dense=True,
        border_radius=8,
        border_color="#E2E8F0",
        expand=True,
        on_change=lambda e: app.on_search_change(e.control.value),
    )

    table_rows = []
    for alert_item in app.all_alerts_list:
        time_str = alert_item["time"]
        a_type = alert_item["type"]
        sev = alert_item["severity"]
        src = alert_item["source"]
        status = alert_item["status"]
        fgc = alert_item["fg"]
        bgc = alert_item["bg"]
        ev_desc = alert_item["desc"]

        if app.active_severity_filter != "All" and sev.lower() != app.active_severity_filter.lower():
            continue
        if app.search_query and (app.search_query.lower() not in a_type.lower() and app.search_query.lower() not in src.lower() and app.search_query.lower() not in ev_desc.lower()):
            continue

        table_rows.append(
            ft.DataRow(
                cells=[
                    ft.DataCell(ft.Text(time_str, size=12, color="#64748B")),
                    ft.DataCell(
                        ft.Container(
                            content=ft.Row([
                                ft.Icon(ft.Icons.SHIELD_ROUNDED if "ARP" in a_type else ft.Icons.WARNING_ROUNDED, color=fgc, size=14),
                                ft.Text(a_type, size=12, weight=ft.FontWeight.W_600, color="#0F172A"),
                            ], spacing=6),
                            on_click=lambda e, t=a_type, s=sev, ip=src, d=ev_desc: show_evidence_dialog(app, t, s, ip, d),
                        )
                    ),
                    ft.DataCell(ft.Container(
                        content=ft.Text(sev, size=10, weight=ft.FontWeight.BOLD, color=fgc),
                        bgcolor=bgc, border_radius=4, padding=ft.Padding.symmetric(horizontal=6, vertical=2),
                    )),
                    ft.DataCell(ft.Text(src, size=12, color="#0F172A")),
                    ft.DataCell(ft.Container(
                        content=ft.Text(status, size=10, weight=ft.FontWeight.BOLD, color="#64748B"),
                        bgcolor="#F1F5F9", border_radius=4, padding=ft.Padding.symmetric(horizontal=6, vertical=2),
                    )),
                ],
            )
        )

    alerts_table = ft.DataTable(
        columns=[
            ft.DataColumn(label=ft.Text("TIME", size=11, weight=ft.FontWeight.BOLD, color="#94A3B8")),
            ft.DataColumn(label=ft.Text("TYPE", size=11, weight=ft.FontWeight.BOLD, color="#94A3B8")),
            ft.DataColumn(label=ft.Text("SEVERITY", size=11, weight=ft.FontWeight.BOLD, color="#94A3B8")),
            ft.DataColumn(label=ft.Text("SOURCE", size=11, weight=ft.FontWeight.BOLD, color="#94A3B8")),
            ft.DataColumn(label=ft.Text("STATUS", size=11, weight=ft.FontWeight.BOLD, color="#94A3B8")),
        ],
        rows=table_rows,
        heading_row_height=40,
        data_row_min_height=42,
        data_row_max_height=46,
        horizontal_lines=ft.BorderSide(1, "#F1F5F9"),
        show_checkbox_column=False,
    )

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
        ft.Container(
            content=ft.Column([
                alerts_table,
                ft.Divider(color="#F1F5F9", height=10),
                ft.Row([
                    ft.Text(f"Showing {len(table_rows)} alerts this session", size=12, color="#94A3B8"),
                    ft.Row([
                        ft.Icon(ft.Icons.TOUCH_APP_ROUNDED, size=14, color="#94A3B8"),
                        ft.Text("Click an alert name to inspect evidence", size=12, color="#94A3B8"),
                    ], spacing=4),
                ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN)
            ]),
            bgcolor="#FFFFFF", border=ft.Border.all(1, "#E2E8F0"), border_radius=12, padding=16,
        )
    ], spacing=14, scroll=ft.ScrollMode.AUTO)
