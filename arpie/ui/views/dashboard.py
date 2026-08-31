import flet as ft
import flet.canvas as cv


def _make_mini_alert_item(title: str, sev: str, fgc: str, bgc: str) -> ft.Container:
    return ft.Container(
        content=ft.Row([
            ft.Row([
                ft.Container(width=8, height=8, border_radius=4, bgcolor=fgc),
                ft.Text(title, size=13, weight=ft.FontWeight.W_600, color="#0F172A"),
            ], spacing=8),
            ft.Container(
                content=ft.Text(sev, size=10, weight=ft.FontWeight.BOLD, color=fgc),
                bgcolor=bgc, border_radius=4, padding=ft.Padding.symmetric(horizontal=6, vertical=2),
            )
        ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
        padding=10, border_radius=8, border=ft.Border.all(1, "#F1F5F9"), bgcolor="#FAFAFC",
    )


def _compute_risk_score(alerts_list):
    if not alerts_list:
        return 0
    severity_weights = {"low": 5, "medium": 15, "high": 30, "critical": 45}
    scores = []
    for a in alerts_list:
        sev = a.get("severity", "").lower()
        scores.append(severity_weights.get(sev, 0))
    base = max(scores) if scores else 0
    distinct_types = {a.get("type", "") for a in alerts_list}
    bonus = min(20, (len(distinct_types) - 1) * 8) if len(distinct_types) > 1 else 0
    return max(0, min(100, base + bonus))


def _count_severities(alerts_list):
    counts = {}
    for a in alerts_list:
        sev = a.get("severity", "UNKNOWN").upper()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _compute_protocol_stats(packet_log):
    if not packet_log:
        return "No data"
    proto_counts = {}
    for p in packet_log:
        proto = p.get("proto", "OTHER")
        base_proto = proto.split(" ")[0].split("(")[0].strip()
        if base_proto in ("TCP", "UDP", "ICMP", "ARP", "DNS", "IP"):
            proto_counts[base_proto] = proto_counts.get(base_proto, 0) + 1
        else:
            proto_counts["OTHER"] = proto_counts.get("OTHER", 0) + 1
    total = sum(proto_counts.values())
    if total == 0:
        return "No data"
    sorted_protos = sorted(proto_counts.items(), key=lambda x: x[1], reverse=True)[:3]
    parts = [f"{name} {int(count / total * 100)}%" for name, count in sorted_protos]
    return " · ".join(parts)


def _build_spline_chart(app) -> ft.Container:
    time_labels = [f"09:{i*2+6:02d}" for i in range(12)]
    suspicious_vals = app.suspicious_history if hasattr(app, "suspicious_history") and app.suspicious_history else [120, 230, 140, 180, 300, 180, 250, 360, 200, 190, 260, 280]
    total_vals = app.traffic_history if hasattr(app, "traffic_history") and app.traffic_history else [40, 100, 50, 110, 190, 95, 140, 210, 85, 70, 115, 130]
    blocked_vals = app.blocked_history if hasattr(app, "blocked_history") and app.blocked_history else [30, 42, 28, 75, 55, 28, 50, 75, 48, 52, 60, 68]

    chart_w = 900
    chart_h = 200
    c_left = 60
    c_right = chart_w - 20
    c_top = 20
    c_bottom = chart_h - 30
    span_x = (c_right - c_left) / (len(time_labels) - 1)
    y_max = max(max(suspicious_vals, default=400), max(total_vals, default=400), max(blocked_vals, default=400), 100) * 1.15

    shapes: list[cv.Shape] = []

    for y_val_raw in range(0, int(y_max) + 1, max(1, int(y_max / 4))):
        y_pos = c_bottom - (y_val_raw / y_max) * (c_bottom - c_top)
        shapes.append(
            cv.Line(c_left, y_pos, c_right, y_pos, paint=ft.Paint(color="#F1F5F9", stroke_width=1.2))
        )
        shapes.append(
            cv.Text(
                16, y_pos - 7, f"{y_val_raw:>3}",
                style=ft.TextStyle(size=11, color="#94A3B8", weight=ft.FontWeight.W_600),
            )
        )

    def compute_points(values):
        return [
            (c_left + i * span_x, c_bottom - (max(0, min(y_max, v)) / y_max) * (c_bottom - c_top))
            for i, v in enumerate(values)
        ]

    def make_spline_elements(pts):
        elems: list[cv.Path.PathElement] = [cv.Path.MoveTo(pts[0][0], pts[0][1])]
        for i in range(len(pts) - 1):
            p0 = pts[max(0, i - 1)]
            p1 = pts[i]
            p2 = pts[i + 1]
            p3 = pts[min(len(pts) - 1, i + 2)]
            cp1_x = p1[0] + (p2[0] - p0[0]) / 3.5
            cp1_y = p1[1] + (p2[1] - p0[1]) / 3.5
            cp2_x = p2[0] - (p3[0] - p1[0]) / 3.5
            cp2_y = p2[1] - (p3[1] - p1[1]) / 3.5
            elems.append(cv.Path.CubicTo(cp1_x, cp1_y, cp2_x, cp2_y, p2[0], p2[1]))
        return elems

    pts_susp = compute_points(suspicious_vals)
    pts_total = compute_points(total_vals)
    pts_blocked = compute_points(blocked_vals)

    def add_area(pts, fill_color):
        area_elems: list[cv.Path.PathElement] = make_spline_elements(pts)
        area_elems.append(cv.Path.LineTo(pts[-1][0], c_bottom))
        area_elems.append(cv.Path.LineTo(pts[0][0], c_bottom))
        area_elems.append(cv.Path.Close())
        shapes.append(cv.Path(elements=area_elems, paint=ft.Paint(color=fill_color, style=ft.PaintingStyle.FILL)))

    add_area(pts_susp, "#FFE4E6")
    add_area(pts_total, "#F1F5F9")
    add_area(pts_blocked, "#F0FDFA")

    shapes.append(
        cv.Path(elements=make_spline_elements(pts_total), paint=ft.Paint(color="#1E293B", stroke_width=2.2, style=ft.PaintingStyle.STROKE))
    )
    shapes.append(
        cv.Path(elements=make_spline_elements(pts_blocked), paint=ft.Paint(color="#0D9488", stroke_width=2.2, style=ft.PaintingStyle.STROKE))
    )
    shapes.append(
        cv.Path(elements=make_spline_elements(pts_susp), paint=ft.Paint(color="#EF4444", stroke_width=2.6, style=ft.PaintingStyle.STROKE))
    )

    def add_nodes(pts, color):
        for px, py in pts:
            shapes.append(cv.Circle(px, py, radius=3.8, paint=ft.Paint(color=color, style=ft.PaintingStyle.FILL)))
            shapes.append(cv.Circle(px, py, radius=2.2, paint=ft.Paint(color="#FFFFFF", style=ft.PaintingStyle.FILL)))

    add_nodes(pts_total, "#1E293B")
    add_nodes(pts_blocked, "#0D9488")
    add_nodes(pts_susp, "#EF4444")

    for i, label in enumerate(time_labels):
        x_pos = c_left + i * span_x
        shapes.append(
            cv.Text(
                x_pos - 15, c_bottom + 8, label,
                style=ft.TextStyle(size=10, color="#94A3B8", weight=ft.FontWeight.W_600),
            )
        )

    canvas = cv.Canvas(shapes=shapes, width=chart_w, height=chart_h)

    return ft.Container(
        content=ft.Column([
            ft.Row([
                ft.Column([
                    ft.Text("Real-Time Traffic", size=16, weight=ft.FontWeight.BOLD, color="#0F172A"),
                    ft.Text("Packets / second timeline", size=12, color="#64748B", weight=ft.FontWeight.W_500),
                ], spacing=2),
                ft.Row([
                    ft.Row([ft.Container(width=12, height=3, border_radius=2, bgcolor="#1E293B"), ft.Text("Total Traffic", size=11, weight=ft.FontWeight.W_600, color="#475569")], spacing=6),
                    ft.Row([ft.Container(width=12, height=3, border_radius=2, bgcolor="#EF4444"), ft.Text("Suspicious Traffic", size=11, weight=ft.FontWeight.W_600, color="#475569")], spacing=6),
                    ft.Row([ft.Container(width=12, height=3, border_radius=2, bgcolor="#0D9488"), ft.Text("Blocked Traffic", size=11, weight=ft.FontWeight.W_600, color="#475569")], spacing=6),
                ], spacing=20)
            ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
            ft.Container(height=6),
            ft.Container(
                content=canvas,
                alignment=ft.Alignment(0, 0),
            ),
        ]),
        bgcolor="#FFFFFF", border=ft.Border.all(1, "#E2E8F0"), border_radius=14, padding=18,
    )


def render_dashboard_view(app) -> ft.Column:
    risk_score = _compute_risk_score(app.all_alerts_list)
    risk_val = max(0.05, min(1.0, risk_score / 100.0))
    risk_color = "#DC2626" if risk_score >= 70 else ("#D97706" if risk_score >= 40 else "#10B981")
    risk_bg = "#FEE2E2" if risk_score >= 70 else ("#FEF3C7" if risk_score >= 40 else "#ECFDF5")
    risk_label = "HIGH RISK" if risk_score >= 70 else ("MED RISK" if risk_score >= 40 else "LOW RISK")

    risk_gauge = ft.Container(
        content=ft.Stack([
            ft.ProgressRing(value=risk_val, stroke_width=7, color=risk_color, bgcolor=risk_bg, width=54, height=54),
            ft.Container(
                content=ft.Text(str(risk_score), size=16, weight=ft.FontWeight.BOLD, color=risk_color),
                alignment=ft.Alignment(0, 0),
                width=54, height=54,
            )
        ]),
        width=54, height=54,
    )

    card_risk = ft.Container(
        content=ft.Row([
            risk_gauge,
            ft.Column([
                ft.Text("SESSION RISK", size=10, weight=ft.FontWeight.BOLD, color="#94A3B8"),
                ft.Row([
                    ft.Text(f"{risk_score}", size=20, weight=ft.FontWeight.BOLD, color="#0F172A"),
                    ft.Text("/100", size=11, color="#94A3B8", weight=ft.FontWeight.BOLD),
                ], spacing=2),
                ft.Container(
                    content=ft.Text(risk_label, size=9, weight=ft.FontWeight.BOLD, color=risk_color),
                    bgcolor=risk_bg, border_radius=4, padding=ft.Padding.symmetric(horizontal=6, vertical=2),
                )
            ], spacing=2, expand=True),
        ], spacing=12, vertical_alignment=ft.CrossAxisAlignment.CENTER),
        bgcolor="#FFFFFF", border=ft.Border.all(1, "#E2E8F0"), border_radius=12, padding=14, expand=1,
    )

    total_alerts = len(app.all_alerts_list)
    sev_counts = _count_severities(app.all_alerts_list)
    high_cnt = sev_counts.get("HIGH", 0) + sev_counts.get("CRITICAL", 0)
    med_cnt = sev_counts.get("MEDIUM", 0)
    low_cnt = sev_counts.get("LOW", 0)
    sev_text = f"{high_cnt} High · {med_cnt} Med · {low_cnt} Low"

    alert_ring = ft.Container(
        content=ft.Stack([
            ft.ProgressRing(value=min(1.0, total_alerts / max(total_alerts, 1)), stroke_width=7, color="#D97706", bgcolor="#FEF3C7", width=54, height=54),
            ft.Container(
                content=ft.Icon(ft.Icons.NOTIFICATIONS_ACTIVE_ROUNDED, size=18, color="#D97706"),
                alignment=ft.Alignment(0, 0),
                width=54, height=54,
            )
        ]),
        width=54, height=54,
    )

    total_bar = high_cnt + med_cnt + low_cnt or 1
    card_alerts = ft.Container(
        content=ft.Row([
            alert_ring,
            ft.Column([
                ft.Text("ACTIVE ALERTS", size=10, weight=ft.FontWeight.BOLD, color="#94A3B8"),
                ft.Text(f"{total_alerts} Detected", size=18, weight=ft.FontWeight.BOLD, color="#0F172A"),
                ft.Row([
                    ft.Container(height=4, width=max(4, int(66 * high_cnt / total_bar)), border_radius=2, bgcolor="#DC2626"),
                    ft.Container(height=4, width=max(4, int(66 * med_cnt / total_bar)), border_radius=2, bgcolor="#D97706"),
                    ft.Container(height=4, width=max(4, int(66 * low_cnt / total_bar)), border_radius=2, bgcolor="#10B981"),
                ], spacing=3),
                ft.Text(sev_text, size=9, color="#64748B", weight=ft.FontWeight.W_500),
            ], spacing=2, expand=True),
        ], spacing=12, vertical_alignment=ft.CrossAxisAlignment.CENTER),
        bgcolor="#FFFFFF", border=ft.Border.all(1, "#E2E8F0"), border_radius=12, padding=14, expand=1,
    )

    proto_text = _compute_protocol_stats(app.packet_log_stream)
    packet_ring = ft.Container(
        content=ft.Stack([
            ft.ProgressRing(value=0.88, stroke_width=7, color="#0284C7", bgcolor="#E0F2FE", width=54, height=54),
            ft.Container(
                content=ft.Icon(ft.Icons.DATA_SAVER_ON_ROUNDED, size=18, color="#0284C7"),
                alignment=ft.Alignment(0, 0),
                width=54, height=54,
            )
        ]),
        width=54, height=54,
    )

    card_packets = ft.Container(
        content=ft.Row([
            packet_ring,
            ft.Column([
                ft.Text("PACKET ANALYSIS", size=10, weight=ft.FontWeight.BOLD, color="#94A3B8"),
                ft.Text(f"{app.packets_count:,}", size=18, weight=ft.FontWeight.BOLD, color="#0F172A"),
                ft.Text(proto_text, size=9, color="#64748B", weight=ft.FontWeight.W_500),
            ], spacing=2, expand=True),
        ], spacing=12, vertical_alignment=ft.CrossAxisAlignment.CENTER),
        bgcolor="#FFFFFF", border=ft.Border.all(1, "#E2E8F0"), border_radius=12, padding=14, expand=1,
    )

    active_rules = sum(1 for v in app.detection_rules.values() if v)
    total_rules = len(app.detection_rules)
    engine_ring = ft.Container(
        content=ft.Stack([
            ft.ProgressRing(value=1.0, stroke_width=7, color="#10B981", bgcolor="#ECFDF5", width=54, height=54),
            ft.Container(
                content=ft.Icon(ft.Icons.SHIELD_ROUNDED, size=18, color="#10B981"),
                alignment=ft.Alignment(0, 0),
                width=54, height=54,
            )
        ]),
        width=54, height=54,
    )

    card_engine = ft.Container(
        content=ft.Row([
            engine_ring,
            ft.Column([
                ft.Text("NIDS ENGINE", size=10, weight=ft.FontWeight.BOLD, color="#94A3B8"),
                app.timer_text,
                ft.Container(
                    content=ft.Row([
                        ft.Container(width=6, height=6, border_radius=3, bgcolor="#10B981"),
                        ft.Text(f"{active_rules}/{total_rules} Rules Active", size=9, weight=ft.FontWeight.BOLD, color="#10B981"),
                    ], spacing=4),
                    bgcolor="#ECFDF5", border_radius=4, padding=ft.Padding.symmetric(horizontal=6, vertical=2),
                )
            ], spacing=2, expand=True),
        ], spacing=12, vertical_alignment=ft.CrossAxisAlignment.CENTER),
        bgcolor="#FFFFFF", border=ft.Border.all(1, "#E2E8F0"), border_radius=12, padding=14, expand=1,
    )

    kpi_cards = ft.Row([card_risk, card_alerts, card_packets, card_engine], spacing=14)
    chart_card = _build_spline_chart(app)

    top_talkers_header = ft.Row([
        ft.Text("IP Address", size=11, weight=ft.FontWeight.BOLD, color="#94A3B8", expand=2),
        ft.Text("Packets", size=11, weight=ft.FontWeight.BOLD, color="#94A3B8", expand=1, text_align=ft.TextAlign.RIGHT),
        ft.Text("%", size=11, weight=ft.FontWeight.BOLD, color="#94A3B8", expand=1, text_align=ft.TextAlign.RIGHT),
    ])

    top_talkers_rows: list[ft.Control] = [
        ft.Container(
            content=ft.Row([
                ft.Text(str(row["ip"]), size=12, weight=ft.FontWeight.W_600, color="#0F172A", expand=2),
                ft.Text(f"{row['packets']:,}", size=12, color="#475569", expand=1, text_align=ft.TextAlign.RIGHT),
                ft.Text(str(row["pct"]), size=12, weight=ft.FontWeight.BOLD, color="#DC2626", expand=1, text_align=ft.TextAlign.RIGHT),
            ]),
            padding=ft.Padding.symmetric(vertical=6),
            border=ft.Border(bottom=ft.BorderSide(1, "#F1F5F9")),
        ) for row in app.top_talkers_data
    ]

    top_talkers_card = ft.Container(
        content=ft.Column([
            ft.Text("TOP TALKERS", size=11, weight=ft.FontWeight.BOLD, color="#94A3B8"),
            top_talkers_header,
            ft.Column(top_talkers_rows, spacing=0),
        ], spacing=8),
        bgcolor="#FFFFFF", border=ft.Border.all(1, "#E2E8F0"), border_radius=12, padding=16, expand=1,
    )

    sev_color_map = {
        "HIGH": ("#DC2626", "#FEE2E2"), "CRITICAL": ("#DC2626", "#FEE2E2"),
        "MEDIUM": ("#D97706", "#FEF3C7"), "LOW": ("#10B981", "#ECFDF5"),
    }
    recent = app.all_alerts_list[:3]
    recent_alerts_items: list[ft.Control] = []
    for a in recent:
        fg, bg = sev_color_map.get(a.get("severity", "").upper(), ("#64748B", "#F1F5F9"))
        recent_alerts_items.append(_make_mini_alert_item(a.get("type", "Alert"), a.get("severity", ""), fg, bg))

    if not recent_alerts_items:
        recent_alerts_items.append(ft.Text("No alerts detected yet.", size=12, color="#94A3B8"))

    recent_alerts_card = ft.Container(
        content=ft.Column([
            ft.Row([
                ft.Text("RECENT ALERTS", size=11, weight=ft.FontWeight.BOLD, color="#94A3B8"),
                ft.TextButton("View All", on_click=lambda e: app.nav_to("alerts")),
            ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
            ft.Column(recent_alerts_items, spacing=8),
        ]),
        bgcolor="#FFFFFF", border=ft.Border.all(1, "#E2E8F0"), border_radius=12, padding=16, expand=1,
    )

    return ft.Column([
        kpi_cards,
        chart_card,
        ft.Row([top_talkers_card, recent_alerts_card], spacing=14),
    ], spacing=14, scroll=ft.ScrollMode.AUTO, expand=True)
