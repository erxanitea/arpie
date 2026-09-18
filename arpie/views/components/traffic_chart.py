import datetime
import flet as ft
import flet.canvas as cv


def build_spline_chart_content(app) -> ft.Column:
    num_pts = 12
    if hasattr(app, "traffic_timestamps") and app.traffic_timestamps:
        time_labels = list(app.traffic_timestamps)[-num_pts:]
        while len(time_labels) < num_pts:
            time_labels.insert(0, "--:--:--")
    else:
        now = datetime.datetime.now()
        step = max(1, getattr(app, "traffic_interval_sec", 1))
        time_labels = [
            (now - datetime.timedelta(seconds=(num_pts - 1 - i) * step)).strftime("%H:%M:%S")
            for i in range(num_pts)
        ]

    suspicious_vals = list(app.suspicious_history if app.suspicious_history else [0] * num_pts)[-num_pts:]
    total_vals = list(app.traffic_history if app.traffic_history else [0] * num_pts)[-num_pts:]
    blocked_vals = list(app.blocked_history if app.blocked_history else [0] * num_pts)[-num_pts:]

    while len(suspicious_vals) < num_pts:
        suspicious_vals.insert(0, 0)
    while len(total_vals) < num_pts:
        total_vals.insert(0, 0)
    while len(blocked_vals) < num_pts:
        blocked_vals.insert(0, 0)

    chart_w = 900
    chart_h = 200
    c_left = 60
    c_right = chart_w - 20
    c_top = 20
    c_bottom = chart_h - 30
    span_x = (c_right - c_left) / (len(time_labels) - 1)

    peak = max(max(suspicious_vals, default=0), max(total_vals, default=0), max(blocked_vals, default=0))
    if peak <= 10:
        y_max = 20
    elif peak <= 40:
        y_max = 50
    elif peak <= 80:
        y_max = 100
    elif peak <= 160:
        y_max = 200
    else:
        y_max = int(peak * 1.25)

    shapes: list[cv.Shape] = []

    for step_idx in range(5):
        y_val_raw = int(y_max * step_idx / 4)
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
                x_pos - 20, c_bottom + 8, label,
                style=ft.TextStyle(size=10, color="#94A3B8", weight=ft.FontWeight.W_600),
            )
        )

    canvas = cv.Canvas(shapes=shapes, width=chart_w, height=chart_h)

    return ft.Column([
        ft.Row([
            ft.Column([
                ft.Row([
                    ft.Text("Real-Time Traffic", size=16, weight=ft.FontWeight.BOLD, color="#0F172A"),
                ], vertical_alignment=ft.CrossAxisAlignment.CENTER),
                ft.Text("Packets / second timeline", size=12, color="#64748B", weight=ft.FontWeight.W_500),
            ], spacing=2),
            ft.Row([
                ft.Row([ft.Container(width=12, height=3, border_radius=2, bgcolor="#1E293B"), ft.Text("Total Traffic", size=11, weight=ft.FontWeight.W_600, color="#475569")], spacing=6),
                ft.Row([ft.Container(width=12, height=3, border_radius=2, bgcolor="#EF4444"), ft.Text("Suspicious Traffic", size=11, weight=ft.FontWeight.W_600, color="#475569")], spacing=6),
                ft.Row([ft.Container(width=12, height=3, border_radius=2, bgcolor="#0D9488"), ft.Text("Blocked Traffic", size=11, weight=ft.FontWeight.W_600, color="#475569")], spacing=6),
            ], spacing=14, vertical_alignment=ft.CrossAxisAlignment.CENTER),
        ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
        ft.Container(height=6),
        ft.Container(
            content=canvas,
            alignment=ft.Alignment(0, 0),
        ),
    ])


def build_spline_chart(app) -> ft.Container:
    container = ft.Container(
        content=build_spline_chart_content(app),
        bgcolor="#FFFFFF",
        border=ft.Border.all(1, "#E2E8F0"),
        border_radius=14,
        padding=18,
    )
    app.dashboard_chart_slot = container
    return container


__all__ = ["build_spline_chart", "build_spline_chart_content"]
