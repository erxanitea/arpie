import flet as ft


def make_filter_chip(label: str, is_selected: bool, on_click) -> ft.Container:
    return ft.Container(
        content=ft.Text(
            label,
            size=12,
            weight=ft.FontWeight.BOLD if is_selected else ft.FontWeight.W_500,
            color="#FFFFFF" if is_selected else "#475569",
        ),
        bgcolor="#0F172A" if is_selected else "#FFFFFF",
        border=ft.Border.all(1, "#0F172A" if is_selected else "#E2E8F0"),
        border_radius=20,
        padding=ft.Padding.symmetric(horizontal=14, vertical=6),
        on_click=on_click,
    )


def build_status_badge(text: str, color: str, bg_color: str) -> ft.Container:
    return ft.Container(
        content=ft.Text(text, size=11, weight=ft.FontWeight.BOLD, color=color),
        bgcolor=bg_color,
        border_radius=6,
        padding=ft.Padding.symmetric(horizontal=8, vertical=2),
    )


def build_kpi_card(
    title: str,
    value: str,
    subtitle: str = "",
    icon: str | ft.IconData = ft.Icons.INFO_OUTLINE_ROUNDED,  # type: ignore[assignment]
    icon_color: str = "#0F172A",
    border_color: str = "#E2E8F0",
    width: int | None = None,
) -> ft.Container:
    items: list[ft.Control] = [
        ft.Row([
            ft.Text(title, size=12, weight=ft.FontWeight.W_600, color="#64748B"),
            ft.Icon(icon, size=18, color=icon_color),  # type: ignore[arg-type]
        ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
        ft.Text(value, size=22, weight=ft.FontWeight.BOLD, color="#0F172A"),
    ]
    if subtitle:
        items.append(ft.Text(subtitle, size=11, color="#64748B"))

    return ft.Container(
        content=ft.Column(items, spacing=4),
        bgcolor="#FFFFFF",
        border=ft.Border.all(1, border_color),
        border_radius=12,
        padding=16,
        width=width,
        expand=True if width is None else False,
    )
