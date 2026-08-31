import flet as ft
from .app import ArpieApp


def main(page: ft.Page):
    ArpieApp(page)


def run():
    ft.app(target=main, view=ft.AppView.FLET_APP)  # type: ignore[deprecated]


__all__ = ["ArpieApp", "main", "run"]
