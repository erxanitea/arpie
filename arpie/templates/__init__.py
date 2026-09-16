import flet as ft

if not hasattr(ft, "ElevatedButton"):
    setattr(ft, "ElevatedButton", ft.Button)

from .app import ArpieApp


def main(page: ft.Page):
    ArpieApp(page)


def run():
    ft.run(main, view=ft.AppView.FLET_APP)


__all__ = ["ArpieApp", "main", "run"]
