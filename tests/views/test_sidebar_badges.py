from typing import cast
from unittest.mock import MagicMock

import flet as ft

from arpie.views.components.sidebar import build_sidebar
from arpie.views.mixins.navigation_mixin import NavigationMixin


class DummyApp(NavigationMixin):
    def __init__(self):
        self.current_view = "dashboard"
        self.all_alerts_list = []
        self.active_blocks = []
        self.sidebar_btn_refs = []
        self.sidebar_badge_refs = {}
        self.status_toast = ""
        self.user_name = "Admin"
        self.operator_username = "admin"
        self.user_role = "Evaluator/Administrator"
        self.sidebar_status_dot = ft.Container()
        self.sidebar_status_text = ft.Text("")
        self.sidebar_timer_text = ft.Text("")
        self.sidebar_toggle_btn = ft.Container()
        self.top_bar_title = ft.Text("")
        self.top_bar_subtitle = ft.Text("")
        self.toast_banner = ft.Container()
        self.toast_text = ft.Text("")
        self.toast_icon = ft.Icon(ft.Icons.CHECK_CIRCLE_ROUNDED)
        self.content_area = ft.Container()
        self.page = cast(ft.Page, MagicMock())

    def _restore_session_from_db(self) -> None:
        pass

    def refresh_network_context(self) -> None:
        pass


def test_sidebar_badges_reflect_exact_counts():
    app = DummyApp()
    build_sidebar(app)

    assert "alerts" in app.sidebar_badge_refs
    assert "seal" in app.sidebar_badge_refs
    assert app.sidebar_badge_refs["alerts"].value == "0"
    assert app.sidebar_badge_refs["seal"].value == "0"

    app.all_alerts_list.extend([{"id": 1}, {"id": 2}, {"id": 3}])
    app.active_blocks.append("192.168.1.100")
    app.update_view_content()

    assert app.sidebar_badge_refs["alerts"].value == "3"
    assert app.sidebar_badge_refs["seal"].value == "1"

    app.all_alerts_list.clear()
    app.active_blocks.clear()
    app.update_view_content()

    assert app.sidebar_badge_refs["alerts"].value == "0"
    assert app.sidebar_badge_refs["seal"].value == "0"
