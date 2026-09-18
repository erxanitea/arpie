import flet as ft

from arpie.views.alerts import render_alerts_view
from arpie.views.context import render_context_screen
from arpie.views.dashboard import render_dashboard_view
from arpie.views.inventory import render_inventory_view
from arpie.views.login import render_login_screen
from arpie.views.mfa import render_mfa_challenge_screen
from arpie.views.packets import render_packets_view
from arpie.views.profile import render_profile_screen
from arpie.views.register import render_register_screen
from arpie.views.reports import render_reports_view
from arpie.views.seal import render_seal_view
from arpie.views.settings import render_settings_view
from arpie.views.users import render_users_view
from arpie.views.components.sidebar import build_sidebar
from arpie.views.components.topbar import build_topbar
from arpie.views.mixins._typing import MixinBase


class NavigationMixin(MixinBase):
    """Screen routing, sidebar/topbar assembly, and per-view render dispatch."""

    def render(self):
        if self.current_screen == "register":
            self.root_container.content = render_register_screen(self)
        elif self.current_screen == "login":
            self.root_container.content = render_login_screen(self)
        elif self.current_screen == "mfa_challenge":
            self.root_container.content = render_mfa_challenge_screen(self)
        elif self.current_screen == "context":
            self.root_container.content = render_context_screen(self)
        elif self.current_screen == "profile":
            self.root_container.content = render_profile_screen(self)
        elif self.current_screen == "app_shell":
            if not self.all_alerts_list and not self.devices_inventory:
                self._restore_session_from_db()
            self.root_container.content = self._build_app_shell()
            self.update_view_content()
        self.page.update()

    def go_to_context(self):
        self.current_screen = "context"
        self.render()

    def _build_app_shell(self):
        sidebar = build_sidebar(self)
        top_bar = build_topbar(self)

        main_area = ft.Container(
            content=ft.Column([
                top_bar,
                self.content_area,
            ], spacing=0, expand=True),
            expand=True,
            bgcolor="#F8FAFC",
        )

        return ft.Row([sidebar, main_area], expand=True, spacing=0)

    def nav_to(self, vid: str):
        self.current_view = vid
        self.update_view_content()
        self.page.update()

    def update_view_content(self):
        title_map = {
            "dashboard": ("Dashboard", "Real-time overview of your network and security status"),
            "alerts": ("Alerts", "All detected security events for this monitoring session"),
            "inventory": ("Network", "Network context assessment and discovered device inventory"),
            "packets": ("Packet Capture Logs", "Live inspection and recorded packet stream replay"),
            "seal": ("Seal Mode Mitigation", "Reversible endpoint threat response and network isolation"),
            "reports": ("Forensic Reports", "Automated incident reports, threat summaries, and exports"),
            "users": ("User Accounts", "Registered system operators and RBAC role assignments"),
            "settings": ("System Configuration", "Heuristic thresholds, threat intel feeds, and rules"),
        }
        title, subtitle = title_map.get(self.current_view, ("Arpie", ""))
        self.top_bar_title.value = title
        self.top_bar_subtitle.value = subtitle

        for vid, btn, icon_ctrl, text_ctrl, icon_on, icon_off in self.sidebar_btn_refs:
            is_active = (self.current_view == vid)
            btn.bgcolor = "#1E293B" if is_active else "transparent"
            icon_ctrl.name = icon_on if is_active else icon_off
            icon_ctrl.color = "#FFFFFF" if is_active else "#94A3B8"
            text_ctrl.color = "#FFFFFF" if is_active else "#94A3B8"
            text_ctrl.weight = ft.FontWeight.W_600 if is_active else ft.FontWeight.W_500

        view_map = {
            "dashboard": render_dashboard_view,
            "alerts": render_alerts_view,
            "inventory": render_inventory_view,
            "packets": render_packets_view,
            "seal": render_seal_view,
            "reports": render_reports_view,
            "users": render_users_view,
            "settings": render_settings_view,
        }
        render_fn = view_map.get(self.current_view)
        if render_fn:
            try:
                self.content_area.content = render_fn(self)
            except Exception as exc:
                import traceback
                traceback.print_exc()
                self.content_area.content = ft.Column([
                    ft.Icon(ft.Icons.ERROR_OUTLINE_ROUNDED, color="#DC2626", size=48),
                    ft.Text(f"Render error: {exc}", size=14, color="#DC2626"),
                ], horizontal_alignment=ft.CrossAxisAlignment.CENTER, alignment=ft.MainAxisAlignment.CENTER, expand=True)

    def update_monitoring_ui(self):
        is_mon = self.is_monitoring
        self.sidebar_status_dot.bgcolor = "#10B981" if is_mon else "#64748B"
        self.sidebar_status_text.value = "ACTIVE" if is_mon else "PAUSED"
        self.sidebar_status_text.color = "#10B981" if is_mon else "#94A3B8"
        self.sidebar_btn_icon.icon = ft.Icons.STOP_ROUNDED if is_mon else ft.Icons.PLAY_ARROW_ROUNDED
        self.sidebar_btn_text.value = "Stop Monitoring" if is_mon else "Resume"
        self.sidebar_toggle_btn.style = ft.ButtonStyle(
            bgcolor="#DC2626" if is_mon else "#10B981",
            shape=ft.RoundedRectangleBorder(radius=6),
        )
        try:
            if self.sidebar_status_dot.page is not None:
                self.sidebar_status_dot.update()
            if self.sidebar_status_text.page is not None:
                self.sidebar_status_text.update()
            if self.sidebar_toggle_btn.page is not None:
                self.sidebar_toggle_btn.update()
        except Exception:
            pass

    def logout(self):
        if self.is_monitoring:
            self.is_monitoring = False
            self.timer_running = False
        self.accumulated_seconds = 0.0
        self.last_resume_time = 0.0
        self.timer_text.value = "00:00:00"
        self.sidebar_timer_text.value = "00:00:00"
        self.update_monitoring_ui()
        if self.live_capture:
            try:
                self.live_capture.stop()
            except Exception:
                pass
            self.live_capture = None
        if self.session_id:
            try:
                self.db.end_session(self.session_id)
            except Exception:
                pass
            self.session_id = None
        self.operator_id = None
        self.operator_username = ""
        self.operator_email = ""
        self.user_name = ""
        self.user_role = "End User"
        self.status_toast = ""
        self._pending_operator = None
        self.current_screen = "login"
        self.render()

    def set_severity_filter(self, label: str):
        self.active_severity_filter = label
        self.update_view_content()
        self.page.update()

    def on_search_change(self, val: str):
        self.search_query = val
        self.update_view_content()
        self.page.update()

    @property
    def is_evaluator(self) -> bool:
        return self.user_role == "Evaluator/Administrator"

    def toggle_rule(self, k: str, val: bool):
        if not self.is_evaluator:
            return
        self.detection_rules[k] = val

    def set_threshold(self, k: str, val: str):
        if not self.is_evaluator:
            return
        self.thresholds[k] = val

    def open_dialog(self, dlg: ft.AlertDialog):
        self.page.show_dialog(dlg)

    def close_dialog(self, dlg: ft.AlertDialog):
        self.page.pop_dialog()
