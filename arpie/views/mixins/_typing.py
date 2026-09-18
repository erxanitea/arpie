from __future__ import annotations
from typing import TYPE_CHECKING, Any, Protocol, Optional
import flet as ft

if TYPE_CHECKING:
    class AppProtocol(Protocol):
        page: ft.Page
        db: Any
        threat_intel: Any
        current_screen: str
        current_view: str
        user_role: str
        user_name: str
        operator_username: str
        operator_email: str
        operator_id: Optional[int]
        network_context: Any
        selected_profile: str
        detection_rules: dict[str, bool]
        thresholds: dict[str, str]
        selected_alert: Optional[dict]
        session_id: Optional[int]
        engine: Any
        seal_mgr: Any
        live_capture: Any
        capture_thread: Any
        capture_controller: Any
        auth_controller: Any
        report_controller: Any
        seal_controller: Any
        is_monitoring: bool
        monitoring_start_time: Optional[float]
        accumulated_seconds: float
        last_resume_time: float
        timer_thread: Any
        timer_running: bool
        threats_count: int
        alerts: list
        enrichments: dict
        active_blocks: list
        packets_count: int
        all_alerts_list: list
        top_talkers_data: list
        _ip_packet_counts: dict
        devices_inventory: list
        _known_device_macs: set
        packet_log_stream: list
        traffic_interval_sec: int
        traffic_history: list
        suspicious_history: list
        blocked_history: list
        traffic_timestamps: list
        _current_interval_total: int
        _current_interval_suspicious: int
        _current_interval_blocked: int
        _tick_counter: int
        dashboard_chart_slot: Any
        active_severity_filter: str
        search_query: str
        status_toast: str
        reports_dir: Any
        timer_text: Any
        sidebar_timer_text: Any
        sidebar_status_dot: Any
        sidebar_status_text: Any
        sidebar_btn_icon: Any
        sidebar_btn_text: Any
        sidebar_toggle_btn: Any
        sidebar_btn_refs: list
        content_area: Any
        top_bar_title: Any
        top_bar_subtitle: Any
        root_container: Any
        file_picker: Any

        def render(self) -> None: ...
        def update_view_content(self) -> None: ...
        def update_monitoring_ui(self) -> None: ...
        def _restore_session_from_db(self) -> None: ...
        def nav_to(self, vid: str) -> None: ...

    MixinBase = AppProtocol
else:
    MixinBase = object
