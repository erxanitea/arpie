import os
import flet as ft

_assets_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "assets"))
_new_logo = os.path.join(_assets_dir, "arpie-logo.png")
_default_logo = os.path.join(_assets_dir, "logo.png")
LOGO_PATH = _new_logo if os.path.exists(_new_logo) else _default_logo


SEVERITY_COLORS = {
    "low": "#10B981",
    "medium": "#F59E0B",
    "high": "#EF4444",
    "critical": "#DC2626",
    "info": "#06B6D4",
}

SEVERITY_BG = {
    "low": "#ECFDF5",
    "medium": "#FFFBEB",
    "high": "#FEF2F2",
    "critical": "#FEE2E2",
    "info": "#ECFEFF",
}

COLOR_PRIMARY = "#DC2626"
COLOR_PRIMARY_DARK = "#991B1B"
COLOR_BG_LIGHT = "#F8FAFC"
COLOR_BG_CARD = "#FFFFFF"
COLOR_TEXT_MAIN = "#0F172A"
COLOR_TEXT_MUTED = "#64748B"
COLOR_BORDER = "#E2E8F0"
COLOR_SIDEBAR_BG = "#0F172A"
COLOR_SIDEBAR_ACTIVE = "#1E293B"
