"""
Views — one module per screen. Each exposes a ``render_*`` function that takes the
application and returns a Flet control tree.
"""

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

__all__ = [
    "render_alerts_view",
    "render_context_screen",
    "render_dashboard_view",
    "render_inventory_view",
    "render_login_screen",
    "render_mfa_challenge_screen",
    "render_packets_view",
    "render_profile_screen",
    "render_register_screen",
    "render_reports_view",
    "render_seal_view",
    "render_settings_view",
    "render_users_view",
]
