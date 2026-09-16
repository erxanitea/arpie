"""Backward-compatible import shim for :mod:`arpie.infrastructure.notifications`."""

from .infrastructure.notifications import send_desktop_notification

__all__ = ["send_desktop_notification"]
