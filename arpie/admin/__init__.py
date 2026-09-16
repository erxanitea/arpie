"""Privileged operator-management policies for the Flet application."""

from .operator import can_manage_operators, can_manage_system_settings

__all__ = ["can_manage_operators", "can_manage_system_settings"]
