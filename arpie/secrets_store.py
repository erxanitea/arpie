"""Backward-compatible import shim for :mod:`arpie.security.secrets_store`."""

from .security.secrets_store import available, delete_secret, get_secret, set_secret

__all__ = ["available", "delete_secret", "get_secret", "set_secret"]
