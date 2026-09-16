"""Backward-compatible import shim for :mod:`arpie.network.context`."""

from .network.context import NetworkContext, classify_network, detect_network_context

__all__ = ["NetworkContext", "classify_network", "detect_network_context"]