"""
Views — one module per screen. Each exposes a ``render_*`` function that takes the
application and returns a Flet control tree.

Views render and forward user intent to ``arpie.controllers``. They do not query
the database, scan the network, or touch the firewall.
"""
