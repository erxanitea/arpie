import datetime
import threading
import flet as ft
from arpie.network import arp_sweep, mac_vendor, local_ipv4_and_cidr


def render_inventory_view(app) -> ft.Column:
    ctx = getattr(app, "network_context", None)
    if not ctx and hasattr(app, "refresh_network_context"):
        ctx = app.refresh_network_context()

    ssid_name = (ctx.ssid if ctx and ctx.ssid else None) or "Not connected"
    gw_ip = (ctx.gateway_ip if ctx and ctx.gateway_ip else None) or "Unknown"
    if ctx and not ctx.gateway_mac and gw_ip != "Unknown":
        from arpie.network.context import _get_gateway_mac
        found_mac = _get_gateway_mac(gw_ip)
        if found_mac:
            ctx.gateway_mac = found_mac

    gw_mac = (ctx.gateway_mac if ctx and ctx.gateway_mac else None) or "Resolving via ARP…"
    iface = (ctx.interface if ctx and ctx.interface else None) or "Unknown"
    cls = ctx.classification if ctx and ctx.classification else "unknown"

    local_ip = getattr(app, "local_ip", None) or "Unknown"
    if local_ip == "Unknown" and hasattr(app, "ensure_host_ip"):
        local_ip = app.ensure_host_ip() or "Unknown"
    subnet = getattr(app, "subnet_cidr", None) or "Unknown"

    is_trusted = (cls == "trusted")
    trust_label = "TRUSTED / PRIVATE NETWORK" if is_trusted else "PUBLIC / UNTRUSTED NETWORK"
    trust_bg = "#ECFDF5" if is_trusted else "#FEE2E2"
    trust_fg = "#10B981" if is_trusted else "#DC2626"
    trust_icon = ft.Icons.VERIFIED_USER_ROUNDED if is_trusted else ft.Icons.GPP_MAYBE_ROUNDED

    transport_label = "Wi-Fi infrastructure" if iface.lower().startswith(("wl", "wi", "ath")) else "Network interface"

    # --- Card 1: Network Context Assessment (Required Entity #3) ---
    def _context_cell(label: str, value: str, sub: str, icon) -> ft.Container:
        return ft.Container(
            content=ft.Row([
                ft.Container(
                    content=ft.Icon(icon, size=18, color="#0F172A"),
                    bgcolor="#F1F5F9", border_radius=8, padding=8,
                ),
                ft.Column([
                    ft.Text(label, size=10, weight=ft.FontWeight.BOLD, color="#64748B"),
                    ft.Text(value, size=13, weight=ft.FontWeight.BOLD, color="#0F172A"),
                    ft.Text(sub, size=10, color="#94A3B8"),
                ], spacing=1),
            ], spacing=10),
            bgcolor="#F8FAFC", border=ft.Border.all(1, "#E2E8F0"), border_radius=10, padding=12, expand=1,
        )

    context_card = ft.Container(
        content=ft.Column([
            ft.Row([
                ft.Row([
                    ft.Icon(ft.Icons.ROUTER_ROUNDED, color="#0F172A", size=22),
                    ft.Column([
                        ft.Text("Network Context Assessment", size=16, weight=ft.FontWeight.BOLD, color="#0F172A"),
                        ft.Text("Environmental trust evaluation, gateway bindings, and subnet parameters.", size=12, color="#64748B"),
                    ], spacing=1),
                ], spacing=10),
                ft.Container(
                    content=ft.Row([
                        ft.Icon(trust_icon, size=13, color=trust_fg),
                        ft.Text(trust_label, size=10, weight=ft.FontWeight.BOLD, color=trust_fg),
                    ], spacing=4),
                    bgcolor=trust_bg, border_radius=6, padding=ft.Padding.symmetric(horizontal=8, vertical=4),
                ),
            ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
            ft.Divider(color="#E2E8F0", height=12),
            ft.Row([
                _context_cell("SSID / NETWORK NAME", ssid_name, transport_label, ft.Icons.WIFI_ROUNDED),
                _context_cell("GATEWAY IP & MAC", f"{gw_ip} ({gw_mac})", "Observed gateway binding", ft.Icons.DNS_ROUNDED),
            ], spacing=12),
            ft.Row([
                _context_cell("SUBNET CIDR", subnet, "Local Broadcast Domain Scope", ft.Icons.HUB_ROUNDED),
                _context_cell("THIS ENDPOINT", local_ip, f"Use as simulator target · interface {iface}", ft.Icons.SPEED_ROUNDED),
            ], spacing=12),
        ], spacing=10),
        bgcolor="#FFFFFF", border=ft.Border.all(1, "#E2E8F0"), border_radius=12, padding=16,
    )

    # --- Card 2: Network Device Inventory (Required Entity #4) ---
    rows = [
        ft.DataRow(cells=[
            ft.DataCell(ft.Text(f"#{dev.get('id', str(idx + 1))}", size=12, weight=ft.FontWeight.BOLD, color="#64748B")),
            ft.DataCell(ft.Text(str(dev.get("hostname", f"Host-{idx+1}")), size=12, weight=ft.FontWeight.BOLD, color="#0F172A")),
            ft.DataCell(ft.Text(str(dev.get("ip", "Unknown")), size=12, weight=ft.FontWeight.W_600, color="#0F172A")),
            ft.DataCell(ft.Text(str(dev.get("mac", "Unknown")), size=12, color="#475569")),
            ft.DataCell(ft.Text(str(dev.get("vendor", "Unknown")), size=12, color="#475569")),
            ft.DataCell(ft.Text(str(dev.get("type", "Endpoint")), size=12, color="#0F172A")),
            ft.DataCell(
                ft.Container(
                    content=ft.Row([
                        ft.Container(
                            width=6, height=6, border_radius=3,
                            bgcolor="#0284C7" if "Gateway" in str(dev.get("status", "")) else ("#10B981" if "Endpoint" in str(dev.get("status", "")) else ("#DC2626" if "Untrusted" in str(dev.get("status", "")) or "Suspect" in str(dev.get("status", "")) else "#64748B")),
                        ),
                        ft.Text(
                            str(dev.get("status", "Active")), size=10, weight=ft.FontWeight.BOLD,
                            color="#0369A1" if "Gateway" in str(dev.get("status", "")) else ("#065F46" if "Endpoint" in str(dev.get("status", "")) else ("#991B1B" if "Untrusted" in str(dev.get("status", "")) or "Suspect" in str(dev.get("status", "")) else "#334155")),
                        ),
                    ], spacing=5),
                    bgcolor="#E0F2FE" if "Gateway" in str(dev.get("status", "")) else ("#ECFDF5" if "Endpoint" in str(dev.get("status", "")) else ("#FEE2E2" if "Untrusted" in str(dev.get("status", "")) or "Suspect" in str(dev.get("status", "")) else "#F1F5F9")),
                    border_radius=4, padding=ft.Padding.symmetric(horizontal=6, vertical=3),
                )
            ),
            ft.DataCell(ft.Text(str(dev.get("last_seen", "Recent")), size=12, color="#64748B")),
        ]) for idx, dev in enumerate(app.devices_inventory)
    ]

    table = ft.DataTable(
        columns=[
            ft.DataColumn(label=ft.Text("DeviceID", size=11, weight=ft.FontWeight.BOLD, color="#94A3B8")),
            ft.DataColumn(label=ft.Text("Hostname", size=11, weight=ft.FontWeight.BOLD, color="#94A3B8")),
            ft.DataColumn(label=ft.Text("IP Address", size=11, weight=ft.FontWeight.BOLD, color="#94A3B8")),
            ft.DataColumn(label=ft.Text("MAC Address", size=11, weight=ft.FontWeight.BOLD, color="#94A3B8")),
            ft.DataColumn(label=ft.Text("Vendor", size=11, weight=ft.FontWeight.BOLD, color="#94A3B8")),
            ft.DataColumn(label=ft.Text("Device Type", size=11, weight=ft.FontWeight.BOLD, color="#94A3B8")),
            ft.DataColumn(label=ft.Text("Status", size=11, weight=ft.FontWeight.BOLD, color="#94A3B8")),
            ft.DataColumn(label=ft.Text("Last Seen", size=11, weight=ft.FontWeight.BOLD, color="#94A3B8")),
        ],
        rows=rows,
        heading_row_height=42,
        data_row_min_height=48,
        data_row_max_height=52,
        column_spacing=26,
        horizontal_lines=ft.BorderSide(1, "#F1F5F9"),
        show_checkbox_column=False,
    )

    scan_status = ft.Text("", size=11, color="#64748B", visible=False)
    scan_spinner = ft.ProgressRing(width=16, height=16, stroke_width=2, visible=False)

    def do_scan(e):
        scan_status.value = "Scanning local subnet…"
        scan_status.visible = True
        scan_spinner.visible = True
        app.page.update()

        def _run():
            ctx = app.network_context
            iface = ctx.interface if ctx else None
            _, cidr = local_ipv4_and_cidr(iface)
            if not cidr:
                scan_status.value = "Scan unavailable: no subnet could be determined for this interface."
                scan_spinner.visible = False
                app.page.update()
                return

            hosts = arp_sweep(cidr, iface=iface, timeout=3)
            existing_ips = {d.get("ip") for d in app.devices_inventory if isinstance(d, dict) and d.get("ip")}
            now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
            added = 0
            for h in hosts:
                if h["ip"] not in existing_ips:
                    vendor = mac_vendor(h["mac"])
                    app.devices_inventory.append({
                        "id": str(len(app.devices_inventory) + 1),
                        "hostname": h["ip"],
                        "ip": h["ip"],
                        "mac": h["mac"],
                        "vendor": vendor,
                        "type": "Endpoint",
                        "status": "Discovered via ARP",
                        "last_seen": now,
                    })
                    added += 1

            scan_spinner.visible = False
            scan_status.value = f"Scan complete — {added} new host(s) discovered ({len(hosts)} total responded)"
            try:
                app.update_view_content()
                app.page.update()
            except Exception:
                pass

        threading.Thread(target=_run, daemon=True).start()

    inventory_card = ft.Container(
        content=ft.Column([
            ft.Row([
                ft.Row([
                    ft.Icon(ft.Icons.DEVICE_HUB_ROUNDED, color="#0F172A", size=20),
                    ft.Column([
                        ft.Text("Network Device Inventory", size=15, weight=ft.FontWeight.BOLD, color="#0F172A"),
                        ft.Text(
                            getattr(app, "scan_status", None) or f"Tracking {len(app.devices_inventory)} host(s) observed passively + via ARP sweep",
                            size=11, color="#64748B"),
                    ], spacing=1),
                ], spacing=8),
                ft.Button("Scan Local Subnet", icon=ft.Icons.REFRESH_ROUNDED, on_click=do_scan, style=ft.ButtonStyle(bgcolor="#DC2626", color="#FFFFFF", padding=10)),
            ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
            ft.Row([scan_spinner, scan_status], spacing=8, visible=True),
            ft.Divider(color="#E2E8F0", height=12),
            ft.Row([table], scroll=ft.ScrollMode.AUTO),
            ft.Divider(color="#F1F5F9", height=10),
            ft.Row([
                ft.Text(f"Showing {len(app.devices_inventory)} active endpoints", size=12, color="#94A3B8"),
                ft.Row([
                    ft.Icon(ft.Icons.SHIELD_OUTLINED, size=14, color="#10B981"),
                    ft.Text("MAC-IP bindings monitored in real-time for ARP spoofing", size=12, color="#64748B"),
                ], spacing=4),
            ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
        ]),
        bgcolor="#FFFFFF", border=ft.Border.all(1, "#E2E8F0"), border_radius=12, padding=16,
    )

    return ft.Column([
        context_card,
        inventory_card,
    ], spacing=14, scroll=ft.ScrollMode.AUTO)
