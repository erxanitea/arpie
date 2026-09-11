import flet as ft


def render_inventory_view(app) -> ft.Column:
    ctx = app.network_context
    ssid_name = (ctx.ssid if ctx and ctx.ssid else None) or "Not connected"
    gw_ip = (ctx.gateway_ip if ctx and ctx.gateway_ip else None) or "Unknown"
    gw_mac = (ctx.gateway_mac if ctx and ctx.gateway_mac else None) or "Resolving via ARP…"
    iface = (ctx.interface if ctx and ctx.interface else None) or "Unknown"
    cls = ctx.classification if ctx and ctx.classification else "unknown"
    subnet = app.subnet_cidr or "Unknown"
    local_ip = app.local_ip or "Unknown"

    is_trusted = (cls == "trusted")
    trust_label = "TRUSTED / PRIVATE NETWORK" if is_trusted else "PUBLIC / UNTRUSTED NETWORK"
    trust_bg = "#ECFDF5" if is_trusted else "#FEE2E2"
    trust_fg = "#10B981" if is_trusted else "#DC2626"
    trust_icon = ft.Icons.VERIFIED_USER_ROUNDED if is_trusted else ft.Icons.GPP_MAYBE_ROUNDED

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
                _context_cell("SSID / NETWORK NAME", ssid_name, "802.11 Wi-Fi Infrastructure", ft.Icons.WIFI_ROUNDED),
                _context_cell("GATEWAY IP & MAC", f"{gw_ip} ({gw_mac})", "Validated Default Gateway Binding", ft.Icons.DNS_ROUNDED),
            ], spacing=12),
            ft.Row([
                _context_cell("SUBNET CIDR", subnet, "Local Broadcast Domain Scope", ft.Icons.HUB_ROUNDED),
                _context_cell("THIS ENDPOINT (attacker --target)", local_ip, f"Interface {iface}", ft.Icons.SPEED_ROUNDED),
            ], spacing=12),
        ], spacing=10),
        bgcolor="#FFFFFF", border=ft.Border.all(1, "#E2E8F0"), border_radius=12, padding=16,
    )

    # --- Card 2: Network Device Inventory (Required Entity #4) ---
    rows = [
        ft.DataRow(cells=[
            ft.DataCell(ft.Text(f"#{dev['id']}", size=12, weight=ft.FontWeight.BOLD, color="#64748B")),
            ft.DataCell(ft.Text(dev["hostname"], size=12, weight=ft.FontWeight.BOLD, color="#0F172A")),
            ft.DataCell(ft.Text(dev["ip"], size=12, weight=ft.FontWeight.W_600, color="#0F172A")),
            ft.DataCell(ft.Text(dev["mac"], size=12, color="#475569")),
            ft.DataCell(ft.Text(dev["vendor"], size=12, color="#475569")),
            ft.DataCell(ft.Text(dev["type"], size=12, color="#0F172A")),
            ft.DataCell(
                ft.Container(
                    content=ft.Row([
                        ft.Container(
                            width=6, height=6, border_radius=3,
                            bgcolor="#0284C7" if "Gateway" in dev["status"] else ("#10B981" if "Endpoint" in dev["status"] else ("#DC2626" if "Untrusted" in dev["status"] or "Suspect" in dev["status"] else "#64748B")),
                        ),
                        ft.Text(
                            dev["status"], size=10, weight=ft.FontWeight.BOLD,
                            color="#0369A1" if "Gateway" in dev["status"] else ("#065F46" if "Endpoint" in dev["status"] else ("#991B1B" if "Untrusted" in dev["status"] or "Suspect" in dev["status"] else "#334155")),
                        ),
                    ], spacing=5),
                    bgcolor="#E0F2FE" if "Gateway" in dev["status"] else ("#ECFDF5" if "Endpoint" in dev["status"] else ("#FEE2E2" if "Untrusted" in dev["status"] or "Suspect" in dev["status"] else "#F1F5F9")),
                    border_radius=4, padding=ft.Padding.symmetric(horizontal=6, vertical=3),
                )
            ),
            ft.DataCell(ft.Text(dev["last_seen"], size=12, color="#64748B")),
        ]) for dev in app.devices_inventory
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

    def do_scan(e):
        app.scan_subnet()

    inventory_card = ft.Container(
        content=ft.Column([
            ft.Row([
                ft.Row([
                    ft.Icon(ft.Icons.DEVICE_HUB_ROUNDED, color="#0F172A", size=20),
                    ft.Column([
                        ft.Text("Network Device Inventory", size=15, weight=ft.FontWeight.BOLD, color="#0F172A"),
                        ft.Text(
                            app.scan_status or f"Tracking {len(app.devices_inventory)} host(s) observed passively + via ARP sweep",
                            size=11, color="#64748B"),
                    ], spacing=1),
                ], spacing=8),
                ft.ElevatedButton("Scan Local Subnet", icon=ft.Icons.REFRESH_ROUNDED, on_click=do_scan, style=ft.ButtonStyle(bgcolor="#DC2626", color="#FFFFFF", padding=10)),
            ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
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
