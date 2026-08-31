import datetime
import flet as ft


def render_inventory_view(app) -> ft.Column:
    rows = [
        ft.DataRow(cells=[
            ft.DataCell(ft.Text(dev["id"], size=12, color="#64748B")),
            ft.DataCell(ft.Text(dev["hostname"], size=12, weight=ft.FontWeight.BOLD, color="#0F172A")),
            ft.DataCell(ft.Text(dev["ip"], size=12, color="#0F172A")),
            ft.DataCell(ft.Text(dev["mac"], size=12, color="#475569")),
            ft.DataCell(ft.Text(dev["vendor"], size=12, color="#475569")),
            ft.DataCell(ft.Text(dev["type"], size=12, color="#0F172A")),
            ft.DataCell(ft.Container(
                content=ft.Text(dev["status"], size=10, weight=ft.FontWeight.BOLD, color="#10B981" if dev["status"] == "Trusted" else "#DC2626"),
                bgcolor="#ECFDF5" if dev["status"] == "Trusted" else "#FEE2E2",
                border_radius=4, padding=ft.Padding.symmetric(horizontal=6, vertical=2),
            )),
            ft.DataCell(ft.Text(dev["last_seen"], size=12, color="#64748B")),
        ]) for dev in app.devices_inventory
    ]

    table = ft.DataTable(
        columns=[
            ft.DataColumn(label=ft.Text("DeviceID", size=11, weight=ft.FontWeight.BOLD)),
            ft.DataColumn(label=ft.Text("Hostname", size=11, weight=ft.FontWeight.BOLD)),
            ft.DataColumn(label=ft.Text("IP Address", size=11, weight=ft.FontWeight.BOLD)),
            ft.DataColumn(label=ft.Text("MAC Address", size=11, weight=ft.FontWeight.BOLD)),
            ft.DataColumn(label=ft.Text("Vendor", size=11, weight=ft.FontWeight.BOLD)),
            ft.DataColumn(label=ft.Text("Device Type", size=11, weight=ft.FontWeight.BOLD)),
            ft.DataColumn(label=ft.Text("Status", size=11, weight=ft.FontWeight.BOLD)),
            ft.DataColumn(label=ft.Text("Last Seen", size=11, weight=ft.FontWeight.BOLD)),
        ],
        rows=rows,
        heading_row_height=40,
        data_row_min_height=42,
    )

    def do_scan(e):
        app.devices_inventory.append({
            "id": str(len(app.devices_inventory) + 1),
            "hostname": "Discovered-Node",
            "ip": f"192.168.1.{100 + len(app.devices_inventory)}",
            "mac": "54:E1:AD:77:88:99",
            "vendor": "Intel Corp.",
            "type": "Laptop",
            "status": "Trusted",
            "last_seen": datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
        })
        app.update_view_content()
        app.page.update()

    return ft.Column([
        ft.Container(
            content=ft.Column([
                ft.Row([
                    ft.Column([
                        ft.Text("Discovered Devices & MAC Bindings", size=18, weight=ft.FontWeight.BOLD, color="#0F172A"),
                        ft.Text(f"Tracking {len(app.devices_inventory)} active network endpoints on subnet.", size=12, color="#64748B"),
                    ], spacing=2),
                    ft.ElevatedButton("Scan Local Subnet", icon=ft.Icons.REFRESH_ROUNDED, on_click=do_scan, style=ft.ButtonStyle(bgcolor="#DC2626", color="#FFFFFF")),
                ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                ft.Divider(color="#E2E8F0", height=16),
                table,
            ]),
            bgcolor="#FFFFFF", border=ft.Border.all(1, "#E2E8F0"), border_radius=12, padding=20,
        )
    ], spacing=14, scroll=ft.ScrollMode.AUTO)
