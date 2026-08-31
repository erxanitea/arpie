import flet as ft
from ..components.dialogs import show_seal_dialog


def render_seal_view(app) -> ft.Column:
    def do_lockdown(e):
        show_seal_dialog(app)

    block_items: list[ft.Control] = []
    for ip in app.active_blocks:
        block_items.append(
            ft.Container(
                content=ft.Row([
                    ft.Row([
                        ft.Icon(ft.Icons.BLOCK_ROUNDED, color="#DC2626", size=18),
                        ft.Column([
                            ft.Text(f"Hostile Attacker: {ip}", size=14, weight=ft.FontWeight.BOLD, color="#0F172A"),
                            ft.Text("Rule: DROP ALL INBOUND/OUTBOUND (iptables -A INPUT -s ... -j DROP)", size=12, color="#64748B"),
                        ], spacing=2)
                    ], spacing=10),
                    ft.OutlinedButton("Unblock", icon=ft.Icons.LOCK_OPEN_ROUNDED, on_click=lambda e, rip=ip: app.unblock_ip(rip)),
                ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                padding=14, border=ft.Border.all(1, "#FECACA"), border_radius=8, bgcolor="#FEF2F2",
            )
        )

    return ft.Column([
        ft.Container(
            content=ft.Column([
                ft.Row([
                    ft.Column([
                        ft.Text("Endpoint Seal Mode Threat Mitigation", size=20, weight=ft.FontWeight.BOLD, color="#0F172A"),
                        ft.Text("Automated and reversible host isolation using iptables/netsh.", size=13, color="#64748B"),
                    ], spacing=2),
                    ft.ElevatedButton(
                        content=ft.Row([
                            ft.Icon(ft.Icons.LOCK_ROUNDED, color="#FFFFFF", size=18),
                            ft.Text("Activate Emergency Seal", size=13, weight=ft.FontWeight.BOLD, color="#FFFFFF"),
                        ], spacing=6),
                        style=ft.ButtonStyle(bgcolor="#DC2626", shape=ft.RoundedRectangleBorder(radius=8), padding=14),
                        on_click=do_lockdown,
                    )
                ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                ft.Divider(color="#E2E8F0", height=16),
                ft.Row([
                    ft.Container(
                        content=ft.Column([
                            ft.Text("ACTIVE CONTAINMENT RULES", size=11, weight=ft.FontWeight.BOLD, color="#94A3B8"),
                            ft.Text(f"{len(app.active_blocks)} Blocked IPs", size=20, weight=ft.FontWeight.BOLD, color="#DC2626"),
                            ft.Text("Host isolation is active and dropping suspicious ingress/egress.", size=12, color="#64748B"),
                        ], spacing=4),
                        bgcolor="#FEF2F2", border=ft.Border.all(1, "#FECACA"), border_radius=10, padding=16, expand=1,
                    ),
                    ft.Container(
                        content=ft.Column([
                            ft.Text("FIREWALL STATE", size=11, weight=ft.FontWeight.BOLD, color="#94A3B8"),
                            ft.Text("Reversible & Safe", size=20, weight=ft.FontWeight.BOLD, color="#10B981"),
                            ft.Text("All routing tables restore automatically on session teardown.", size=12, color="#64748B"),
                        ], spacing=4),
                        bgcolor="#ECFDF5", border=ft.Border.all(1, "#A7F3D0"), border_radius=10, padding=16, expand=1,
                    )
                ], spacing=16),
                ft.Divider(color="#E2E8F0", height=16),
                ft.Text("Currently Isolated Hosts", size=14, weight=ft.FontWeight.BOLD, color="#0F172A"),
                ft.Column(block_items if block_items else [ft.Text("No active host blocks currently applied.", size=13, color="#64748B")], spacing=10),
            ], spacing=12),
            bgcolor="#FFFFFF", border=ft.Border.all(1, "#E2E8F0"), border_radius=12, padding=24,
        )
    ], spacing=14, scroll=ft.ScrollMode.AUTO)
