import flet as ft
from pathlib import Path
from arpie.middleware import can_manage_operators


def render_packets_view(app) -> ft.Column:
    is_evaluator = can_manage_operators(app)

    rows = [
        ft.DataRow(cells=[
            ft.DataCell(ft.Text(p["ts"], size=11, color="#64748B")),
            ft.DataCell(ft.Text(p["src"], size=12, weight=ft.FontWeight.W_600, color="#0F172A")),
            ft.DataCell(ft.Text(p["dst"], size=12, color="#0F172A")),
            ft.DataCell(ft.Container(
                content=ft.Text(p["proto"], size=10, weight=ft.FontWeight.BOLD, color="#DC2626" if "ARP" in p["proto"] else "#0284C7"),
                bgcolor="#FEF2F2" if "ARP" in p["proto"] else "#E0F2FE",
                border_radius=4, padding=ft.Padding.symmetric(horizontal=6, vertical=2),
            )),
            ft.DataCell(ft.Text(p["src_mac"], size=11, color="#64748B")),
            ft.DataCell(ft.Text(p["dst_mac"], size=11, color="#64748B")),
            ft.DataCell(ft.Text(p["len"], size=12, color="#475569")),
        ]) for p in app.packet_log_stream
    ]

    table = ft.DataTable(
        columns=[
            ft.DataColumn(label=ft.Text("Timestamp", size=11, weight=ft.FontWeight.BOLD)),
            ft.DataColumn(label=ft.Text("Source IP", size=11, weight=ft.FontWeight.BOLD)),
            ft.DataColumn(label=ft.Text("Dest IP", size=11, weight=ft.FontWeight.BOLD)),
            ft.DataColumn(label=ft.Text("Protocol", size=11, weight=ft.FontWeight.BOLD)),
            ft.DataColumn(label=ft.Text("Source MAC", size=11, weight=ft.FontWeight.BOLD)),
            ft.DataColumn(label=ft.Text("Dest MAC", size=11, weight=ft.FontWeight.BOLD)),
            ft.DataColumn(label=ft.Text("Length", size=11, weight=ft.FontWeight.BOLD)),
        ],
        rows=rows,
        heading_row_height=40,
        data_row_min_height=38,
    )

    content_items: list[ft.Control] = []
    if is_evaluator:
        demo_pcap = str(Path("sample_pcaps") / "demo_attack.pcap")
        pcap_input = ft.TextField(
            label="Offline PCAP Attack Replay (Evaluator Tool)",
            value=demo_pcap,
            dense=True,
            expand=True,
            border_radius=8,
        )

        def do_replay(e):
            app.run_pcap_replay(pcap_input.value or demo_pcap)

        def run_demo(e):
            app.run_pcap_replay(demo_pcap)

        content_items.extend([
            ft.Row([
                ft.Icon(ft.Icons.SCHOOL_ROUNDED, color="#0284C7", size=18),
                ft.Text("Use the bundled attack capture for a repeatable product demonstration. Results are labeled as demo replay data.", size=12, color="#475569"),
            ], spacing=8),
            ft.Row([
                pcap_input,
                ft.Button("Run Demo Capture", icon=ft.Icons.PLAY_CIRCLE_FILL_ROUNDED, on_click=run_demo, style=ft.ButtonStyle(bgcolor="#0F766E", color="#FFFFFF")),
                ft.Button("Replay PCAP File", icon=ft.Icons.PLAY_CIRCLE_FILL_ROUNDED, on_click=do_replay, style=ft.ButtonStyle(bgcolor="#DC2626", color="#FFFFFF")),
            ], spacing=12),
            ft.Divider(color="#E2E8F0", height=16),
        ])
    else:
        content_items.extend([
            ft.Row([
                ft.Icon(ft.Icons.STREAM_ROUNDED, color="#0284C7", size=20),
                ft.Column([
                    ft.Text("Live Packet Sniffing Stream", size=15, weight=ft.FontWeight.BOLD, color="#0F172A"),
                    ft.Text("Real-time passive packet inspection across your active network interface.", size=12, color="#64748B"),
                ], spacing=1),
            ], spacing=10),
            ft.Divider(color="#E2E8F0", height=16),
        ])

    content_items.append(table)

    return ft.Column([
        ft.Container(
            content=ft.Column(content_items),
            bgcolor="#FFFFFF", border=ft.Border.all(1, "#E2E8F0"), border_radius=12, padding=20,
        )
    ], spacing=14, scroll=ft.ScrollMode.AUTO)
