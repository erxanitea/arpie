import ast
import datetime
import flet as ft
from arpie.infrastructure.threat_intel import is_public_ip


def build_evidence_drawer(app, alert_item: dict, on_close, on_seal) -> ft.Container:
    today_date = datetime.datetime.now().strftime("%Y-%m-%d")
    sel_type = alert_item.get("type", "Security Event")
    sel_sev = alert_item.get("severity", "HIGH")
    sel_src = alert_item.get("source", "Unknown")
    sel_target = alert_item.get("target", "Local Endpoint")
    raw_desc = alert_item.get("desc", "No description available.")
    sel_fg = alert_item.get("fg", "#DC2626")
    sel_bg = alert_item.get("bg", "#FEE2E2")
    sel_time = alert_item.get("time", "")
    sel_date = alert_item.get("date", today_date)
    confidence = alert_item.get("confidence")
    confidence_text = f"{float(confidence) * 100:.0f}%" if isinstance(confidence, (int, float)) else "N/A"

    evidence = alert_item.get("evidence")
    if not isinstance(evidence, dict) and isinstance(raw_desc, str) and (raw_desc.startswith("{") or raw_desc.startswith("{'")):
        try:
            parsed = ast.literal_eval(raw_desc)
            if isinstance(parsed, dict):
                evidence = parsed
        except Exception:
            pass

    clean_desc = raw_desc
    if isinstance(evidence, dict):
        clean_desc = (
            evidence.get("reason")
            or evidence.get("description")
            or alert_item.get("action")
            or raw_desc
        )

    evidence_chips = []
    if isinstance(evidence, dict):
        if "macs_observed" in evidence:
            mac_str = ", ".join(evidence["macs_observed"])
            evidence_chips.append(
                ft.Row([
                    ft.Text("Observed MACs:", size=11, color="#64748B", weight=ft.FontWeight.W_500),
                    ft.Text(mac_str, size=11, color="#0F172A", weight=ft.FontWeight.BOLD, selectable=True),
                ], spacing=4)
            )
        if "window_seconds" in evidence:
            evidence_chips.append(
                ft.Row([
                    ft.Text("Evaluation Window:", size=11, color="#64748B", weight=ft.FontWeight.W_500),
                    ft.Text(f"{evidence['window_seconds']}s", size=11, color="#0F172A", weight=ft.FontWeight.BOLD),
                ], spacing=4)
            )
        if "unique_ports_contacted" in evidence:
            evidence_chips.append(
                ft.Row([
                    ft.Text("Contacted Ports:", size=11, color="#64748B", weight=ft.FontWeight.W_500),
                    ft.Text(str(evidence["unique_ports_contacted"]), size=11, color="#0F172A", weight=ft.FontWeight.BOLD),
                ], spacing=4)
            )

    enrichment = getattr(app, "enrichments", {}).get(sel_src)
    abuse_score = getattr(enrichment, "abuse_confidence_score", None) if enrichment else None
    country = getattr(enrichment, "country", None) if enrichment else None
    asn = getattr(enrichment, "asn", None) if enrichment else None
    is_public = is_public_ip(sel_src) if sel_src and sel_src != "Unknown" else False

    triage_statuses = ["NEW", "ACKNOWLEDGED", "RESOLVED", "FALSE POSITIVE"]
    current_status = alert_item.get("status", "NEW").upper()
    if current_status not in triage_statuses:
        current_status = "NEW"

    def on_status_change(e):
        new_val = e.control.value
        alert_item["status"] = new_val
        ev_id = alert_item.get("id")
        if ev_id and hasattr(app, "db") and hasattr(app.db, "update_event_status"):
            app.db.update_event_status(ev_id, new_val)
        if hasattr(app, "page") and app.page:
            app.page.update()

    status_dropdown = ft.Dropdown(
        value=current_status,
        options=[ft.dropdown.Option(s) for s in triage_statuses],
        height=32,
        text_size=11,
        content_padding=ft.Padding.symmetric(horizontal=8, vertical=4),
        border_color="#CBD5E1",
        border_radius=6,
        on_select=on_status_change,
    )

    threat_intel_content: list[ft.Control] = []
    if not is_public:
        threat_intel_content = [
            ft.Row([
                ft.Icon(ft.Icons.ROUTER_ROUNDED, size=15, color="#64748B"),
                ft.Text("Threat Intelligence", size=12, weight=ft.FontWeight.BOLD, color="#0F172A"),
            ], spacing=6),
            ft.Row([
                ft.Text("IP Scope:", size=11, color="#64748B"),
                ft.Container(
                    content=ft.Text("Local RFC 1918 Subnet", size=10, weight=ft.FontWeight.BOLD, color="#0284C7"),
                    bgcolor="#E0F2FE", border_radius=4, padding=ft.Padding.symmetric(horizontal=6, vertical=2),
                ),
            ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
            ft.Text(
                "External intelligence feeds (AbuseIPDB/IPinfo) evaluate public WAN IPs. Private LAN addresses are kept local to protect network privacy.",
                size=10, color="#64748B",
            ),
        ]
    else:
        threat_intel_content = [
            ft.Row([
                ft.Icon(ft.Icons.TRAVEL_EXPLORE_ROUNDED, size=15, color="#0F172A"),
                ft.Text("Threat Intelligence", size=12, weight=ft.FontWeight.BOLD, color="#0F172A"),
            ], spacing=6),
            ft.Row([
                ft.Text("Abuse Confidence Score:", size=11, color="#64748B"),
                ft.Container(
                    content=ft.Text(
                        f"{abuse_score}% reported abuse" if abuse_score is not None else "N/A — unverified",
                        size=10, weight=ft.FontWeight.BOLD, color="#DC2626" if abuse_score else "#64748B",
                    ),
                    bgcolor="#FEE2E2" if abuse_score else "#F1F5F9",
                    border_radius=4, padding=ft.Padding.symmetric(horizontal=6, vertical=2),
                ),
            ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
            ft.Row([
                ft.Text("Autonomous System:", size=11, color="#64748B"),
                ft.Text(
                    " · ".join(value for value in (asn, country) if value) or "N/A — unverified",
                    size=11, weight=ft.FontWeight.W_500, color="#0F172A",
                ),
            ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
        ]

    return ft.Container(
        content=ft.Column([
            ft.Row([
                ft.Row([
                    ft.Icon(ft.Icons.SAVED_SEARCH_ROUNDED, color="#0F172A", size=20),
                    ft.Column([
                        ft.Text("Incident Evidence Details", size=14, weight=ft.FontWeight.BOLD, color="#0F172A"),
                        ft.Text("Deterministic Heuristic Proof Metrics", size=10, color="#64748B"),
                    ], spacing=1),
                ], spacing=8),
                ft.IconButton(ft.Icons.CLOSE_ROUNDED, icon_size=18, tooltip="Close Inspector", on_click=on_close),
            ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
            ft.Divider(color="#E2E8F0", height=10),
            ft.Container(
                content=ft.Column([
                    ft.Row([
                        ft.Text(sel_type, size=13, weight=ft.FontWeight.BOLD, color="#0F172A"),
                        ft.Container(
                            content=ft.Text(sel_sev, size=9, weight=ft.FontWeight.BOLD, color=sel_fg),
                            bgcolor=sel_bg, border_radius=4, padding=ft.Padding.symmetric(horizontal=6, vertical=2),
                        ),
                    ], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
                    ft.Text(f"Detected on {sel_date} at {sel_time}", size=11, color="#64748B"),
                    ft.Text(clean_desc, size=12, color="#334155"),
                    *([ft.Divider(color="#E2E8F0", height=6)] + evidence_chips if evidence_chips else []),
                ], spacing=6),
                bgcolor="#F8FAFC", border=ft.Border.all(1, "#E2E8F0"), border_radius=8, padding=12,
            ),
            ft.Column([
                ft.Row([
                    ft.Column([
                        ft.Text("Source Host (Attacker)", size=10, color="#64748B", weight=ft.FontWeight.BOLD),
                        ft.Text(sel_src, size=13, weight=ft.FontWeight.BOLD, color="#DC2626"),
                    ], spacing=2, expand=1),
                    ft.Column([
                        ft.Text("Target Endpoint", size=10, color="#64748B", weight=ft.FontWeight.BOLD),
                        ft.Text(sel_target, size=13, weight=ft.FontWeight.BOLD, color="#0F172A"),
                    ], spacing=2, expand=1),
                ]),
                ft.Row([
                    ft.Column([
                        ft.Text("Heuristic Certainty", size=10, color="#64748B", weight=ft.FontWeight.BOLD),
                        ft.Text(f"{confidence_text} rule confidence", size=12, weight=ft.FontWeight.BOLD, color="#0284C7"),
                    ], spacing=2, expand=1),
                    ft.Column([
                        ft.Text("Triage Status", size=10, color="#64748B", weight=ft.FontWeight.BOLD),
                        status_dropdown,
                    ], spacing=2, expand=1),
                ], vertical_alignment=ft.CrossAxisAlignment.CENTER),
            ], spacing=10),
            ft.Divider(color="#F1F5F9", height=8),
            ft.Container(
                content=ft.Column(threat_intel_content, spacing=6),
                bgcolor="#F8FAFC", border=ft.Border.all(1, "#E2E8F0"), border_radius=8, padding=10,
            ),
            ft.Container(height=4),
            ft.Button(
                content=ft.Row([
                    ft.Icon(ft.Icons.SHIELD_ROUNDED, color="#FFFFFF", size=16),
                    ft.Text("1-Click Seal Mode: Isolate Host", size=12, weight=ft.FontWeight.BOLD, color="#FFFFFF"),
                ], alignment=ft.MainAxisAlignment.CENTER, spacing=6),
                style=ft.ButtonStyle(
                    bgcolor="#DC2626",
                    shape=ft.RoundedRectangleBorder(radius=8),
                    padding=ft.Padding.symmetric(vertical=12),
                ),
                on_click=on_seal,
                width=350,
            ),
        ], spacing=10, scroll=ft.ScrollMode.AUTO),
        width=380,
        bgcolor="#FFFFFF",
        border=ft.Border.all(1, "#E2E8F0"),
        border_radius=12,
        padding=16,
        shadow=ft.BoxShadow(spread_radius=1, blur_radius=16, color="#0F172A0D"),
    )

