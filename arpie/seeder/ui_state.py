"""Apply seeded database snapshots to the Flet application state."""

import time

from .fixtures import REALISTIC_DEVICES, REALISTIC_SAMPLE_PACKETS
from .service import is_seeded, seed_database, unseed_database


def seed_active_app_state(app):
    """Seed the database, then project its demo snapshots into the UI."""
    if not is_seeded(app.db):
        result = seed_database(app.db, operator_id=app.operator_id)
    else:
        result = {"status": "already_seeded"}

    app._restore_session_from_db()
    app.devices_inventory = []
    for index, device in enumerate(REALISTIC_DEVICES, start=1):
        item = dict(device)
        item["id"] = str(index)
        item["last_seen"] = time.strftime("%Y-%m-%d %H:%M:%S")
        item["seeded"] = True
        app.devices_inventory.append(item)

    app.packet_log_stream = []
    for source, target, protocol, source_mac, target_mac, length in REALISTIC_SAMPLE_PACKETS:
        app.packet_log_stream.append({
            "ts": time.strftime("%H:%M:%S"),
            "src": source,
            "dst": target,
            "proto": protocol,
            "src_mac": source_mac,
            "dst_mac": target_mac,
            "len": length,
        })

    app.status_toast = "Seeded realistic evaluation dataset."
    app.update_view_content()
    if app.page:
        app.page.update()
    return result


def clear_active_app_state(app):
    """Clear seeded database records and reset demo-only UI state."""
    result = unseed_database(app.db)
    app.all_alerts_list = [item for item in app.all_alerts_list if not item.get("seeded")]
    app.devices_inventory = [item for item in app.devices_inventory if not item.get("seeded")]
    app.traffic_history = [0] * 12
    app.suspicious_history = [0] * 12
    app.blocked_history = [0] * 12
    app.packets_count = 0
    app.threats_count = len(app.all_alerts_list)
    app.packet_log_stream = []
    app._ip_packet_counts.clear()
    app._rebuild_top_talkers()
    app.status_toast = f"Cleared seeded evaluation data ({result['removed_sessions']} audit sessions purged)."
    app.update_view_content()
    if app.page:
        app.page.update()
    return result
