import json
import random
import time
from typing import Optional
from arpie.models import Database
from arpie.seeder.fixtures import REALISTIC_DEVICES, REALISTIC_SAMPLE_PACKETS


SEEDED_SOURCE = "seeder"


def is_seeded(db: Database) -> bool:
    if db.get_config("seeded_state") == "1":
        return True
    with db.cursor() as cur:
        cur.execute("SELECT COUNT(*) as cnt FROM sessions WHERE source = ?", (SEEDED_SOURCE,))
        row = cur.fetchone()
        return bool(row and row["cnt"] > 0)


def seed_database(db: Database, operator_id: Optional[int] = None, user_identifier: Optional[str] = "eradumangcas7@gmail.com") -> dict:
    if operator_id is None and user_identifier:
        op = db.get_operator(user_identifier)
        if op:
            operator_id = op["id"]
        else:
            ops = db.list_operators()
            if ops:
                operator_id = ops[0]["id"]

    unseed_database(db)

    now = time.time()
    seeded_sessions = []
    seeded_events = []

    s1_start = now - 600
    s1_id = db.start_session(
        ssid="Starbucks_Guest_WiFi",
        network_context="public-untrusted",
        interface="wlan0",
        source=SEEDED_SOURCE,
        operator_id=operator_id,
    )
    with db.cursor() as cur:
        cur.execute("UPDATE sessions SET started_at = ? WHERE id = ?", (s1_start, s1_id))

    e1 = db.log_event(
        session_id=s1_id,
        detection_type="arp_spoof",
        source_ip="192.168.1.50",
        target="192.168.1.1",
        severity="high",
        confidence=0.88,
        risk_score=68,
        evidence={
            "rule": "arp_inconsistency",
            "mitre": "T1557.002",
            "description": "Rogue MAC 3c:97:0e:12:34:56 poisoned default gateway IP 192.168.1.1 (Dual-MAC Inconsistency)",
            "known_mac": "00:50:56:c0:00:01",
            "rogue_mac": "3c:97:0e:12:34:56",
            "impact": "Hostile adversary intercepting Layer-2 subnet traffic",
        },
        recommended_action="Enable Seal Mode to enforce static ARP bindings or isolate offending host.",
    )
    with db.cursor() as cur:
        cur.execute("UPDATE events SET ts = ? WHERE id = ?", (s1_start + 120, e1))

    db.log_action(
        session_id=s1_id,
        event_id=e1,
        action="seal",
        target="192.168.1.50",
        confirmed_by_user=1,
        notes="Operator verified rogue ARP reply and engaged Seal Mode.",
    )

    e2 = db.log_event(
        session_id=s1_id,
        detection_type="port_scan",
        source_ip="192.168.1.50",
        target="192.168.1.15",
        severity="medium",
        confidence=0.82,
        risk_score=42,
        evidence={
            "rule": "port_scan_heuristic",
            "mitre": "T1046",
            "description": "Host 192.168.1.50 probed 28 distinct TCP/UDP destination ports in 4.8 seconds",
            "ports_probed": [21, 22, 23, 80, 443, 445, 3389, 8080, 8443],
            "probe_rate_pps": 5.8,
        },
        recommended_action="Isolate scanning source from broadcast domain and review firewall logs.",
    )
    with db.cursor() as cur:
        cur.execute("UPDATE events SET ts = ? WHERE id = ?", (s1_start + 300, e2))

    e3 = db.log_event(
        session_id=s1_id,
        detection_type="traffic_anomaly",
        source_ip="192.168.1.50",
        target="192.168.1.1",
        severity="high",
        confidence=0.91,
        risk_score=72,
        evidence={
            "rule": "pps_threshold_exceeded",
            "mitre": "T1498",
            "description": "Traffic burst of 145 pps from host 192.168.1.50 exceeded threshold (100 pps, SYN flood pattern)",
            "measured_pps": 145,
            "threshold_pps": 100,
        },
        recommended_action="Apply rate-limiting filter on upstream switch or host firewall.",
    )
    with db.cursor() as cur:
        cur.execute("UPDATE events SET ts = ? WHERE id = ?", (s1_start + 650, e3))

    seeded_sessions.append(s1_id)
    seeded_events.extend([e1, e2, e3])

    s2_start = now - 18000
    s2_id = db.start_session(
        ssid="Airport_Terminal4_Free",
        network_context="public-untrusted",
        interface="wlan0",
        source=SEEDED_SOURCE,
        operator_id=operator_id,
    )
    with db.cursor() as cur:
        cur.execute("UPDATE sessions SET started_at = ?, ended_at = ? WHERE id = ?", (s2_start, s2_start + 3600, s2_id))

    e4 = db.log_event(
        session_id=s2_id,
        detection_type="gateway_change",
        source_ip="192.168.1.1",
        target="192.168.1.1",
        severity="critical",
        confidence=0.94,
        risk_score=88,
        evidence={
            "rule": "gateway_identity_transition",
            "mitre": "T1557",
            "description": "Default router MAC changed unexpectedly from Cisco (00:50:56:c0:00:01) to Intel (3c:97:0e:12:34:56)",
            "prev_mac": "00:50:56:c0:00:01",
            "new_mac": "3c:97:0e:12:34:56",
        },
        recommended_action="Disconnect immediately; possible Evil Twin or rogue access point deployment.",
    )
    with db.cursor() as cur:
        cur.execute("UPDATE events SET ts = ? WHERE id = ?", (s2_start + 450, e4))

    seeded_sessions.append(s2_id)
    seeded_events.append(e4)

    s3_start = now - 86400
    s3_id = db.start_session(
        ssid="Corporate_HQ_Secure",
        network_context="trusted",
        interface="eth0",
        source=SEEDED_SOURCE,
        operator_id=operator_id,
    )
    with db.cursor() as cur:
        cur.execute("UPDATE sessions SET started_at = ?, ended_at = ? WHERE id = ?", (s3_start, s3_start + 7200, s3_id))
    seeded_sessions.append(s3_id)

    db.cache_ip(
        ip="185.220.101.5",
        abuse_confidence_score=100,
        country="Germany",
        asn="AS208298",
        isp="Zwiebelfreunde e.V.",
        raw_json=json.dumps({"is_tor": True, "total_reports": 1420}),
    )
    db.cache_ip(
        ip="45.33.32.156",
        abuse_confidence_score=45,
        country="United States",
        asn="AS63949",
        isp="Linode, LLC",
        raw_json=json.dumps({"is_tor": False, "total_reports": 38}),
    )

    db.set_config("snapshot_devices", json.dumps(REALISTIC_DEVICES))
    db.set_config("snapshot_packets", "14250")
    packet_log_snapshot = []
    for index, packet in enumerate(REALISTIC_SAMPLE_PACKETS):
        packet_log_snapshot.append({
            "ts": time.strftime("%H:%M:%S", time.localtime(now - (len(REALISTIC_SAMPLE_PACKETS) - index) * 3)),
            "src": packet[0],
            "dst": packet[1],
            "proto": packet[2],
            "src_mac": packet[3],
            "dst_mac": packet[4],
            "len": packet[5],
        })
    db.set_config("snapshot_packet_log", json.dumps(packet_log_snapshot))
    db.set_config("snapshot_traffic", json.dumps([18, 24, 32, 45, 98, 142, 110, 65, 40, 28, 35, 42]))
    db.set_config("snapshot_top_talkers", json.dumps([
        {"ip": "192.168.1.50", "packets": 8420, "pct": "59.1%"},
        {"ip": "192.168.1.15", "packets": 3210, "pct": "22.5%"},
        {"ip": "192.168.1.1", "packets": 1820, "pct": "12.8%"},
        {"ip": "192.168.1.105", "packets": 800, "pct": "5.6%"},
    ]))
    db.set_config("seeded_state", "1")

    return {
        "status": "seeded",
        "operator_id": operator_id,
        "sessions_count": len(seeded_sessions),
        "events_count": len(seeded_events),
        "sessions": seeded_sessions,
    }


def unseed_database(db: Database) -> dict:
    with db.cursor() as cur:
        cur.execute("SELECT id FROM sessions WHERE source = ?", (SEEDED_SOURCE,))
        sids = [r["id"] for r in cur.fetchall()]

        if sids:
            placeholders = ",".join("?" for _ in sids)
            cur.execute(f"DELETE FROM actions WHERE session_id IN ({placeholders})", sids)
            cur.execute(f"DELETE FROM events WHERE session_id IN ({placeholders})", sids)
            cur.execute(f"DELETE FROM sessions WHERE source = ?", (SEEDED_SOURCE,))

        cur.execute("DELETE FROM threat_intel_cache WHERE ip IN ('185.220.101.5', '45.33.32.156')")

    db.set_config("snapshot_devices", "")
    db.set_config("snapshot_packets", "")
    db.set_config("snapshot_packet_log", "")
    db.set_config("snapshot_traffic", "")
    db.set_config("snapshot_top_talkers", "")
    db.set_config("seeded_state", "0")

    return {"status": "cleared", "removed_sessions": len(sids) if sids else 0}


def seed_active_app_state(app):
    if not is_seeded(app.db):
        db_result = seed_database(app.db, operator_id=app.operator_id)
    else:
        db_result = {"status": "already_seeded"}

    app.all_alerts_list = [
        {
            "id": 101,
            "time": time.strftime("%H:%M:%S", time.localtime(time.time() - 140)),
            "type": "ARP Identity Inconsistency",
            "severity": "HIGH",
            "source": "192.168.1.50",
            "status": "NEW",
            "fg": "#DC2626",
            "bg": "#FEE2E2",
            "desc": "Rogue MAC 3C:97:0E:12:34:56 poisoned default gateway IP 192.168.1.1 (Dual-MAC Inconsistency)",
            "action": "Enable Seal Mode or verify gateway BSSID anchor",
            "mitre": "T1557.002",
            "confidence": 0.88,
            "risk_score": 68,
            "evidence": {
                "detected_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() - 140)),
                "rule": "arp_inconsistency",
                "known_mac": "00:50:56:c0:00:01",
                "rogue_mac": "3c:97:0e:12:34:56",
            },
            "seeded": True,
        },
        {
            "id": 102,
            "time": time.strftime("%H:%M:%S", time.localtime(time.time() - 320)),
            "type": "Port-Scan Behavior",
            "severity": "MEDIUM",
            "source": "192.168.1.50",
            "status": "REVIEW",
            "fg": "#D97706",
            "bg": "#FEF3C7",
            "desc": "Host 192.168.1.50 probed 28 distinct TCP/UDP ports in 4.8 seconds (Reconnaissance pattern)",
            "action": "Isolate scanning source and inspect exposed ports",
            "mitre": "T1046",
            "confidence": 0.82,
            "risk_score": 42,
            "evidence": {
                "detected_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() - 320)),
                "rule": "port_scan_heuristic",
                "ports_count": 28,
            },
            "seeded": True,
        },
        {
            "id": 103,
            "time": time.strftime("%H:%M:%S", time.localtime(time.time() - 580)),
            "type": "Traffic-Rate Anomaly",
            "severity": "HIGH",
            "source": "192.168.1.50",
            "status": "ACK",
            "fg": "#DC2626",
            "bg": "#FEE2E2",
            "desc": "Traffic burst of 145 pps exceeded public Wi-Fi threshold (100 pps, SYN flood profile)",
            "action": "Engage temporary rate-limiting firewall filter",
            "mitre": "T1498",
            "confidence": 0.91,
            "risk_score": 72,
            "evidence": {
                "detected_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() - 580)),
                "rule": "pps_threshold_exceeded",
                "measured_pps": 145,
            },
            "seeded": True,
        },
    ]

    app.threats_count = len(app.all_alerts_list)

    app.devices_inventory = []
    for idx, dev in enumerate(REALISTIC_DEVICES):
        dev_copy: dict[str, object] = dict(dev)
        dev_copy["id"] = str(idx + 1)
        dev_copy["last_seen"] = time.strftime("%Y-%m-%d %H:%M:%S")
        dev_copy["seeded"] = True
        app.devices_inventory.append(dev_copy)

    app.traffic_history = [18, 24, 32, 45, 98, 142, 110, 65, 40, 28, 35, 42]
    app.suspicious_history = [0, 0, 1, 2, 8, 14, 10, 3, 1, 0, 1, 2]
    app.blocked_history = [0, 0, 0, 1, 4, 8, 6, 2, 0, 0, 0, 1]
    app.packets_count = 14250

    app._ip_packet_counts = {
        "192.168.1.50": 8420,
        "192.168.1.15": 3210,
        "192.168.1.1": 1820,
        "192.168.1.105": 800,
    }
    app._rebuild_top_talkers()

    app.packet_log_stream = []
    for ep in REALISTIC_SAMPLE_PACKETS:
        now_str = time.strftime("%H:%M:%S") + f".{random.randint(100, 999)}"
        app.packet_log_stream.append({
            "ts": now_str,
            "src": ep[0],
            "dst": ep[1],
            "proto": ep[2],
            "src_mac": ep[3],
            "dst_mac": ep[4],
            "len": ep[5],
        })

    app.status_toast = "Seeded realistic evaluation dataset (3 sessions, 3 alerts, 6 subnet endpoints)."
    app.update_view_content()
    if app.page:
        app.page.update()

    return db_result


def clear_active_app_state(app):
    res = unseed_database(app.db)
    app._ip_packet_counts.clear()
    app._rebuild_top_talkers()
    app.status_toast = f"Cleared all seeded evaluation data ({res['removed_sessions']} audit sessions purged)."
    app.update_view_content()
    if app.page:
        app.page.update()
    return res
