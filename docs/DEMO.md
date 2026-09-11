# Arpie — Live Two-Device Demonstration Runbook

This is the script for presenting Arpie as a **real, working tool**: one machine
runs Arpie and truly detects attacks launched from a second (attacker) device on
the same network. Every alert you see is produced by the real detection engine
from real packets — there is no scripted/fake data in the UI.

---

## What you need

| Role | Device | Software |
|------|--------|----------|
| **Defender** | Your laptop (Arpie host) | Arpie, run with admin/root |
| **Attacker** | A second laptop/phone-with-Termux/VM | Python + Scapy + `tools/simulate_attack.py` |
| **Network** | One Wi-Fi AP or a phone hotspot both devices join | — |

> A dedicated hotspot or a cheap travel router is ideal for a presentation: you
> control it, it's isolated, and client-isolation won't interfere. A VirtualBox
> **host-only / internal network** between two VMs also works and is the most
> reproducible option for a classroom.

### Why the attacker must target the Arpie host directly

An endpoint on WPA2/WPA3 Wi-Fi only sees traffic **addressed to it** plus
**broadcast**. That is exactly enough for Arpie's threat model:

- **ARP spoofing** and **gateway MAC change** are broadcast/directed → always visible.
- **Port scan** and **traffic flood** are only visible when aimed **at the Arpie host**.

So the attacker script targets the Arpie host's IP. This is honest and correct —
Arpie is an *endpoint* IDS, not a whole-network tap.

---

## Step 1 — Start Arpie (Defender machine)

```bash
# Linux/macOS — raw capture + Seal Mode need root
sudo -E python main.py

# Windows — run the terminal "as Administrator" (needs Npcap installed)
python main.py
```

1. Register the first account as **Evaluator/Administrator** (first run) — this
   role unlocks the self-test button, PCAP replay, and threshold tuning.
2. On the **Network Context** screen, confirm the classification and click
   **Continue → Start Monitoring**.
3. Read the **top bar**: it shows **`This host: <IP>`**. That IP is the attacker's
   `--target`. The **Network** view also shows it, plus the detected **Gateway IP**
   (the attacker's `--gateway`) and the **Subnet CIDR**.

Live capture is now running. The dashboard timers, packet counter, packet log,
and Top Talkers will begin moving with **real** traffic.

## Step 2 — Prepare the Attacker machine

Copy `tools/simulate_attack.py` (and install Scapy) onto the second device:

```bash
pip install scapy
```

## Step 3 — Launch attacks (Attacker machine)

Use the IPs Arpie showed you:

```bash
sudo python tools/simulate_attack.py --target <ARPIE_HOST_IP> --gateway <GATEWAY_IP>
```

Menu options map 1:1 to Arpie's four detection rules:

| Option | Attack | Arpie should show |
|--------|--------|-------------------|
| 1 | ARP Identity Inconsistency | **ARP Spoof** alert (HIGH), gateway flagged *Suspect* in Network view |
| 2 | Port-Scan (>15 ports) | **Port Scan** alert (MEDIUM/HIGH) |
| 3 | Traffic-Rate Anomaly (SYN burst) | **Traffic Anomaly** alert, spike on the traffic chart |
| 4 | Gateway Identity Change | **Gateway Change** alert (CRITICAL) |
| 5 | **Full 4-stage narrative** | all of the above; **Session Risk climbs toward CRITICAL** |

For the main demo beat, run **option 5**. Watch Arpie:

- **Dashboard** — Session Risk rises, Active Alerts increments, the Suspicious
  Traffic line spikes, Top Talkers shows the attacker IP dominating.
- A native **desktop notification** fires for each detection.
- **Alerts** view — click any row to open the **Evidence** drawer (conflicting
  MACs / scanned ports / pps), with real threat-intel (or "N/A — local host"
  for LAN attackers, which is the honest answer).

## Step 4 — Respond live (Defender machine)

1. In **Alerts** → open the attacker's alert → **1-Click Seal Mode: Isolate Host**
   (or use **Seal Mode → Activate Emergency Seal**).
2. Arpie applies a reversible `iptables` / `netsh` DROP rule for that host and
   lists it under **Currently Isolated Hosts**.
3. Click **Unblock** to reverse it. Every seal/unseal is written to the audit log.
4. Go to **Reports** → **Export Active PDF/HTML/JSON** to produce the forensic
   session report on the spot.

## Step 5 — No second device? Use the Engine Self-Test

If Wi-Fi is uncooperative or you have one machine, click **⚡ Engine Self-Test**
(top bar, Evaluator role). It crafts **real Scapy attack packets and pushes them
through the exact same detection pipeline** — the detections are genuine engine
output, not canned alerts. You can also replay a capture: **Packet Logs →
Replay PCAP** on `sample_pcaps/demo_attack.pcap`.

---

## Talking points (what makes this defensible)

- **Deterministic, explainable rules** — every alert cites the exact evidence
  (which MACs, which ports, measured pps). No black-box ML to hand-wave.
- **Same pipeline everywhere** — live capture, PCAP replay, and the self-test all
  feed one `DetectionEngine`; that's why it's reproducible and testable
  (`pytest tests/ -v`, 21 tests).
- **Honest scope** — Arpie is a **layer-2 trust monitor + host-directed attack
  detector for the local broadcast domain**. It does not claim to see other
  clients' encrypted traffic, because on modern Wi-Fi no endpoint can.
- **Safety** — Seal Mode is reversible, user-confirmed, auto-restores, and any
  rule stranded by a crash is cleared on next startup.

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| No packets / counter stuck at 0 | Not running as root/admin, or wrong interface — set `ARPIE_IFACE`. |
| ARP/gateway alerts fire but not scan/flood | Attacker `--target` isn't the Arpie host IP. |
| "Seal failed … requires admin/root" | Run Arpie elevated; Seal edits the firewall. |
| Attacker packets don't arrive | AP has **client isolation** on — use your own hotspot / travel router / VM network. |
| No threat-intel geo/ASN | Expected for LAN IPs; set API keys in **Settings** for public IPs. |
