# Arpie 🦭 — Context-Aware Endpoint Network Intrusion Detection and Threat-Response System for Public Wi-Fi

*Your Cyber-Detective Seal. Safe. Secure. Sealed.*

Arpie is a lightweight endpoint NIDS for students, remote/hybrid workers, and
SOHO users who connect to public or unfamiliar Wi-Fi without dedicated IT
support. It classifies the current network, passively monitors traffic,
applies deterministic detection rules, enriches findings with threat
intelligence, and produces explainable, evidence-based alerts — with a
reversible, user-confirmed "Seal Mode" to block a suspicious host.

> Built for IT21 (Information Assurance and Security 2).

## Features

- **Network-context classification** — trusted / public-untrusted / unknown
- **4 deterministic detection rules**
  - ARP Identity Inconsistency (spoofing/MITM)
  - Port-Scan Behavior
  - Traffic-Rate Anomaly (SYN/UDP/ICMP floods)
  - Gateway Identity Change (rogue gateway / route hijack)
- **Threat-intel enrichment** — AbuseIPDB reputation + IPinfo Lite geo/ASN, cached locally in SQLite
- **Transparent 0–100 session risk score**
- **Seal Mode** — reversible, user-confirmed temporary firewall rule with auto-restore, manual Unseal, and full audit log
- **Exportable session reports** — JSON, HTML, PDF
- **Live capture or PCAP replay** — same detection pipeline either way, so runs and tests are repeatable

## Project layout

```
arpie/
├── main.py                    # entry point (GUI or --pcap CLI mode)
├── requirements.txt
├── arpie/
│   ├── config.py               # thresholds, Seal Mode, threat-intel config
│   ├── db.py                   # SQLite schema + storage
│   ├── network_context.py      # SSID / gateway / classification
│   ├── capture.py              # live sniff + PCAP replay
│   ├── detection/
│   │   ├── __init__.py         # Alert type + DetectionEngine
│   │   ├── arp_spoof.py
│   │   ├── port_scan.py
│   │   ├── traffic_anomaly.py
│   │   └── gateway_change.py
│   ├── threat_intel.py         # AbuseIPDB + IPinfo Lite + caching
│   ├── risk.py                 # heuristic scoring
│   ├── seal.py                 # firewall block/unblock + audit log + crash reconcile
│   ├── report.py               # JSON/HTML/PDF export
│   ├── discovery.py            # local IP/subnet, ARP-sweep host enumeration, OUI lookup
│   └── ui/                     # Flet desktop app (app shell + views/ + components/)
└── tests/
    ├── conftest.py
    ├── test_detection.py
    └── test_risk.py
```

## Setup

```bash
git clone https://github.com/<your-username>/arpie.git
cd arpie
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### API keys (optional but recommended)

Threat-intel enrichment needs free API keys. Set them as environment
variables before running (never commit real keys):

```bash
export ABUSEIPDB_API_KEY="your_key_here"     # https://www.abuseipdb.com/account/api
export IPINFO_API_KEY="your_key_here"        # https://ipinfo.io/signup
```

Without keys, Arpie still runs fully — enrichment is simply skipped and
detection/scoring/Seal Mode work unaffected.

### Privileges

- **Live capture** needs raw-socket access: run as Administrator (Windows) or with `sudo` (Linux/macOS).
- **Seal Mode** needs firewall-modification rights for the same reason (`netsh advfirewall` on Windows, `iptables` on Linux).
- Neither is required to explore the app in **PCAP replay** mode.

## Running

**Desktop app:**
```bash
python main.py
```

**Headless CLI (PCAP replay, no admin rights needed):**
```bash
python main.py --pcap sample_pcaps/your_capture.pcap
```

### Live two-device demo

To see Arpie detect a **real** attacker device on the same network — the full
presentation flow, including which IP the attacker targets and how to respond
with Seal Mode — follow **[docs/DEMO.md](docs/DEMO.md)**. No second device on
hand? The **Engine Self-Test** button and PCAP replay drive the identical
detection pipeline.

> **Scope, stated honestly:** Arpie is an *endpoint* IDS — a layer-2 trust
> monitor (ARP/gateway) plus a detector for scans/floods **aimed at this host**.
> On modern WPA2/WPA3 Wi-Fi an endpoint cannot see other clients' encrypted
> traffic, and Arpie does not pretend to. Every alert, device, and metric in the
> UI reflects real observation.

## Testing

```bash
pytest tests/ -v
```

All four detection rules are covered with synthetic Scapy packets, so
the suite runs anywhere (no live interface or admin rights needed).

## Building a downloadable binary

The GUI is a Flet app; the modern Flet build path (`flet build <os>`), the
headless-CLI PyInstaller path, and the runtime prerequisites (elevation, Npcap
on Windows, code signing, privacy) are all documented in
**[docs/PACKAGING.md](docs/PACKAGING.md)**. Prefer attaching built binaries to a
tagged GitHub Release over committing them to the repo.

## Notes on design choices

- **Flet, not Flask** — Arpie is a local desktop monitoring tool, not a web
  service, so a native desktop UI framework fits the real-time alerting
  use case better than a server-rendered web app.
- **Deterministic rules over ML** — every alert is traceable to specific
  evidence (which IPs, which ports, which counts), matching the
  proposal's requirement for explainable alerts rather than an opaque
  classifier score.
- **Seal Mode never fires automatically** — it always requires explicit
  user confirmation, by design, since blocking a host is a disruptive
  action a user should consciously choose.

## System Architecture & Specifications

For the comprehensive system architecture diagram, component specifications, and use case interactions (covering both End User and Evaluator / Administrator roles), see:
- [System Flow & Evaluation Guide](FLOWCHART.md) — Comprehensive flowchart, use case mappings, and assessment reference.
- [System Architecture Specification](docs/system_architecture.md)
- [PlantUML Architecture Diagram](docs/system_architecture.puml)



## License

[MIT](LICENSE). The bundled attack simulator is for authorized testing of
networks you own or are permitted to test.
