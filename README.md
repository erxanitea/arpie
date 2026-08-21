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
│   ├── seal.py                 # firewall block/unblock + audit log
│   ├── report.py               # JSON/HTML/PDF export
│   └── ui.py                   # Flet dashboard
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

## Testing

```bash
pytest tests/ -v
```

All four detection rules are covered with synthetic Scapy packets, so
the suite runs anywhere (no live interface or admin rights needed).

## Building the standalone `.exe`

PyInstaller is already in `requirements.txt`. From the project root, on
a **Windows machine** (build the `.exe` on the OS you're targeting):

```bash
pyinstaller --name Arpie --onefile --windowed ^
  --add-data "arpie;arpie" ^
  main.py
```

- `--onefile` bundles everything into a single `Arpie.exe` in `dist/`
- `--windowed` suppresses the console window for the GUI (drop this flag if you want console output for debugging)
- On Linux/macOS, use `--add-data "arpie:arpie"` (colon instead of semicolon) to build platform-native equivalents

The finished executable will be at `dist/Arpie.exe`. Since Scapy needs
packet-capture drivers, make sure **Npcap** (https://npcap.com/) is
installed on the target Windows machine — it's a runtime dependency of
Scapy on Windows, not something PyInstaller can bundle.

For a GitHub Release, zip `dist/Arpie.exe` alongside a short `README`
and attach it to a tagged release rather than committing the binary
into the repo.

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
