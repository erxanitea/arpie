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
├── main.py                  # packaging entry point (flet pack / pyinstaller)
├── arpie/
│   ├── __main__.py          # canonical entry: python -m arpie
│   ├── cli.py               # headless --pcap mode, or launch the desktop UI
│   ├── config/              # Configuration — settings + detection thresholds
│   ├── models/              # Models — entities and the only SQL in the codebase
│   ├── controllers/         # Controllers — workflow orchestration
│   ├── views/               # Views — one module per screen
│   ├── templates/           # Templates — app shell, theme, components, dialogs
│   ├── forms/               # Forms — pure input validators
│   ├── admin/               # Admin — privileged-operator policy
│   ├── middleware/          # Middleware — roles, sessions, MFA
│   ├── detection/           # the four NIDS rules + engine (core domain)
│   ├── domain/              # pure business rules (risk scoring)
│   ├── network/             # context classification, ARP sweep
│   ├── security/            # Seal Mode, OS keyring
│   ├── integrations/        # AbuseIPDB / IPinfo enrichment
│   ├── infrastructure/      # packet capture, desktop notifications
│   ├── reporting/           # JSON / HTML / PDF export
│   └── seeder/              # demo fixtures
├── tests/                   # pytest suite
├── tools/                   # PCAP generator, attack simulation
├── lab/                     # Vagrant lab environment
├── sample_pcaps/            # demo PCAP files
├── assets/                  # logo and documentation PDFs
├── docs/                    # architecture, security, packaging, demo
└── .github/workflows/       # CI & release automation
```

See [docs/PROJECT_STRUCTURE.md](docs/PROJECT_STRUCTURE.md) for what each layer
owns and how it maps onto the Django structural layers, and
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the target state and remaining
migration phases.

## Setup

```bash
git clone https://github.com/<your-username>/arpie.git
cd arpie
python -m venv .venv
# Bash / Zsh
source .venv/bin/activate
# fish
source .venv/bin/activate.fish
# Windows: .venv\Scripts\activate
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

## Risk Scoring

Arpie uses a **transparent, auditable heuristic** (no black-box ML) so every
point in the 0–100 score is traceable to a specific alert or enrichment fact.

### Per-alert score

Each alert's score is the sum of three (optionally four) components:

| Component | Values | Max |
|-----------|--------|-----|
| **Severity weight** | low = 5, medium = 15, high = 30, critical = 45 | 45 |
| **Detection-type weight** | gateway_change = 15, arp_spoof = 10, traffic_anomaly = 5, port_scan = 5 | 15 |
| **Confidence factor** | `confidence × 20` (confidence is 0.0–1.0) | 20 |
| **Threat-intel bonus** | `AbuseIPDB score × 0.2` (only when enrichment is available) | 20 |

The result is clamped to **0–100**.

### Session risk score

The session-level score aggregates all alerts:
1. Start with the **highest** individual alert score.
2. Add a **diversity bonus**: `min(20, (distinct_detection_types − 1) × 8)` —
   multiple independent signal types (e.g. ARP spoof *and* gateway change) are
   more concerning than a single repeated alert type.
3. Clamp to **0–100**.

### Risk bands

| Score | Band |
|-------|------|
| 75–100 | 🔴 Critical |
| 50–74 | 🟠 High |
| 25–49 | 🟡 Medium |
| 0–24 | 🟢 Low |

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

## System Architecture & Specifications

For the comprehensive system architecture diagram, component specifications, and use case interactions (covering both End User and Evaluator / Administrator roles), see:
- [System Flow & Evaluation Guide](FLOWCHART.md) — Comprehensive flowchart, use case mappings, and assessment reference.
- [System Architecture Specification](docs/system_architecture.md)
- [PlantUML Architecture Diagram](docs/system_architecture.puml)


