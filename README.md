# Arpie - Endpoint Network Threat Defense

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey.svg)](https://github.com/erxanitea/arpie/releases)

**Protect your device on public Wi-Fi. Real-time detection. Instant containment. 100% local.**

Arpie is a local endpoint network intrusion detection and response station: a native desktop app that monitors your network connection, spots ARP spoofing, port scans, and gateway identity tampering in real time, and seals your machine off with one-click firewall containment—never sending your private traffic outside your device.

---

## Features

- 🖥️ **Native Desktop App** – Modern desktop interface built with Flutter/Flet featuring live telemetry, threat radar, and alert queues.
- 🛡️ **Multi-Vector Detection** – Real-time engine detecting ARP cache poisoning, gateway MAC changes, SYN/UDP/ICMP floods, and port scans.
- 🔒 **Instant Seal Mode** – Reversible, one-click host firewall isolation that cuts off attacker access while keeping local forensics active.
- 🧪 **Offline PCAP Replay** – Zero-privilege evaluation mode to replay and analyze packet captures without live network permissions.
- 🌐 **Privacy-First Threat Intel** – Optional public IP enrichment via AbuseIPDB and IPinfo; LAN and private packets never leave your machine.
- 📊 **Forensic Reports & History** – Tamper-evident SQLite session logging and 1-click exports to PDF, HTML, and JSON reports.
- ⌨️ **Full Terminal & CLI Support** – Run headless PCAP inspection and automated simulations directly from your shell.

---

## Requirements

| Component | Requirement | Notes |
|---|---|---|
| **OS** | Windows / Linux / macOS | Native standalone builds available for all three |
| **Privileges** | Optional (Live mode only) | **Zero privileges** needed for PCAP replay. Live packet sniffing and Seal Mode require Administrator / root |
| **Npcap** | Windows only | Required for live packet capture on Windows ([npcap.com](https://npcap.com/)) |
| **Python** | Developers only | End users do not need Python or Git installed—everything is bundled |

---

## Install

Download the latest version from the [Releases](https://github.com/erxanitea/arpie/releases) page:

### Windows
1. Download **`arpie-windows-setup.exe`** from [Releases](https://github.com/erxanitea/arpie/releases).
2. Run the installer (automatically adds Desktop and Start Menu shortcuts).
3. *(Optional)* A standalone portable archive (`arpie-windows.zip`) is also available.

### Linux
Install directly from your terminal (no `sudo` required):
```bash
curl -fsSL https://raw.githubusercontent.com/erxanitea/arpie/main/scripts/install.sh | bash
arpie
```
*Or download `arpie-linux.tar.gz` manually from [Releases](https://github.com/erxanitea/arpie/releases).*

### macOS
Download **`arpie-macos.tar.gz`** from [Releases](https://github.com/erxanitea/arpie/releases), unpack, and launch Arpie.

---

## First Run

1. **Launch Arpie** from your desktop shortcut or terminal (`arpie`).
2. **Try the Demo (No Admin Needed)**:
   - Navigate to the **Packet Logs** tab.
   - Click **Run Demo Capture**.
   - Watch the intrusion detection engine flag simulated ARP poisoning and port scans in real time.
3. **Explore Threats & Evidence**:
   - Inspect risk scores, forensic packet metadata, and explainable attack timelines.
4. **Live Monitoring (Public Wi-Fi)**:
   - When connected to a public network, launch with required system permissions (Run as Administrator on Windows, or elevated on Linux/macOS) to activate continuous live capture and Seal Mode.

---

## Developer Setup

For development, academic evaluation, or contributing:

```bash
git clone https://github.com/erxanitea/arpie.git
cd arpie
python3 -m venv .venv
source .venv/bin/activate  # In fish: source .venv/bin/activate.fish
pip install -r requirements.txt
python -m arpie
```

### Running Tests & Simulations

```bash
# Run test suite
pytest tests/ -v

# Run offline PCAP replay
python main.py --pcap sample_pcaps/demo_attack.pcap

# Run controlled attack simulation (requires privileges)
sudo python tools/simulate_attack.py --target <test-ip>
```

---

## Documentation

- 📖 [Live Demonstration Guide](docs/DEMO.md)
- 🚀 [Deployment & First-Run Notes](docs/DEPLOYMENT.md)
- 📦 [Packaging & Toolchains](docs/PACKAGING.md)
- 🏗️ [Architecture Overview](docs/ARCHITECTURE.md)
- 🔐 [Security & Threat Model](docs/SECURITY.md)
- 🗺️ [System Flowchart](FLOWCHART.md)

---

## License

[MIT](LICENSE) © Era Dumangcas