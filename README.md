# Arpie

**Endpoint network intrusion detection and threat response for public Wi-Fi.**

Arpie is a local desktop application that monitors the network connection of
the device where it runs. It detects suspicious ARP changes, port scans,
traffic bursts, and gateway identity changes, then presents explainable alerts
and optional host containment.

## Download

For normal users, download the latest desktop package from **GitHub Releases**
for your operating system:

| System | Download |
|---|---|
| Linux | `arpie-linux.tar.gz` |
| Windows | `arpie-windows-setup.exe` (installer) or `arpie-windows.zip` (portable) |
| macOS | `arpie-macos.tar.gz` |

After downloading, open the application. No Git, Python, virtual environment,
or source checkout is required.

Do **not** use **Code → Download ZIP** for normal installation. That downloads
the developer source repository, not the desktop application.

If the Releases page is empty, the first release has not been built yet. A
maintainer must push a version tag such as `v0.1.0`; the release workflow then
builds and uploads the platform packages automatically.

Start with the bundled PCAP demo. It works without administrator privileges and
lets you explore the interface, alerts, evidence, reports, and configuration.
In the application, open **Packet Logs** and choose **Run Demo Capture**.

For live monitoring, follow the first-run instructions in
[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md). Live capture and Seal Mode require
operating-system permissions.

### Linux terminal install

After the first Linux release is published, Linux users can install the latest
desktop package with:

```bash
curl -fsSL https://raw.githubusercontent.com/erxanitea/arpie/main/scripts/install.sh \
	-o arpie-install.sh
bash arpie-install.sh
arpie
```

The installer uses the user's home directory and does not require `sudo`.
Live capture and Seal Mode may still require operating-system permissions.

## Developer and Demo Setup

Use the source setup only for development, academic evaluation, or controlled
attack simulation. Maintainers use this path to build the desktop packages that
appear under GitHub Releases.

```bash
git clone https://github.com/<your-username>/arpie.git
cd arpie
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python main.py
```

For fish:

```fish
source .venv/bin/activate.fish
python main.py
```

## Try the Demo

From a source checkout, run the bundled attack capture without live network
permissions:

```bash
python main.py --pcap sample_pcaps/demo_attack.pcap
```

The application also includes an Evaluator-only Engine Self-Test and a
controlled two-device demonstration. See [docs/DEMO.md](docs/DEMO.md).

## Live Monitoring

Arpie is an **endpoint** monitor, not a whole-network sensor. It observes
broadcast ARP traffic and traffic addressed to the local device.

Live packet capture requires elevated operating-system permissions:

```bash
sudo -E env ARPIE_IFACE=<wifi_interface> python main.py
```

- Linux/macOS: run with the required capture and firewall permissions.
- Windows: install Npcap and run as Administrator.
- Seal Mode: requires firewall permissions and explicit confirmation.

Use a private phone hotspot or test network that you own. Do not run the attack
simulator against networks without authorization.

## Features

- Network context classification: trusted, public/untrusted, or unknown
- ARP identity inconsistency detection
- Port-scan detection
- SYN, UDP, and ICMP traffic-rate anomaly detection
- Gateway identity-change detection
- Explainable evidence and session risk scoring
- Optional AbuseIPDB and IPinfo enrichment
- Local desktop notifications
- Reversible, audited Seal Mode containment
- JSON, HTML, and PDF session reports
- SQLite session history with OS-level keyring support
- PCAP replay for repeatable testing

## Privacy and Security

Arpie runs locally. Session data and reports are stored on the user's device.
Threat-intelligence enrichment is optional. Private and local IP addresses are
not sent to external providers.

Never commit API keys, `.env` files, databases, reports, or live packet captures.
Review the first-run permissions and privacy notes in
[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

## Development

Run the test suite:

```bash
pytest tests/ -v
```

Build instructions and platform prerequisites are documented in
[docs/PACKAGING.md](docs/PACKAGING.md). The open-user release plan is in
[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

## Documentation

- [Live demonstration guide](docs/DEMO.md)
- [Deployment plan](docs/DEPLOYMENT.md)
- [Packaging guide](docs/PACKAGING.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Security notes](docs/SECURITY.md)
- [Project structure](docs/PROJECT_STRUCTURE.md)
- [System flow](FLOWCHART.md)

## License

[MIT](LICENSE)

The bundled attack simulator is for authorized testing of networks you own or
are explicitly permitted to test.