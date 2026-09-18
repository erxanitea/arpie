# Arpie Project Structure

Arpie is an endpoint Network Intrusion Detection and Threat-Response System (NIDS) for public Wi-Fi, featuring a Flet desktop user interface. The project structure follows a layered architecture aligned with the `python-project-structure` skill:

```text
arpie/
├── __init__.py              # Public package API (AppConfig, Database, DetectionEngine)
├── __main__.py              # Canonical entry point: python -m arpie
├── cli.py                   # argparse: headless PCAP mode, or launch desktop UI
│
├── config/                  ## Configuration
│   ├── settings.py          # AppConfig dataclass + CONFIG singleton
│   └── thresholds.py        # DetectionThresholds, SealModeConfig, ThreatIntelConfig
│
├── controllers/             ## Controllers — workflow orchestration
│   ├── auth_controller.py   # MFA challenge, login completion
│   ├── capture_controller.py# PCAP replay orchestration
│   ├── report_controller.py # Report export triggering
│   └── seal_controller.py   # Host isolation / release commands
│
├── detection/               ## Detection — core NIDS heuristic engine & rules
│   ├── engine.py            # Fans each packet out to rules
│   ├── risk.py              # Explainable heuristic risk scoring and banding
│   ├── timebase.py          # Clock abstractions for replay/live timestamps
│   └── rules/               # Rule implementations (one concept per file)
│       ├── arp_spoof.py     # Rule 1 — ARP identity inconsistency
│       ├── gateway_change.py# Rule 2 — Gateway MAC change
│       ├── port_scan.py     # Rule 3 — Port-scan behavior
│       └── traffic_anomaly.py# Rule 4 — Traffic-rate anomaly
│
├── forms/                   ## Forms — pure validators, no UI dependency
│   ├── auth.py              # Email, username, password rules and strength
│   └── settings.py          # Threshold, export-path, API-key validation
│
├── infrastructure/          ## Infrastructure — external I/O & OS interfaces
│   ├── capture.py           # LiveCapture (Scapy sniff), PcapReplay
│   ├── notifications.py     # OS desktop notifications
│   ├── report.py            # PDF / HTML / JSON export generators
│   └── threat_intel.py      # AbuseIPDB API client with caching
│
├── middleware/              ## Middleware — cross-cutting security guards
│   ├── auth.py              # Roles, require_role, session validity
│   └── mfa.py               # TOTP verification, recovery codes, QR provisioning
│
├── models/                  ## Models — SQLite persistence and entities
│   ├── base.py              # Connection, schema DDL, scrypt password hashing
│   ├── alert.py             # Alert entity
│   ├── operator.py          # Operator accounts, authentication, TOTP secrets
│   ├── session.py           # Monitoring audit sessions
│   ├── event.py             # Event audit trail
│   ├── action.py            # Operator remediation actions
│   ├── threat_intel.py      # Cached IP enrichment records
│   ├── config.py            # Key-value runtime settings
│   └── _typing.py           # MixinBase for Database mixins type checking
│
├── network/                 ## Network — scanning and context discovery
│   ├── context.py           # NetworkContext (trust classification)
│   └── discovery.py         # ARP sweeps and subnet interface resolution
│
├── security/                ## Security — endpoint isolation & secrets
│   ├── seal.py              # SealManager (firewall-backed host isolation)
│   └── secrets_store.py     # OS Keyring secrets management
│
├── seeder/                  ## Seeder — demo fixtures & evaluation data
│   ├── fixtures.py          # Evaluation attack datasets
│   ├── realistic_data.py    # Sample packet and device generators
│   ├── service.py           # Database seeding and unseeding service
│   └── ui_state.py          # State hydration
│
└── views/                   ## Views — Flet desktop GUI presentation layer
    ├── app.py               # ArpieApp: desktop page setup, state, and lifecycle
    ├── theme.py             # Color palette, severity tokens, logo path
    ├── mixins/              # Application lifecycle mixins
    │   ├── _typing.py       # AppProtocol typing base for mixins
    │   ├── auth_mixin.py
    │   ├── monitoring_mixin.py
    │   ├── navigation_mixin.py
    │   ├── reports_mixin.py
    │   ├── seal_mixin.py
    │   └── session_restore_mixin.py
    ├── components/          # Reusable presentation widgets
    │   ├── cards.py         # Metric tiles and status badges
    │   ├── evidence_drawer.py
    │   ├── sidebar.py
    │   ├── topbar.py
    │   └── traffic_chart.py # Real-time spline chart canvas
    ├── dialogs/             # Modal dialogs
    │   ├── evidence.py
    │   ├── mfa_disable.py
    │   ├── mfa_setup.py
    │   └── seal.py
    ├── alerts.py            # Alerts management screen
    ├── context.py           # Network context & trust screen
    ├── dashboard.py         # Main dashboard screen
    ├── inventory.py         # Device inventory screen
    ├── login.py             # Operator login screen
    ├── mfa.py               # MFA challenge screen
    ├── packets.py           # Live packet stream inspection
    ├── profile.py           # Network detection profile selector
    ├── register.py          # Operator onboarding screen
    ├── reports.py           # Export and report generation screen
    ├── seal.py              # Host isolation control screen
    ├── settings.py          # System thresholds & credentials screen
    └── users.py             # Operator management & RBAC screen
```

## Test Structure

Parallel test directory mirroring the package structure:

```text
tests/
├── conftest.py              # Shared pytest fixtures
├── detection/
│   ├── test_detection.py
│   ├── test_risk.py
│   └── test_timebase.py
├── forms/
│   └── test_validation.py
├── middleware/
│   └── test_mfa.py
├── models/
│   └── test_db.py
├── network/
│   └── test_context.py
├── security/
│   └── test_secrets.py
├── seeder/
│   └── test_seeder.py
└── views/
    └── test_traffic_chart.py
```

## Entry Points

```bash
python -m arpie                                         # Desktop UI (canonical)
python -m arpie --pcap sample_pcaps/demo_attack.pcap    # Headless detection run
python main.py                                          # PyInstaller compatibility entry
```
