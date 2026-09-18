# Arpie Project Structure

Arpie is a Flet desktop application, so it uses screen navigation and workflow
controllers instead of Django URL views and HTTP middleware. All eight
Python/Django structural layers are present; where the Django meaning does not
apply, the deviation is stated in §"Deliberate deviations" below.

`ARCHITECTURE.md` describes the target state and the remaining migration phases.
This file describes what is on disk today.

```text
arpie/
├── __main__.py              # canonical entry point: python -m arpie
├── cli.py                   # argparse: headless PCAP mode, or launch the desktop UI
│
├── config/                  ## Configuration
│   ├── settings.py          #    AppConfig + CONFIG singleton, export-dir resolution
│   └── thresholds.py        #    DetectionThresholds, SealModeConfig, ThreatIntelConfig
│
├── models/                  ## Models — entities and the only SQL in the codebase
│   ├── base.py              #    connection, schema, migrations, scrypt password hashing
│   ├── alert.py             #    Alert entity
│   ├── operator.py          #    accounts, authentication, TOTP, recovery codes
│   ├── session.py  event.py  action.py  threat_intel.py  config.py
│   └── _typing.py           #    MixinBase so the mixin composition type-checks
│
├── controllers/             ## Controllers — workflow orchestration
│   ├── auth_controller.py   #    MFA challenge, login completion
│   ├── capture_controller.py#    PCAP replay
│   ├── report_controller.py #    report export
│   └── seal_controller.py   #    host isolation / release
│
├── views/                   ## Views — one module per screen, render-only
│   ├── register.py  login.py  mfa.py  context.py  profile.py
│   ├── dashboard.py  alerts.py  inventory.py  packets.py
│   └── seal.py  reports.py  users.py  settings.py
│
├── templates/               ## Templates — reusable presentation, no workflow
│   ├── app.py               #    ArpieApp: page setup, state, routing  (to be split)
│   ├── theme.py             #    palette, severity colors, logo path
│   ├── components/          #    sidebar, topbar, cards, evidence drawer
│   └── dialogs/             #    evidence, seal, mfa_setup, mfa_disable
│
├── forms/                   ## Forms — pure validators, no UI dependency
│   ├── auth.py              #    email, username, password rules and strength
│   └── settings.py          #    threshold, export-path, API-key validation
│
├── admin/                   ## Admin — privileged-operator policy (no Django admin site)
│   └── operator.py
│
├── middleware/              ## Middleware — cross-cutting security only
│   ├── auth.py              #    roles, require_role, session validity
│   └── mfa.py               #    TOTP, recovery codes, QR provisioning
│
├── detection/               # the deterministic NIDS heuristics — core domain
│   ├── engine.py            #    fans each packet out to every rule
│   └── rules/
│       ├── arp_spoof.py     #    Rule 1 — ARP identity inconsistency
│       ├── port_scan.py     #    Rule 2 — port-scan behavior
│       ├── traffic_anomaly.py #  Rule 3 — traffic-rate anomaly
│       └── gateway_change.py  #  Rule 4 — gateway identity change
│
├── domain/                  # pure business rules: no I/O, no UI
│   └── risk.py              #    explainable risk scoring and banding
│
├── network/                 # context.py (trust classification), discovery.py (ARP sweep)
├── security/                # seal.py (firewall-backed isolation), secrets_store.py (keyring)
├── integrations/            # threat_intel.py (AbuseIPDB / ipinfo, cached)
├── infrastructure/          # the only layer that touches the OS
│   ├── capture.py           #    LiveCapture (Scapy sniff), PcapReplay
│   └── notifications.py     #    desktop notifications
├── reporting/               # report.py — JSON / HTML / PDF export
└── seeder/                  # demo fixtures and UI-state projection
```

## Layer rules

- `views/` render Flet controls and forward user actions. They do not own workflow.
- `controllers/` coordinate workflows and update application state.
- `models/` own database persistence; controllers call them.
- `detection/` and `domain/` hold business rules and are free of UI and I/O.
- `middleware/` provides cross-cutting security behavior (roles, sessions, MFA).
- `admin/` centralizes privileged-role policy checks.
- `infrastructure/` is the only place that captures packets or calls the OS.
- `config/` is the application settings module.

## Deliberate deviations from Django

- **No `urls.py`.** Flet navigates by `current_screen` / `current_view` on the
  application object, not by URL resolution.
- **No Django admin site.** `admin/` is RBAC policy for the in-app operator
  management screens.
- **Middleware is not WSGI middleware.** There is no request cycle; `middleware/`
  holds guards applied at controller entry.
- **Detection is not middleware.** The packet pipeline is the product's core
  domain, so it lives in `detection/` rather than being filed under a
  cross-cutting label.
- **Thin models, separate domain.** `models/` is persistence; business rules live
  in `domain/` and `detection/`. This is deliberately *not* Django's fat-model
  default — it keeps risk scoring and detection testable without a database.

## Entry points

```bash
python -m arpie                                   # desktop UI (canonical)
python -m arpie --pcap sample_pcaps/demo_attack.pcap   # headless detection run
```

`main.py` at the repository root is retained because `flet pack` and
`pyinstaller` require a script path rather than a module target; see
`PACKAGING.md`. It only calls `arpie.cli.main`.
