# Arpie Project Structure

Arpie is a Flet desktop application, so it uses screen navigation and workflow
controllers instead of Django URL views and HTTP middleware.

```text
arpie/
├── admin/          # Privileged operator policies; no Django admin site
├── controllers/    # UI workflow orchestration
├── forms/          # Input validation and form rules
├── models/         # SQLite persistence models and mixins
├── middleware/     # Authentication, MFA, and packet detection pipeline
├── domain/         # Core business rules such as explainable risk scoring
├── network/        # Network context and local host discovery
├── security/       # Firewall-backed Seal Mode and OS secret storage
├── integrations/   # External threat-intelligence providers
├── infrastructure/ # Operating-system adapters such as notifications
├── reporting/      # JSON, HTML, and PDF report generation
├── seeder/         # Database fixtures and demo UI-state projection
├── templates/      # Flet UI entry point, layouts, and reusable components
├── config.py       # Runtime configuration, not Django settings.py
├── capture.py      # Live and offline packet-source abstractions
├── network_context.py # Compatibility import for network/context.py
├── risk.py          # Compatibility import for domain/risk.py
├── notification.py  # Compatibility import for infrastructure/notifications.py
└── cli.py          # Canonical CLI and desktop launcher
```

## Layer Rules

- `templates` renders Flet controls and forwards user actions.
- `controllers` coordinate workflows and update application state.
- `models` own database persistence; controllers call them.
- `middleware` provides cross-cutting security and detection behavior.
- `admin` centralizes privileged-role policy checks.
- `config.py` is the application settings module.
- There is no `urls.py`: Flet uses `current_screen` and `current_view` for local
  desktop navigation.

The supported launcher is:

```bash
python -m arpie
```

`main.py` remains as a compatibility launcher for existing packaging commands.
