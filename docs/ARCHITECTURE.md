# Arpie — Target Architecture

Status: **design / target state.** Current tree is described in `PROJECT_STRUCTURE.md`;
this document is what it should become. Replace `PROJECT_STRUCTURE.md` with this file
once Phase 4 lands.

Arpie is a Flet desktop NIDS, not a web app. The eight rubric layers
(Configuration, Controllers, Models, Views, Forms, Templates, Admin, Middleware)
are all present and each one is honest about its contents — no folder is named
after a Django concept it does not actually hold.

---

## 1. The one rule that makes this an architecture

```
                 ┌──────────────────────────────────────────┐
  flet allowed   │  views/  templates/  app.py  router.py    │
                 └───────────────────┬──────────────────────┘
                                     │ calls, passes plain data
                 ┌───────────────────▼──────────────────────┐
  no flet        │  controllers/                             │
                 └───────────────────┬──────────────────────┘
                                     │
                 ┌───────────────────▼──────────────────────┐
  no flet, no UI │  models/ domain/ detection/ forms/         │
                 │  network/ security/ integrations/         │
                 │  infrastructure/ reporting/ middleware/   │
                 └──────────────────────────────────────────┘
```

**`controllers/` and everything below it must never `import flet`.**

That single constraint is what the current structure lacks, and it is what buys
the whole refactor its value:

- Controllers become unit-testable with a fake `AppState` and a temp SQLite file —
  no `ft.Page`, no window, no event loop.
- It becomes structurally impossible for a view to run SQL or a firewall command,
  because the view has nothing to call but a controller.
- `state.py` holds session data as plain Python, so it can be asserted on in tests
  and serialised to a snapshot without reaching into Flet controls.

Enforce it in CI with one line:

```bash
! grep -rn "^import flet\|^from flet\|import flet as ft" \
    arpie/controllers arpie/models arpie/domain arpie/detection \
    arpie/network arpie/security arpie/integrations arpie/forms
```

### Supporting rules

| Rule | Why |
|---|---|
| `views/` import only `controllers/`, `templates/`, `forms/`, `state` | keeps rendering free of persistence and I/O |
| `controllers/` receive `AppState` + `Database`, never `ArpieApp` | breaks the `app ↔ controller` cycle |
| `controllers/` return results; they do not call `page.update()` | the caller owns the frame; controllers stay headless |
| `domain/` is pure — no DB, no sockets, no clock reads passed implicitly | makes risk, metrics and parsing trivially testable |
| `models/` is the only place with SQL | one audit surface for injection and schema |
| `infrastructure/` is the only place that shells out or touches the OS | one audit surface for privilege |

---

## 2. Target tree

```text
arpie/
├── __main__.py                 # sole entry point: python -m arpie
├── cli.py                      # argparse: headless pcap run, or launch desktop
├── app.py                      # ArpieApp: owns page, AppState, controllers. ~120 lines
├── router.py                   # screen + view registry, titles, dispatch
├── state.py                    # AppState dataclass — all runtime data, zero flet
│
├── config/                     ## Configuration
│   ├── settings.py             #    AppConfig, paths, env resolution
│   └── thresholds.py           #    DetectionThresholds, SealModeConfig, ThreatIntelConfig
│
├── models/                     ## Models — entities + the only SQL in the codebase
│   ├── __init__.py             #    Database = mixin composition
│   ├── base.py                 #    connect, schema, migrations, password hashing
│   ├── entities.py             #    Alert and typed row shapes
│   ├── operator.py
│   ├── session.py
│   ├── event.py
│   ├── action.py
│   ├── snapshot.py             #  NEW  typed snapshot_* accessors
│   ├── threat_intel.py
│   ├── config.py
│   └── _typing.py              #    MixinBase for type checking
│
├── controllers/                ## Controllers — workflow owners, no flet
│   ├── auth_controller.py      #    register, login, MFA challenge, logout, credentials, TOTP
│   ├── monitor_controller.py   #    start/stop/toggle, packet pipeline, ARP sweep, tick
│   ├── capture_controller.py   #    PCAP replay
│   ├── session_controller.py   #    restore and persist session snapshot
│   ├── seal_controller.py      #    block, unblock, emergency seal
│   ├── report_controller.py    #    export, export directory
│   ├── inventory_controller.py #  NEW  device discovery and rescan
│   └── settings_controller.py  #    rule toggles, thresholds, filters, traffic interval
│
├── views/                      ## Views — one screen each, render-only
│   ├── register.py   login.py     mfa.py       context.py   profile.py
│   ├── dashboard.py  alerts.py    inventory.py packets.py
│   └── seal.py       reports.py   users.py     settings.py
│
├── templates/                  ## Templates — reusable presentation, no workflow
│   ├── theme.py                #    colors, logo, severity_style()
│   ├── shell.py                #    sidebar + topbar + content layout
│   ├── charts.py               #    traffic spline builders
│   ├── components/
│   │   ├── cards.py  sidebar.py  topbar.py  evidence_drawer.py
│   └── dialogs/
│       ├── evidence.py  seal.py  mfa_setup.py  mfa_disable.py
│
├── forms/                      ## Forms — pure validators, already correct
│   ├── auth.py  settings.py
│
├── admin/                      ## Admin — privileged policy on role strings
│   └── policies.py
│
├── middleware/                 ## Middleware — cross-cutting only
│   ├── auth.py                 #    roles, require_role, guards
│   ├── session.py              #    session validity checks
│   └── mfa.py                  #    TOTP, recovery codes, QR
│
├── detection/                  # promoted out of middleware: this is the product
│   ├── engine.py               #    DetectionEngine
│   └── rules/
│       ├── arp_spoof.py  port_scan.py  traffic_anomaly.py  gateway_change.py
│
├── domain/                     # pure logic: no I/O, no flet, no DB
│   ├── risk.py                 #    score_alert, session_risk_score, risk_band
│   ├── metrics.py              #  NEW  TrafficWindow rolling buffer
│   ├── records.py              #  NEW  alert_record(), device_record()
│   └── protocols.py            #  NEW  packet → (src, dst, proto, macs, length)
│
├── network/                    # context.py  discovery.py
├── security/                   # seal.py  secrets_store.py
├── integrations/               # threat_intel.py
├── infrastructure/             # the only code that touches the OS
│   ├── capture.py              #    LiveCapture, PcapReplay
│   ├── notifications.py        #    desktop notifications
│   └── platform.py             #  NEW  open_folder()
├── reporting/                  # report.py
└── seeder/                     # service.py  fixtures.py  realistic_data.py  ui_state.py
```

---

## 3. Naming corrections and why each one matters

| Now | Target | Reason |
|---|---|---|
| `templates/app.py` (890 lines) | `app.py` + `router.py` + `state.py` + 4 controllers | The most important file in the project is currently inside a folder named for inert markup. |
| `templates/views/` | `views/` | Views are a top-level rubric layer, not a subfolder of Templates. Django nests neither inside the other. |
| `templates/` (app core + screens + widgets) | `templates/` (theme, shell, charts, components, dialogs) | Restores the Django meaning: reusable presentation fragments, no workflow. |
| `middleware/detection/` | `detection/` | Four detection rules are the reason this product exists. A packet pipeline is not middleware; filing the core algorithm under a rubric label is the hardest thing here to defend in a viva. |
| `capture.py` at package root | `infrastructure/capture.py` | It is a Scapy/OS adapter. Every other adapter already lives in `infrastructure/`; this one was left behind. |
| `admin/operator.py`, functions take `app` | `admin/policies.py`, functions take `role: str` | A policy check needs a role, not the whole application. Also makes it testable and drops the `getattr(app, ...)` guessing. |
| `middleware/auth.py` holding session checks | `middleware/auth.py` + `middleware/session.py` | Role policy and session lifetime are different concerns. |
| `templates/components/dialogs.py` (355 lines) | `templates/dialogs/` (4 files) | Four unrelated dialogs in one module, one of which writes TOTP secrets to the DB. |
| `templates/views/dashboard.py` (411 lines) | `views/dashboard.py` + `templates/charts.py` | `tests/test_traffic_chart.py` currently imports the private `_build_spline_chart` from a view. Chart geometry is reusable presentation and should be importable without the screen. |
| `config.py` | `config/settings.py` + `config/thresholds.py` | App settings and detection tuning change for different reasons and by different people. |
| `models/alert.py` | `models/entities.py` | `detection/` reaching into `models.alert` for a dataclass reads as a layering break; a named entities module makes the dependency obvious and correct. |

### Files to delete

| File | Why |
|---|---|
| `arpie/secrets_store.py` | shim with **zero** importers anywhere in the repo |
| `arpie/notification.py` | shim with **zero** importers anywhere in the repo |
| `arpie/risk.py` | only importer is `tests/test_risk.py:2` |
| `arpie/network_context.py` | only importer is `tests/test_context.py:4` |
| `arpie/main.py` | `sys.path.insert` inside an installed package; a symptom of running the package as a loose script |

`main.py` at the repo root is **kept**: `flet pack` and `pyinstaller` need a script
path, not a module target (`PACKAGING.md`). It is a two-line shim over `arpie.cli.main`.

Four "backward compatibility" shims exist to avoid editing two test import lines,
in a project whose only consumer is itself. Fix the two lines instead.

---

## 4. Splitting `templates/app.py`

`ArpieApp` currently conflates four responsibilities. The split follows those seams.

| Current member | Goes to |
|---|---|
| `page`, `_init_page`, `file_picker`, widget refs | `app.py` |
| `render`, `nav_to`, `update_view_content`, the `title_map` / `view_map` dicts | `router.py` |
| `current_screen`, `current_view`, `alerts`, `devices_inventory`, `packet_log_stream`, `traffic_history`, counters, `operator_*`, `session_id` | `state.py` (`AppState`) |
| `_build_app_shell` | `templates/shell.py` |
| `update_monitoring_ui` | `templates/components/sidebar.py` |
| `_process_packet`, `_rebuild_top_talkers`, `_passive_discover_device`, `start_monitoring`, `_initial_arp_sweep`, `_start_capture_safe`, `toggle_monitoring` | `controllers/monitor_controller.py` |
| the rolling-window arithmetic inside `_timer_task` | `domain/metrics.py` (`TrafficWindow`) |
| the 1-second loop shell of `_timer_task` | `app.py`, delegating to `monitor_controller.tick()` |
| `_restore_session_from_db`, session-change polling | `controllers/session_controller.py` |
| `enable_totp`, `disable_totp`, `save_operator_credentials`, `logout`, `_complete_login`, `verify_mfa_login` | `controllers/auth_controller.py` |
| `set_threshold`, `toggle_rule`, `set_traffic_interval`, `set_severity_filter`, `on_search_change` | `controllers/settings_controller.py` |
| `set_reports_dir`, `open_reports_directory`, `pick_reports_directory`, `export_report` | `controllers/report_controller.py` (+ `infrastructure/platform.py`) |
| reports-directory resolution in `__init__` | `config/settings.py` |

Target: `app.py` under ~120 lines, holding page setup, `AppState`, the controller
set, and the async tick.

---

## 5. Three duplications the new layout removes

These are the concrete payoff — not tidier folders, less code.

**1. The alert dict is built twice, inconsistently.**
`_restore_session_from_db` produces keys `date`, `target`, `status`, `confidence`,
`risk_score`, `evidence`, `action`. `_process_packet` produces a shorter dict
missing all of them. Any view reading `alert["risk_score"]` works on restored
alerts and raises `KeyError` on live ones. Fix: `domain/records.py:alert_record()`
as the single shape, built from either source.

**2. The device dict is built twice, verbatim.**
The same ~20 lines (`status` / `dev_type` / `hostname` from gateway comparison,
then the 8-key append) appear in `_passive_discover_device` and `_initial_arp_sweep`.
Fix: `domain/records.py:device_record(ip, mac, gateway_ip, seq)`.

**3. Theme constants leak into packet handling.**
`_process_packet` and `_restore_session_from_db` both import `SEVERITY_COLORS` /
`SEVERITY_BG` and bake `fg` / `bg` hex values into business records. Fix: records
carry plain `severity`; `theme.severity_style(severity)` resolves colors at render
time. Business logic stops depending on presentation.

---

## 6. Layering violations to close during the move

| Location | Violation | Fix |
|---|---|---|
| `views/login.py:44-46` | `authenticate_operator`, `get_totp_secret` | `auth_controller.login()` |
| `views/register.py:130-144` | `get_operator_by_username`, `get_operator_by_email`, `create_operator` | `auth_controller.register()` |
| `views/settings.py:52-71,138-146` | password change, TOTP reads — 5 DB calls | `auth_controller`, `settings_controller` |
| `views/users.py:73` | `list_operators`, guarded by `hasattr` | `auth_controller.list_operators()` |
| `views/reports.py:46` | `get_operator_sessions` | `report_controller.list_sessions()` |
| `components/dialogs.py:216-217,303` | writes TOTP secrets and recovery codes | `auth_controller.enable_totp()` |
| `views/inventory.py:4` | calls `arp_sweep` — a view scanning the network | `inventory_controller.rescan()` |
| `views/alerts.py:159` | imports `SealManager` — a view touching the firewall | `seal_controller.block_ip()` |
| `controllers/*` | mutate `app.status_toast`, call `app.page.update()` | return results; caller renders |

Sixteen `app.db.*` calls inside `templates/` today. Target: zero.

---

## 7. Migration order

Each phase leaves the app runnable and the tests green. Do not batch them.

| Phase | Work | Risk | Effort | Status |
|---|---|---|---|---|
| **0** | Delete 4 shims + `arpie/main.py`; fix 3 test imports | none | 15 min | **done** |
| **1** | Replace unsalted SHA-256 with salted scrypt + legacy upgrade path | none | 30 min | **done** |
| **2** | Pure moves: `detection/` out of `middleware/`, `capture.py` → `infrastructure/`, `views/` out of `templates/`, split `config/` and `dialogs/` | low — mechanical | 2 h | **done** |
| **3** | Extract `state.py`, `router.py`, `templates/shell.py` from `app.py` | medium | 3 h | next |
| **4** | Extract `domain/metrics.py`, `records.py`, `protocols.py`; delete the 3 duplications | low — pure, add tests first | 3 h | |
| **5** | Move the 16 DB calls out of views into controllers | medium | 4 h | |
| **6** | Controllers take `(state, db)` not `app`; return results; add the CI flet-import guard | medium | 4 h | |

Phases 0–2 are complete: 41 tests green (3 new, covering salting, the legacy
upgrade path, and credential leakage), all packages import, and
`python -m arpie --pcap sample_pcaps/demo_attack.pcap` still runs the full
capture → detection → risk → persistence path.

Phases 3–6 are what make the word "Controllers" true.

---

## 7b. Decided and done: time as an input

`adr/0001-detection-time-is-an-input.md` records the first change made on this
architecture's terms rather than the rubric's. Detection rules no longer read the
wall clock; the engine resolves each packet's capture timestamp once and passes it
in, and `events.ts` now stores the observation time.

It is listed here because it is the template for the rest: the defect was not a
misplaced file, it was an ambient dependency inside the core. Folder moves could
not have found it, and renaming nothing would have fixed it. Phases 3–6 below are
worth doing; this class of fix is worth doing first.

## 8. Deliberate deviations from Django

Stated up front so they read as decisions, not gaps.

- **No `urls.py`.** Flet navigates by `AppState.current_screen` / `current_view`.
  `router.py` is the local equivalent and holds the registry.
- **No Django admin site.** `admin/policies.py` is RBAC policy for the in-app
  operator management screens.
- **Middleware is not WSGI middleware.** There is no request cycle; `middleware/`
  holds auth, session and MFA guards applied at controller entry.
- **Thin models, separate domain.** `models/` is persistence; business rules live in
  `domain/` and `detection/`. This is deliberately *not* Django's fat-model default —
  it keeps risk scoring and detection testable without a database.
