# Arpie Open-User Deployment Plan

## Product form

Arpie is a local desktop endpoint NIDS, not a hosted web application. Public users
receive a platform-specific desktop bundle from a GitHub Release and run it on
their own device. Packet capture, SQLite history, OS notifications, and Seal
Mode remain local to that device.

This matches the system's security boundary: an endpoint can inspect broadcast
ARP traffic and traffic addressed to itself, but cannot inspect other clients'
encrypted Wi-Fi traffic as a network-wide sensor.

## Release stages

### Stage 1: Academic demonstration

- Use PCAP replay or the Engine Self-Test without administrator privileges.
- Demonstrate login, MFA, context classification, dashboard KPIs, alerts,
  evidence, reports, and configuration persistence.
- Use a private phone hotspot for live testing only.
- Keep the two bundled course PDFs out of public application artifacts.

### Stage 2: Controlled alpha

- Build the Linux bundle on the Linux runner and test it on a clean Linux VM.
- Test live Scapy capture as root and verify `notify-send` notifications.
- Test Seal Mode with `iptables`, including successful block, failed block,
  manual unseal, and automatic restore.
- Capture a live hotspot session in Wireshark and compare it with Arpie alerts.
- Publish a checksum and an explicit unsigned-build warning.

### Stage 3: Open-user release

- Build Linux, Windows, and macOS bundles on their native runners.
- Install Npcap separately on Windows; run capture and Seal Mode elevated.
- Code-sign Windows and macOS artifacts where distribution permits.
- Verify that the release bundle contains the runtime logo and demo PCAP, but no
  course submissions, local database, API keys, reports, or packet captures.
- Attach SHA-256 checksums and a short platform-specific first-run guide.

## User first run

1. Download the bundle for the user's operating system from the GitHub Release.
2. Run PCAP replay first to confirm the UI without elevated privileges.
3. Create the first Evaluator/Administrator account, then create End User
   accounts if needed.
4. Review the detected network and select Public / Untrusted for unfamiliar
   networks.
5. Start live monitoring only after granting the platform's capture permission.
6. Configure API keys optionally through the OS keyring. Public IP enrichment is
   opt-in; private/LAN addresses are not sent to external providers.
7. Use Seal Mode only after explicit confirmation and only for a verified host.

## Security and deployment controls

- GitHub Actions dependencies are pinned to full commit SHAs.
- Secrets are stored through the OS keyring when available; no API key is
  committed to the repository.
- The database and reports use per-user OS data directories by default.
- Seal Mode validates target addresses, refuses the local endpoint and gateway,
  requires an active authenticated session and explicit confirmation, and only
  displays a block after the firewall operation succeeds.
- Detection rules are deterministic, configurable, logged, and covered by the
  automated suite.
- Course PDFs live under `docs/course-deliverables/` and are excluded from
  release bundles; runtime assets are limited to files needed by the UI.

## Rubric alignment

### Security implementation

Authentication, scrypt password storage, optional TOTP MFA, RBAC, parameterized
SQLite access, OS keyring integration, deterministic detection evidence, audit
logging, and reversible containment provide confidentiality, integrity,
availability, authentication, authorization, and accountability controls.

### System deployment

The supported deployment is a native desktop application with a headless PCAP
mode. CI tests the Python suite on Linux, Windows, and macOS; release builds
produce platform bundles. The first open-user release is conditional on native
bundle smoke tests, live capture permission tests, and platform-specific
notification/firewall checks.

### UI/UX

The workflow is: register/login, MFA if enabled, inspect network context, select
a monitoring profile, monitor the dashboard, inspect alert evidence, optionally
confirm Seal Mode, and export a forensic report. The UI exposes live state rather
than silently claiming containment when a firewall operation fails.

## Release checklist

- [ ] Full test suite passes.
- [ ] Problems panel has no errors.
- [ ] Native bundle built successfully for each target OS.
- [ ] Runtime logo and demo PCAP verified inside each bundle.
- [ ] Course PDFs absent from each bundle.
- [ ] PCAP replay works without elevation.
- [ ] Live capture works with documented elevation/Npcap setup.
- [ ] Desktop notifications verified.
- [ ] Seal block, failed block, unseal, and auto-restore verified.
- [ ] SHA-256 checksums published.
- [ ] Unsigned-build and privacy notices published with the release.
