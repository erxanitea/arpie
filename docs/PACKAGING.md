# Packaging Arpie for public download

Goal: a binary a non-technical user downloads from GitHub Releases and runs on
their desktop. This guide covers building it, and — just as important — the
platform realities (privileges, Npcap, antivirus, code signing) that decide
whether that binary actually works on someone else's machine.

> **Read this first (honest expectations):** Arpie sniffs raw packets and edits
> firewall rules. That is an unavoidable part of what an IDS does, and it means
> (a) it must run **elevated**, and (b) unsigned builds will trigger SmartScreen
> / Gatekeeper / antivirus warnings until you code-sign them. Plan for a short
> "first run" setup step in your README, not a friction-free double-click.

---

## 1. Build the desktop app with `flet build`

Flet 0.80+ builds native desktop bundles via Flutter. This is the supported path
and produces the smallest, most reliable result.

**One-time toolchain:** install the [Flutter SDK](https://docs.flutter.dev/get-started/install)
(stable channel) and the platform toolchain (Visual Studio C++ workload on
Windows; Xcode on macOS; `clang`/`ninja`/`libgtk-3-dev` on Linux). Then:

```bash
pip install -r requirements.txt

# Build for the OS you are currently on:
flet build windows --project Arpie --include-packages flet_desktop
flet build macos   --project Arpie --include-packages flet_desktop
flet build linux   --project Arpie --include-packages flet_desktop
```

Notes:
- `flet build <os>` only builds for the OS it runs on — you need one runner per
  target (that is what the release workflow does).
- Bundle the `assets/` folder and `sample_pcaps/` so the logo and demo captures
  ship with the app; add them under the `assets` key in a `pyproject`/`flet`
  config or via `--include-data`, per your Flet version's docs.
- The entry point is `main.py`; `python main.py` launches the GUI.

### Older Flet (0.24–0.7x): `flet pack`

```bash
flet pack main.py --name Arpie --icon assets/logo.png \
  --add-data "assets:assets" --add-data "sample_pcaps:sample_pcaps"
```

## 2. Headless / CLI build (no GUI toolchain needed)

The `--pcap` replay path has no Flet UI and packages cleanly with PyInstaller —
useful for graders, servers, and CI smoke tests:

```bash
pyinstaller --onefile --name arpie-cli main.py
dist/arpie-cli --pcap sample_pcaps/demo_attack.pcap
```

---

## 3. Runtime prerequisites you must document for users

### Privileges (required for live capture + Seal Mode)
- **Windows:** run as Administrator.
- **Linux/macOS:** run with `sudo`, or grant capture capability once:
  `sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python))`
  (or the packaged binary). Seal Mode's `iptables` still needs root/`CAP_NET_ADMIN`.
- PCAP replay mode needs **no** privileges — good for a safe first look.

### Windows: Npcap
Live capture on Windows needs [Npcap](https://npcap.com). Its license does **not**
allow silent redistribution/bundling, so instruct users to install it separately
(check "WinPcap API-compatible mode"). Detect its absence and show a clear message
rather than failing opaquely.

### Antivirus / SmartScreen / Gatekeeper
An unsigned packet-sniffer that edits the firewall matches malware heuristics and
**will** be flagged. To ship smoothly:
- **Windows:** an Authenticode code-signing certificate (OV ~US$200–400/yr, or EV
  to bypass SmartScreen reputation immediately).
- **macOS:** an Apple Developer ID certificate + notarization (`xcrun notarytool`).
- Until signed, tell users the exact "More info → Run anyway" / right-click-Open
  steps in your README.

### Privacy (threat-intel enrichment)
When API keys are set, Arpie sends observed **public** IPs to AbuseIPDB and IPinfo.
LAN/private IPs are never sent. For a public release, make this opt-in on first
run and state it in a short privacy note. Without keys, enrichment is skipped and
everything else works.

---

## 4. Release automation

`.github/workflows/release.yml` builds desktop bundles on a version tag
(`v*.*.*`) across Windows/macOS/Linux runners and attaches them to a GitHub
Release. **Validate it on your first tag** and adjust `flet build` flags to match
your installed Flet version — the exact data-bundling flags change between Flet
releases, and this is the one step that can't be verified without running the
full Flutter toolchain.

```bash
git tag v0.1.0
git push origin v0.1.0   # triggers the release build
```
