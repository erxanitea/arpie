#!/usr/bin/env bash
set -euo pipefail

REPOSITORY="erxanitea/arpie"
APP_NAME="arpie"
INSTALL_ROOT="${ARPIE_INSTALL_DIR:-${HOME}/.local/opt/${APP_NAME}}"
BIN_DIR="${HOME}/.local/bin"
API_URL="https://api.github.com/repos/${REPOSITORY}/releases/latest"

if [ "$(uname -s)" != "Linux" ]; then
    printf 'This installer supports Linux only. Download the Windows or macOS package from GitHub Releases.\n' >&2
    exit 1
fi

command -v curl >/dev/null 2>&1 || { printf 'curl is required.\n' >&2; exit 1; }
command -v tar >/dev/null 2>&1 || { printf 'tar is required.\n' >&2; exit 1; }

asset_url="$(curl -fsSL "$API_URL" 2>/dev/null | sed -n 's/.*"browser_download_url": "\([^"]*arpie-linux\.tar\.gz\)".*/\1/p' | head -n 1 || true)"
if [ -z "$asset_url" ]; then
    asset_url="https://github.com/${REPOSITORY}/releases/latest/download/arpie-linux.tar.gz"
fi


tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT
archive="$tmp_dir/arpie-linux.tar.gz"

printf 'Downloading Arpie from %s\n' "$asset_url"
curl -fL "$asset_url" -o "$archive"
mkdir -p "$tmp_dir/package" "$BIN_DIR"
tar -xzf "$archive" -C "$tmp_dir/package"

find_executable() {
    local target_dir="$1"
    if [ -x "$target_dir/arpie" ]; then
        printf '%s/arpie\n' "$target_dir"
    elif [ -x "$target_dir/Arpie" ]; then
        printf '%s/Arpie\n' "$target_dir"
    else
        find "$target_dir" -maxdepth 2 -type f -perm -u+x ! -name "*.so*" -print -quit
    fi
}

executable="$(find_executable "$tmp_dir/package")"
if [ -z "$executable" ]; then
    printf 'The Linux package does not contain an executable file.\n' >&2
    exit 1
fi

rm -rf "$INSTALL_ROOT"
mkdir -p "$INSTALL_ROOT"
cp -a "$tmp_dir/package/." "$INSTALL_ROOT/"
installed_executable="$(find_executable "$INSTALL_ROOT")"
ln -sfn "$installed_executable" "$BIN_DIR/$APP_NAME"

# Desktop launcher and icon registration
APPS_DIR="${XDG_DATA_HOME:-${HOME}/.local/share}/applications"
ICON_DIR="${XDG_DATA_HOME:-${HOME}/.local/share}/icons/hicolor/256x256/apps"
SYSTEMD_USER_DIR="${HOME}/.config/systemd/user"
mkdir -p "$APPS_DIR" "$ICON_DIR" "$SYSTEMD_USER_DIR"

icon_source="$(find "$INSTALL_ROOT" -maxdepth 3 -name "icon.png" 2>/dev/null | head -n 1 || true)"
if [ -z "$icon_source" ]; then
    icon_source="$(find "$INSTALL_ROOT" -maxdepth 3 -name "logo.png" -o -name "arpie-logo.png" 2>/dev/null | head -n 1 || true)"
fi
if [ -n "$icon_source" ] && [ -f "$icon_source" ]; then
    cp -f "$icon_source" "$ICON_DIR/arpie.png"
fi

cat > "$APPS_DIR/arpie.desktop" <<EOF
[Desktop Entry]
Name=Arpie
GenericName=Network Security Monitor
Comment=Endpoint NIDS & Wi-Fi Protection
Exec=${BIN_DIR}/arpie
Icon=${ICON_DIR}/arpie.png
Terminal=false
Type=Application
Categories=Network;Security;System;
Keywords=security;ids;arp;wifi;network;
StartupNotify=true
EOF

chmod +x "$APPS_DIR/arpie.desktop" 2>/dev/null || true
command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database "$APPS_DIR" 2>/dev/null || true

cat > "$SYSTEMD_USER_DIR/arpie.service" <<EOF
[Unit]
Description=Arpie Background Network Security Monitor
After=network.target

[Service]
ExecStart=${BIN_DIR}/arpie --daemon
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=default.target
EOF

printf '\nArpie installed successfully.\n'
printf '• Run directly from terminal: arpie\n'
printf '• Desktop app entry created in your Linux Application Menu (Search "Arpie" or pin to dock)\n'
printf '• To run Arpie permanently in the background as a systemd service:\n'
printf '    systemctl --user daemon-reload\n'
printf '    systemctl --user enable --now arpie\n\n'
if ! printf '%s' ":$PATH:" | grep -q ":$BIN_DIR:"; then
    printf 'Add %s to PATH if needed:\n' "$BIN_DIR"
    printf '  export PATH="$HOME/.local/bin:$PATH"\n'
fi
printf 'PCAP mode does not require administrator privileges.\n'
printf 'Live capture and Seal Mode require platform permissions.\n'

