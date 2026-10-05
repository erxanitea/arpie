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

asset_url="$(curl -fsSL "$API_URL" | sed -n 's/.*"browser_download_url": "\([^"]*arpie-linux\.tar\.gz\)".*/\1/p' | head -n 1)"
if [ -z "$asset_url" ]; then
    printf 'No Linux release package was found. A maintainer must publish a GitHub Release first.\n' >&2
    exit 1
fi

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT
archive="$tmp_dir/arpie-linux.tar.gz"

printf 'Downloading Arpie from %s\n' "$asset_url"
curl -fL "$asset_url" -o "$archive"
mkdir -p "$tmp_dir/package" "$BIN_DIR"
tar -xzf "$archive" -C "$tmp_dir/package"

executable="$(find "$tmp_dir/package" -type f -perm -u+x -print -quit)"
if [ -z "$executable" ]; then
    printf 'The Linux package does not contain an executable file.\n' >&2
    exit 1
fi

rm -rf "$INSTALL_ROOT"
mkdir -p "$INSTALL_ROOT"
cp -a "$tmp_dir/package/." "$INSTALL_ROOT/"
installed_executable="$(find "$INSTALL_ROOT" -type f -perm -u+x -print -quit)"
ln -sfn "$installed_executable" "$BIN_DIR/$APP_NAME"

printf '\nArpie installed successfully.\n'
printf 'Run it with: arpie\n'
if ! printf '%s' ":$PATH:" | grep -q ":$BIN_DIR:"; then
    printf 'Add %s to PATH if needed:\n' "$BIN_DIR"
    printf '  export PATH="$HOME/.local/bin:$PATH"\n'
fi
printf 'PCAP mode does not require administrator privileges.\n'
printf 'Live capture and Seal Mode require platform permissions.\n'
