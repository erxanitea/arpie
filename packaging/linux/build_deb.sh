#!/usr/bin/env bash
set -euo pipefail

RAW_VERSION="${1:-0.1.0}"
VERSION="${RAW_VERSION#v}"
ARCH="${2:-amd64}"
BUILD_DIR="${3:-build/linux}"

if [ ! -d "$BUILD_DIR" ]; then
    echo "Error: Build directory '$BUILD_DIR' does not exist." >&2
    exit 1
fi

PACKAGE_NAME="arpie"
STAGE_DIR="build/deb_stage/${PACKAGE_NAME}_${VERSION}_${ARCH}"
rm -rf "build/deb_stage"
mkdir -p "$STAGE_DIR"

mkdir -p "$STAGE_DIR/DEBIAN"
mkdir -p "$STAGE_DIR/usr/lib/arpie"
mkdir -p "$STAGE_DIR/usr/bin"
mkdir -p "$STAGE_DIR/usr/share/applications"
mkdir -p "$STAGE_DIR/usr/share/icons/hicolor/256x256/apps"
mkdir -p "$STAGE_DIR/usr/lib/systemd/user"

if [ -d "$BUILD_DIR/bundle" ]; then
    BUILD_DIR="$BUILD_DIR/bundle"
fi

cp -a "$BUILD_DIR/." "$STAGE_DIR/usr/lib/arpie/"

if [ -f "$STAGE_DIR/usr/lib/arpie/Arpie" ] && [ ! -f "$STAGE_DIR/usr/lib/arpie/arpie" ]; then
    ln -s Arpie "$STAGE_DIR/usr/lib/arpie/arpie"
fi

cat > "$STAGE_DIR/usr/bin/arpie" << 'EOF'
#!/bin/sh
if [ -x /usr/lib/arpie/arpie ]; then
    exec /usr/lib/arpie/arpie "$@"
elif [ -x /usr/lib/arpie/Arpie ]; then
    exec /usr/lib/arpie/Arpie "$@"
else
    echo "Error: Arpie binary not found in /usr/lib/arpie" >&2
    exit 1
fi
EOF
chmod 755 "$STAGE_DIR/usr/bin/arpie"


cat > "$STAGE_DIR/usr/share/applications/arpie.desktop" << 'EOF'
[Desktop Entry]
Name=Arpie
GenericName=Network Security Monitor
Comment=Endpoint NIDS & Wi-Fi Protection
Exec=/usr/bin/arpie
Icon=arpie
Terminal=false
Type=Application
Categories=Network;Security;System;
Keywords=security;ids;arp;wifi;network;
StartupNotify=true
EOF
chmod 644 "$STAGE_DIR/usr/share/applications/arpie.desktop"

ICON_SRC="$(find assets packaging "$BUILD_DIR" -name "icon.png" 2>/dev/null | head -n 1 || true)"
if [ -z "$ICON_SRC" ]; then
    ICON_SRC="$(find assets packaging "$BUILD_DIR" -name "logo.png" -o -name "arpie-logo.png" 2>/dev/null | head -n 1 || true)"
fi
if [ -n "$ICON_SRC" ] && [ -f "$ICON_SRC" ]; then
    cp -f "$ICON_SRC" "$STAGE_DIR/usr/share/icons/hicolor/256x256/apps/arpie.png"
    chmod 644 "$STAGE_DIR/usr/share/icons/hicolor/256x256/apps/arpie.png"
fi

cat > "$STAGE_DIR/usr/lib/systemd/user/arpie.service" << 'EOF'
[Unit]
Description=Arpie Background Network Security Monitor
After=network.target

[Service]
ExecStart=/usr/bin/arpie --daemon
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=default.target
EOF
chmod 644 "$STAGE_DIR/usr/lib/systemd/user/arpie.service"

INSTALLED_SIZE=$(du -sk "$STAGE_DIR/usr" | cut -f1)

cat > "$STAGE_DIR/DEBIAN/control" << EOF
Package: ${PACKAGE_NAME}
Version: ${VERSION}
Section: net
Priority: optional
Architecture: ${ARCH}
Installed-Size: ${INSTALLED_SIZE}
Maintainer: Era Dumangcas <https://github.com/erxanitea/arpie>
Depends: libc6, libgtk-3-0
Homepage: https://github.com/erxanitea/arpie
Description: Endpoint Network Intrusion Detection & Threat Response System
 Arpie is a lightweight, cross-platform endpoint NIDS designed for public
 Wi-Fi protection. It continuously detects ARP spoofing, rogue gateway
 hijacks, port scanning, and volumetric traffic floods with 1-click Seal Mode
 endpoint isolation and automated compliance audit reporting.
EOF

cat > "$STAGE_DIR/DEBIAN/postinst" << 'EOF'
#!/bin/sh
set -e
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database -q /usr/share/applications || true
fi
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
    gtk-update-icon-cache -q -t -f /usr/share/icons/hicolor || true
fi
if command -v setcap >/dev/null 2>&1; then
    setcap cap_net_raw,cap_net_admin=eip /usr/lib/arpie/arpie 2>/dev/null || true
    setcap cap_net_raw,cap_net_admin=eip /usr/lib/arpie/Arpie 2>/dev/null || true
fi
EOF
chmod 755 "$STAGE_DIR/DEBIAN/postinst"

cat > "$STAGE_DIR/DEBIAN/postrm" << 'EOF'
#!/bin/sh
set -e
if [ "$1" = "remove" ] || [ "$1" = "purge" ]; then
    if command -v update-desktop-database >/dev/null 2>&1; then
        update-desktop-database -q /usr/share/applications || true
    fi
    if command -v gtk-update-icon-cache >/dev/null 2>&1; then
        gtk-update-icon-cache -q -t -f /usr/share/icons/hicolor || true
    fi
fi
EOF
chmod 755 "$STAGE_DIR/DEBIAN/postrm"

DEB_FILE="arpie_${VERSION}_${ARCH}.deb"
GENERIC_DEB="arpie-linux-${ARCH}.deb"

if command -v dpkg-deb >/dev/null 2>&1; then
    dpkg-deb --build --root-owner-group "$STAGE_DIR" "$DEB_FILE"
else
    python3 - << PYEOF
import tarfile, os, io

def make_tar_gz(source_dir, output_path):
    with tarfile.open(output_path, "w:gz") as tar:
        for root, dirs, files in os.walk(source_dir):
            for file in files:
                p = os.path.join(root, file)
                rel = os.path.relpath(p, source_dir)
                tar.add(p, arcname="./" + rel)

stage = "$STAGE_DIR"
os.makedirs("build/deb_tmp", exist_ok=True)
with open("build/deb_tmp/debian-binary", "w") as f:
    f.write("2.0\n")

make_tar_gz(os.path.join(stage, "DEBIAN"), "build/deb_tmp/control.tar.gz")
make_tar_gz(os.path.join(stage, "usr"), "build/deb_tmp/data.tar.gz")

import subprocess
subprocess.check_call(["ar", "rc", "$DEB_FILE", "build/deb_tmp/debian-binary", "build/deb_tmp/control.tar.gz", "build/deb_tmp/data.tar.gz"])
PYEOF
fi

cp -f "$DEB_FILE" "$GENERIC_DEB"
echo "Built Debian package: $DEB_FILE and $GENERIC_DEB"
