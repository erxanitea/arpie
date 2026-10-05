#!/usr/bin/env bash
set -euo pipefail

APP_NAME="Arpie"
BUILD_DIR="${1:-build/macos}"
OUTPUT_DMG="${2:-arpie-macos.dmg}"

APP_BUNDLE="$(find "$BUILD_DIR" -name "*.app" -type d | head -n 1 || true)"
if [ -z "$APP_BUNDLE" ]; then
    echo "Error: Could not locate .app bundle inside $BUILD_DIR" >&2
    exit 1
fi

TMP_STAGE="$(mktemp -d)"
trap 'rm -rf "$TMP_STAGE"' EXIT

echo "Staging $APP_BUNDLE into disk image..."
cp -R "$APP_BUNDLE" "$TMP_STAGE/$APP_NAME.app"
ln -s /Applications "$TMP_STAGE/Applications"

rm -f "$OUTPUT_DMG"
hdiutil create -volname "$APP_NAME" -srcfolder "$TMP_STAGE" -ov -format UDZO "$OUTPUT_DMG"
echo "Built macOS DMG installer: $OUTPUT_DMG"
