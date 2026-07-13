#!/usr/bin/env bash
# Build the macOS .app bundle (AppleScript applet wrapping the Rust binary) and
# package it as a drag-to-Applications .dmg.
#
#   ./scripts/build-macos.sh
#
# Output: dist/JMSRdpLauncher.dmg  (and dist/JMSRdpLauncher.app)
#
# The applet receives jms:// via its `open location` handler (reliable GURL
# delivery) and forwards the URL as argv to the Rust binary. Opening the .app
# directly runs `on run`, which calls `--register-self` so the bundle becomes
# the default jms:// handler with no manual lsregister / plist editing.
set -euo pipefail

cd "$(dirname "$0")/.."

APP_NAME="JMSRdpLauncher"
BUNDLE_ID="local.jms-rdp-launcher"
BIN_NAME="jms-rdp-launcher"
DIST="dist"
APP="$DIST/$APP_NAME.app"
PB=/usr/libexec/PlistBuddy
LSR="/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister"

echo "==> cargo build --release"
cargo build --release

echo "==> assemble .app bundle"
rm -rf "$DIST"
mkdir -p "$DIST"
# Compile the AppleScript applet (CFBundleExecutable = "applet").
osacompile -o "$APP" scripts/jms_handler.applescript
mkdir -p "$APP/Contents/Resources"
cp "target/release/$BIN_NAME" "$APP/Contents/Resources/$BIN_NAME"
chmod +x "$APP/Contents/Resources/$BIN_NAME"

echo "==> customize Info.plist (bundle id, URL scheme, background-only)"
# osacompile does NOT set CFBundleIdentifier, so force it (Delete+Add is
# idempotent). The bundle id MUST match the LSHandlers default or
# LaunchServices won't route jms:// here reliably.
"$PB" -c "Delete :CFBundleIdentifier" "$APP/Contents/Info.plist" 2>/dev/null || true
"$PB" -c "Add :CFBundleIdentifier string $BUNDLE_ID" "$APP/Contents/Info.plist"
"$PB" -c "Set :CFBundleName string $APP_NAME" "$APP/Contents/Info.plist"
"$PB" -c "Delete :LSUIElement" "$APP/Contents/Info.plist" 2>/dev/null || true
"$PB" -c "Add :LSUIElement bool true" "$APP/Contents/Info.plist"
"$PB" -c "Delete :CFBundleURLTypes" "$APP/Contents/Info.plist" 2>/dev/null || true
"$PB" -c "Add :CFBundleURLTypes array" "$APP/Contents/Info.plist"
"$PB" -c "Add :CFBundleURLTypes:0 dict" "$APP/Contents/Info.plist"
"$PB" -c "Add :CFBundleURLTypes:0:CFBundleURLName string $BUNDLE_ID" "$APP/Contents/Info.plist"
"$PB" -c "Add :CFBundleURLTypes:0:CFBundleURLSchemes array" "$APP/Contents/Info.plist"
"$PB" -c "Add :CFBundleURLTypes:0:CFBundleURLSchemes:0 string jms" "$APP/Contents/Info.plist"

echo "==> codesign (ad-hoc)"
codesign --force --deep --sign - "$APP"

echo "==> register with LaunchServices (so a local build is immediately usable)"
"$LSR" -f "$APP"

echo "==> build drag-to-Applications .dmg"
STAGE="$DIST/.dmg-stage"
rm -rf "$STAGE"
mkdir -p "$STAGE"
cp -R "$APP" "$STAGE/"
ln -s /Applications "$STAGE/Applications"
hdiutil create -volname "$APP_NAME" -fs HFS+ -srcfolder "$STAGE" -ov -format UDZO "$DIST/$APP_NAME.dmg" >/dev/null
rm -rf "$STAGE"

echo
echo "Done. Install: open $DIST/$APP_NAME.dmg, drag $APP_NAME to Applications,"
echo "then open it once (self-registers as the jms:// handler)."
echo "App bundle: $APP"
echo "Disk image: $DIST/$APP_NAME.dmg"
