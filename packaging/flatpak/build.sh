#!/usr/bin/env bash
# Builds and bundles the Veilwire Flatpak using flatpak-builder.
#
# flatpak-builder (and flatpak itself) are not installed on every Linux
# distribution, and are not present, for example, on the Debian/Kali
# machine this packaging system was developed on. This script detects
# that and reports exactly what's needed rather than pretending it can
# build anywhere.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DIST_DIR="$REPO_ROOT/dist"

if ! command -v flatpak-builder >/dev/null 2>&1; then
    cat >&2 <<'EOF'
ERROR: flatpak-builder not found on this system.

To build the Flatpak package:

  sudo apt install flatpak flatpak-builder     # Debian/Ubuntu/Kali
  # or: sudo dnf install flatpak-builder       # Fedora
  # or: sudo pacman -S flatpak-builder         # Arch

  flatpak remote-add --if-not-exists flathub https://flathub.org/repo/flathub.flatpakrepo
  flatpak install -y flathub org.kde.Platform//6.7 org.kde.Sdk//6.7

then re-run this script.

EOF
    exit 1
fi

VERSION="$(cd "$REPO_ROOT" && python3 -c 'import version; print(version.__version__)')"

BUILD_DIR="$(mktemp -d)"
trap 'rm -rf "$BUILD_DIR"' EXIT

# Stage the one true source tree + launcher + desktop file into the build
# context the manifest's `sources: - type: dir` step expects. The
# manifest's build-commands reference top-level files directly (app.py,
# bundle.py, ...) plus icons/ and veilwire.desktop, so copy-source.sh
# stages straight into $BUILD_DIR/staging rather than a subdirectory.
mkdir -p "$BUILD_DIR/staging"
"$REPO_ROOT/packaging/common/copy-source.sh" "$REPO_ROOT" "$BUILD_DIR/staging"
cp "$REPO_ROOT/packaging/common/veilwire.desktop" "$BUILD_DIR/staging/veilwire.desktop"
cp "$REPO_ROOT/packaging/common/veilwire-launcher.sh" "$BUILD_DIR/staging/packaging-launcher.sh"

MANIFEST="$BUILD_DIR/com.veilwire.Veilwire.yml"
sed "s|path: ../..|path: staging|" "$REPO_ROOT/packaging/flatpak/com.veilwire.Veilwire.yml" > "$MANIFEST"

STATE_DIR="$BUILD_DIR/flatpak-builder-state"
REPO_DIR="$DIST_DIR/flatpak-repo"
mkdir -p "$DIST_DIR" "$REPO_DIR"

(
    cd "$BUILD_DIR"
    flatpak-builder --force-clean --state-dir="$STATE_DIR" \
        --repo="$REPO_DIR" "$BUILD_DIR/build" "$MANIFEST"
)

flatpak build-bundle "$REPO_DIR" \
    "$DIST_DIR/Veilwire-${VERSION}-x86_64.flatpak" com.veilwire.Veilwire

echo "Built: $DIST_DIR/Veilwire-${VERSION}-x86_64.flatpak"
echo "Install with: flatpak install --user $DIST_DIR/Veilwire-${VERSION}-x86_64.flatpak"
