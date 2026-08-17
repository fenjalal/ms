#!/usr/bin/env bash
# Builds veilwire_<version>_amd64.deb using dpkg-deb + fakeroot directly -
# no debhelper/dh_make dependency, kept minimal and inspectable.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DIST_DIR="$REPO_ROOT/dist"

command -v dpkg-deb >/dev/null 2>&1 || {
    echo "ERROR: dpkg-deb not found. Install with: sudo apt install dpkg-dev" >&2
    exit 1
}
command -v fakeroot >/dev/null 2>&1 || {
    echo "ERROR: fakeroot not found. Install with: sudo apt install fakeroot" >&2
    exit 1
}

VERSION="$(cd "$REPO_ROOT" && python3 -c 'import version; print(version.__version__)')"
PKG_NAME="veilwire_${VERSION}_amd64"

BUILD_DIR="$(mktemp -d)"
trap 'rm -rf "$BUILD_DIR"' EXIT

PKG_ROOT="$BUILD_DIR/$PKG_NAME"
mkdir -p "$PKG_ROOT/DEBIAN"
mkdir -p "$PKG_ROOT/usr/lib/veilwire"
mkdir -p "$PKG_ROOT/usr/bin"
mkdir -p "$PKG_ROOT/usr/share/applications"
mkdir -p "$PKG_ROOT/usr/share/icons/hicolor"

# --- One source codebase, staged verbatim -----------------------------
"$REPO_ROOT/packaging/common/copy-source.sh" "$REPO_ROOT" "$PKG_ROOT/usr/lib/veilwire"

# --- Launcher -----------------------------------------------------------
install -m 0755 "$REPO_ROOT/packaging/common/veilwire-launcher.sh" "$PKG_ROOT/usr/bin/veilwire"

# --- Desktop entry + icons -----------------------------------------------
install -m 0644 "$REPO_ROOT/packaging/common/veilwire.desktop" "$PKG_ROOT/usr/share/applications/veilwire.desktop"

for size in 16 24 32 48 64 128 256 512; do
    src="$REPO_ROOT/icons/veilwire-${size}.png"
    if [ -f "$src" ]; then
        target_dir="$PKG_ROOT/usr/share/icons/hicolor/${size}x${size}/apps"
        mkdir -p "$target_dir"
        install -m 0644 "$src" "$target_dir/veilwire.png"
    fi
done

# --- Correct permissions everywhere --------------------------------------
find "$PKG_ROOT/usr/lib/veilwire" -type f -exec chmod 0644 {} \;
find "$PKG_ROOT/usr/lib/veilwire" -type d -exec chmod 0755 {} \;
chmod 0755 "$PKG_ROOT/usr/bin/veilwire"

# --- Control metadata -----------------------------------------------------
sed "s/__VERSION__/$VERSION/" "$REPO_ROOT/packaging/debian/control" > "$PKG_ROOT/DEBIAN/control"
install -m 0755 "$REPO_ROOT/packaging/debian/postinst" "$PKG_ROOT/DEBIAN/postinst"
install -m 0755 "$REPO_ROOT/packaging/debian/prerm" "$PKG_ROOT/DEBIAN/prerm"
install -m 0755 "$REPO_ROOT/packaging/debian/postrm" "$PKG_ROOT/DEBIAN/postrm"

# --- Sanity: never let the vault, secrets, or dev artifacts into the package ---
if find "$PKG_ROOT" -iname '*.dat' -o -iname '.env*' -o -iname 'id_rsa*' -o -iname '*.pem' | grep -q .; then
    echo "ERROR: forbidden file pattern found in staged package contents. Aborting." >&2
    find "$PKG_ROOT" -iname '*.dat' -o -iname '.env*' -o -iname 'id_rsa*' -o -iname '*.pem' >&2
    exit 1
fi

# --- Build ------------------------------------------------------------------
mkdir -p "$DIST_DIR"
fakeroot dpkg-deb --build --root-owner-group "$PKG_ROOT" "$DIST_DIR/${PKG_NAME}.deb"

echo "Built: $DIST_DIR/${PKG_NAME}.deb"
