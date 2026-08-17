#!/usr/bin/env bash
# Builds Veilwire-<version>-x86_64.AppImage.
#
# This is the one format that legitimately needs a bundled Python runtime,
# since it must run on distributions without python3-pyside6 etc. already
# installed. The AppDir staging (venv + source + AppRun + desktop file +
# icon) works without any special tooling; producing the final .AppImage
# file needs appimagetool, which is not installed on every system - not
# present, for example, on the Debian/Kali machine this packaging system
# was developed on. This script does the staging unconditionally, then
# only fails at the final packing step if appimagetool is missing, so the
# AppDir itself can still be inspected/tested even without it.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DIST_DIR="$REPO_ROOT/dist"

VERSION="$(cd "$REPO_ROOT" && python3 -c 'import version; print(version.__version__)')"

BUILD_DIR="$(mktemp -d)"
trap 'rm -rf "$BUILD_DIR"' EXIT

APPDIR="$BUILD_DIR/Veilwire.AppDir"
mkdir -p "$APPDIR/usr/lib" "$APPDIR/usr/bin"

# --- One source codebase, staged verbatim -----------------------------
mkdir -p "$APPDIR/usr/lib/veilwire"
"$REPO_ROOT/packaging/common/copy-source.sh" "$REPO_ROOT" "$APPDIR/usr/lib/veilwire"

# --- Self-contained runtime: the SAME requirements.txt used everywhere else ---
echo "Building the bundled Python runtime (this can take a minute)..."
python3 -m venv "$APPDIR/usr/venv"
"$APPDIR/usr/venv/bin/pip" install --quiet --upgrade pip
"$APPDIR/usr/venv/bin/pip" install --quiet -r "$REPO_ROOT/requirements.txt"

# --- AppRun, desktop file, icon, AppStream metadata -----------------------
install -m 0755 "$SCRIPT_DIR/AppRun" "$APPDIR/AppRun"
install -m 0644 "$REPO_ROOT/packaging/common/veilwire.desktop" "$APPDIR/veilwire.desktop"
install -m 0644 "$SCRIPT_DIR/veilwire.appdata.xml" "$APPDIR/veilwire.appdata.xml"
install -m 0644 "$REPO_ROOT/icons/veilwire-256.png" "$APPDIR/veilwire.png"

mkdir -p "$APPDIR/usr/share/icons/hicolor/256x256/apps"
install -m 0644 "$REPO_ROOT/icons/veilwire-256.png" "$APPDIR/usr/share/icons/hicolor/256x256/apps/veilwire.png"

# --- Sanity: never let the vault, secrets, or dev artifacts into the AppDir ---
# Scoped to the application's own staged source (usr/lib/veilwire) and the
# top-level AppDir files, not usr/venv - the bundled Python runtime's own
# third-party packages legitimately contain generically-named .dat/.pem
# files that have nothing to do with the application (e.g. PySide6 ships
# icudtl.dat, an ICU Unicode data table, and pip vendors cacert.pem, a CA
# certificate bundle used only during `pip install`) - checking those
# would be a false positive, not a real finding.
if find "$APPDIR/usr/lib/veilwire" -iname '*.dat' -o -iname '.env*' -o -iname 'id_rsa*' -o -iname '*.pem' | grep -q .; then
    echo "ERROR: forbidden file pattern found in staged application source. Aborting." >&2
    exit 1
fi
if find "$APPDIR" -maxdepth 1 -iname '*.dat' -o -iname '.env*' -o -iname 'id_rsa*' | grep -q .; then
    echo "ERROR: forbidden file pattern found at the AppDir top level. Aborting." >&2
    exit 1
fi

echo "AppDir staged at $APPDIR"

if ! command -v appimagetool >/dev/null 2>&1; then
    cat >&2 <<EOF

ERROR: appimagetool not found on this system.

The AppDir above was staged successfully and can be inspected directly,
but producing the final .AppImage file needs appimagetool, which is not
installed here. Get it from:

    https://github.com/AppImage/AppImageKit/releases

then run:

    appimagetool "$APPDIR" "$DIST_DIR/Veilwire-$VERSION-x86_64.AppImage"

EOF
    exit 1
fi

mkdir -p "$DIST_DIR"
ARCH=x86_64 appimagetool "$APPDIR" "$DIST_DIR/Veilwire-${VERSION}-x86_64.AppImage"
echo "Built: $DIST_DIR/Veilwire-${VERSION}-x86_64.AppImage"
