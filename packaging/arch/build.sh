#!/usr/bin/env bash
# Builds veilwire-<version>-1-x86_64.pkg.tar.zst using makepkg.
#
# makepkg is an Arch-family tool - not available on every Linux
# distribution, and is not present, for example, on the Debian/Kali
# machine this packaging system was developed on. This script detects
# that and reports exactly what's needed rather than pretending it can
# build anywhere.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DIST_DIR="$REPO_ROOT/dist"

if ! command -v makepkg >/dev/null 2>&1; then
    cat >&2 <<'EOF'
ERROR: makepkg not found on this system.

makepkg is only available on Arch-family distributions (Arch Linux,
Manjaro, EndeavourOS) or via a container/chroot targeting one of those.
This is expected and documented - it is not installed here.

To build the Arch package, use one of:

  1. An Arch/Manjaro/EndeavourOS machine:
       cd packaging/arch && ./build.sh

  2. A container (from any host with Docker/Podman):
       podman run --rm -v "$(pwd)":/src -w /src archlinux:latest \
           bash -c "pacman -Sy --noconfirm base-devel python && \
                    useradd -m builder && chown -R builder /src && \
                    su builder -c ./packaging/arch/build.sh"
       (makepkg refuses to run as root, hence the unprivileged user above)

EOF
    exit 1
fi

VERSION="$(cd "$REPO_ROOT" && python3 -c 'import version; print(version.__version__)')"

BUILD_DIR="$(mktemp -d)"
trap 'rm -rf "$BUILD_DIR"' EXIT

mkdir -p "$BUILD_DIR/app" "$BUILD_DIR/icons"
"$REPO_ROOT/packaging/common/copy-source.sh" "$REPO_ROOT" "$BUILD_DIR/app"
cp "$REPO_ROOT/packaging/common/veilwire-launcher.sh" "$BUILD_DIR/veilwire-launcher.sh"
cp "$REPO_ROOT/packaging/common/veilwire.desktop" "$BUILD_DIR/veilwire.desktop"
cp "$REPO_ROOT"/icons/veilwire*.png "$BUILD_DIR/icons/"

sed "s/^pkgver=.*/pkgver=$VERSION/" "$REPO_ROOT/packaging/arch/PKGBUILD" > "$BUILD_DIR/PKGBUILD"

(
    cd "$BUILD_DIR"
    makepkg --skipinteg
)

mkdir -p "$DIST_DIR"
find "$BUILD_DIR" -maxdepth 1 -name '*.pkg.tar.zst' -exec cp {} "$DIST_DIR/" \;
echo "Built Arch package(s) into $DIST_DIR"
