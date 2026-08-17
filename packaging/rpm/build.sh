#!/usr/bin/env bash
# Builds veilwire-<version>-1.x86_64.rpm using rpmbuild.
#
# rpmbuild is NOT installed on every Linux distribution - it is standard
# on Fedora/RHEL/Rocky/AlmaLinux, but is not present, for example, on the
# Debian/Kali machine this packaging system was developed on. This script
# detects that and reports exactly what to install/use rather than
# pretending an RPM can be built anywhere.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DIST_DIR="$REPO_ROOT/dist"

if ! command -v rpmbuild >/dev/null 2>&1; then
    cat >&2 <<'EOF'
ERROR: rpmbuild not found on this system.

rpmbuild is only available on RPM-based distributions (Fedora, RHEL,
Rocky Linux, AlmaLinux) or via a container/VM targeting one of those.
This is expected and documented - it is not installed here.

To build the RPM package, use one of:

  1. A Fedora/RHEL/Rocky/AlmaLinux machine or VM:
       sudo dnf install rpm-build rpmdevtools
       ./packaging/rpm/build.sh

  2. A container (from any host with Docker/Podman):
       podman run --rm -v "$(pwd)":/src -w /src fedora:latest \
           bash -c "dnf install -y rpm-build rpmdevtools python3 && ./packaging/rpm/build.sh"

EOF
    exit 1
fi

VERSION="$(cd "$REPO_ROOT" && python3 -c 'import version; print(version.__version__)')"

TOPDIR="$(mktemp -d)"
trap 'rm -rf "$TOPDIR"' EXIT

mkdir -p "$TOPDIR"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
mkdir -p "$TOPDIR/SOURCES/app" "$TOPDIR/SOURCES/icons"

"$REPO_ROOT/packaging/common/copy-source.sh" "$REPO_ROOT" "$TOPDIR/SOURCES/app"
cp "$REPO_ROOT/packaging/common/veilwire-launcher.sh" "$TOPDIR/SOURCES/veilwire-launcher.sh"
cp "$REPO_ROOT/packaging/common/veilwire.desktop" "$TOPDIR/SOURCES/veilwire.desktop"
cp "$REPO_ROOT"/icons/veilwire*.png "$TOPDIR/SOURCES/icons/"

rpmbuild \
    --define "_veilwire_version $VERSION" \
    --define "_topdir $TOPDIR" \
    -bb "$REPO_ROOT/packaging/rpm/veilwire.spec"

mkdir -p "$DIST_DIR"
find "$TOPDIR/RPMS" -name '*.rpm' -exec cp {} "$DIST_DIR/" \;
echo "Built RPM(s) into $DIST_DIR"
