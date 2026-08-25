#!/usr/bin/env bash
# Unified build entry point for every Veilwire package format.
#
#   ./build.sh deb
#   ./build.sh rpm
#   ./build.sh arch
#   ./build.sh appimage
#   ./build.sh flatpak
#   ./build.sh all       # runs every format, summarizing pass/fail/skipped
#
# Optional --version X.Y.Z bumps version.py's __version__ BEFORE building,
# so a release is "./build.sh all --version 1.1.0" rather than hand-editing
# version.py first. version.py stays the single source of truth - this
# flag is a convenience that edits that one file and nothing else; every
# package format's build script (and the running app itself) already reads
# __version__ from there, so the new number appears in the .deb/.rpm/Arch/
# AppImage/Flatpak filenames, each format's own metadata (control/spec/
# PKGBUILD/manifest), and inside the app's own UI (window title, About
# dialog, status bar tooltip) automatically, with nothing else to update by
# hand. Omitting --version builds whatever version.py already says - two
# builds in a row with no flag produce the identical version number, which
# is the "if same number, stays the same" behavior.
#
# Every invocation runs the full existing test suite first and aborts
# with a non-zero exit code if any test fails - no release package is ever
# built from a failing test suite. This reuses the test_*.py files that
# already exist rather than introducing a second, packaging-specific test
# runner.
#
# Formats whose build tooling (rpmbuild, makepkg, appimagetool,
# flatpak-builder) is not installed on the current machine are reported
# clearly as skipped-with-a-reason, never silently skipped and never
# falsely reported as built.
#
# Every successful invocation (single format or "all") writes/refreshes
# dist/SHA256SUMS covering every package currently in dist/, so anyone
# who downloads a package later can verify it hasn't been altered (see
# GUIDE.md's "Verifying your download" section for the user-facing
# instructions). Set VEILWIRE_GPG_KEY to a key id/email already present
# in the local GPG keyring to also produce a detached signature,
# dist/SHA256SUMS.asc, over that checksum file - e.g.:
#
#   VEILWIRE_GPG_KEY=release@veilwire.example ./build.sh all --version 1.1.0
#
# Left unset, checksums are still written but not signed - a normal dev
# build never needs a signing key configured and never prompts for one.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIST_DIR="$REPO_ROOT/dist"

usage() {
    cat >&2 <<EOF
Usage: $0 {deb|rpm|arch|appimage|flatpak|all} [--version X.Y.Z]
EOF
    exit 1
}

# Validates X.Y.Z (three dot-separated non-negative integers) and rewrites
# only the __version__ = "..." line in version.py - every other line
# (APP_NAME, the XMR/contact constants, helper functions) is left untouched.
set_version() {
    local new_version="$1"
    if ! [[ "$new_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "ERROR: --version must look like X.Y.Z (e.g. 1.1.0), got: $new_version" >&2
        exit 1
    fi
    python3 - "$REPO_ROOT/version.py" "$new_version" <<'PYEOF'
import re
import sys

path, new_version = sys.argv[1], sys.argv[2]
with open(path, "r", encoding="utf-8") as f:
    text = f.read()

updated, count = re.subn(
    r'^__version__ = "[^"]*"',
    f'__version__ = "{new_version}"',
    text,
    count=1,
    flags=re.MULTILINE,
)
if count != 1:
    print(f"ERROR: could not find __version__ = ... in {path}", file=sys.stderr)
    sys.exit(1)

with open(path, "w", encoding="utf-8") as f:
    f.write(updated)
print(f"version.py: __version__ set to {new_version!r}")
PYEOF
}

run_tests() {
    echo "=== Running the full test suite (build gate) ==="
    local test_files=(
        test_transport.py test_e2e.py test_py313.py test_platform.py
        test_keys.py test_ui.py test_offline.py test_vault_concurrency.py
        test_shutdown.py test_bundle.py test_i18n.py test_delete.py
        test_envelope.py test_groups_and_files.py test_group_invite.py
        test_group_onboarding.py test_chunked_transfer.py
    )
    (
        cd "$REPO_ROOT"
        export QT_QPA_PLATFORM="${QT_QPA_PLATFORM:-offscreen}"
        for f in "${test_files[@]}"; do
            echo "--- $f ---"
            python3 "$f"
        done
    )
    echo "=== All tests passed ==="
}

validate_deb() {
    local pkg="$1"
    echo "=== Validating $pkg ==="
    # Captured once into a variable rather than piped directly into `grep
    # -q` repeatedly: under `set -o pipefail`, grep -q's early exit after
    # its first match sends dpkg-deb's tar subprocess a SIGPIPE, which
    # pipefail then (correctly, but unhelpfully here) treats as a pipeline
    # failure even though the grep itself succeeded.
    local contents
    contents="$(dpkg-deb --contents "$pkg")"
    local depends
    depends="$(dpkg-deb -f "$pkg" Depends)"

    echo "$contents" | grep -q 'usr/bin/veilwire' || { echo "FAIL: veilwire binary missing" >&2; exit 1; }
    echo "$contents" | grep 'usr/bin/veilwire' | grep -q '^-rwxr-xr-x' || { echo "FAIL: veilwire binary is not 0755" >&2; exit 1; }
    echo "$contents" | grep -q 'veilwire.desktop' || { echo "FAIL: desktop entry missing" >&2; exit 1; }
    echo "$contents" | grep -q 'icons/hicolor.*veilwire.png' || { echo "FAIL: icons missing" >&2; exit 1; }
    echo "$depends" | grep -q 'python3' || { echo "FAIL: Depends does not mention python3" >&2; exit 1; }
    if echo "$contents" | grep -iE 'vault\.dat|tor-data/|\.env|id_rsa|\.pem$'; then
        echo "FAIL: forbidden file found in package contents" >&2
        exit 1
    fi
    if command -v desktop-file-validate >/dev/null 2>&1; then
        local tmp
        tmp="$(mktemp --suffix=.desktop)"
        dpkg-deb --fsys-tarfile "$pkg" | tar -xO ./usr/share/applications/veilwire.desktop > "$tmp"
        desktop-file-validate "$tmp" || echo "NOTE: desktop-file-validate reported issues (see above)"
        rm -f "$tmp"
    else
        echo "NOTE: desktop-file-validate not installed, skipping that check"
    fi
    echo "=== $pkg passed validation ==="
}

build_deb() {
    echo "=== Building .deb ==="
    if ! command -v dpkg-deb >/dev/null 2>&1 || ! command -v fakeroot >/dev/null 2>&1; then
        echo "SKIPPED: deb (dpkg-deb/fakeroot not installed - sudo apt install dpkg-dev fakeroot)"
        return 1
    fi
    "$REPO_ROOT/packaging/debian/build.sh"
    local version
    version="$(python3 -c 'import version; print(version.__version__)')"
    validate_deb "$DIST_DIR/veilwire_${version}_amd64.deb"
    return 0
}

build_rpm() {
    echo "=== Building .rpm ==="
    if ! command -v rpmbuild >/dev/null 2>&1; then
        echo "SKIPPED: rpm (rpmbuild not installed on this system - see packaging/rpm/build.sh for details)"
        return 1
    fi
    "$REPO_ROOT/packaging/rpm/build.sh"
    return 0
}

build_arch() {
    echo "=== Building Arch package ==="
    if ! command -v makepkg >/dev/null 2>&1; then
        echo "SKIPPED: arch (makepkg not installed on this system - see packaging/arch/build.sh for details)"
        return 1
    fi
    "$REPO_ROOT/packaging/arch/build.sh"
    return 0
}

build_appimage() {
    echo "=== Building AppImage ==="
    "$REPO_ROOT/packaging/appimage/build.sh" || {
        echo "SKIPPED (or partially staged): appimage (appimagetool not installed on this system - see packaging/appimage/build.sh for details)"
        return 1
    }
    return 0
}

build_flatpak() {
    echo "=== Building Flatpak ==="
    if ! command -v flatpak-builder >/dev/null 2>&1; then
        echo "SKIPPED: flatpak (flatpak-builder not installed on this system - see packaging/flatpak/build.sh for details)"
        return 1
    fi
    "$REPO_ROOT/packaging/flatpak/build.sh"
    return 0
}

write_checksums() {
    # Every package format's build script drops its output straight into
    # $DIST_DIR - this recomputes SHA256SUMS from whatever is actually
    # there right now, so it's correct whether "all" just built five
    # formats in one run or a single target (e.g. "./build.sh deb") was
    # run on its own. Previously this only ran from the "all" branch,
    # meaning a single-format build (the common case for a maintainer
    # re-cutting just one package after a fix) silently shipped with no
    # checksum file at all - fixed by calling this from every branch, not
    # just "all".
    local pkgs=()
    shopt -s nullglob
    pkgs=("$DIST_DIR"/*.deb "$DIST_DIR"/*.rpm "$DIST_DIR"/*.pkg.tar.zst "$DIST_DIR"/*.AppImage "$DIST_DIR"/*.flatpak)
    shopt -u nullglob
    if [ "${#pkgs[@]}" -eq 0 ]; then
        return 0
    fi
    (
        cd "$DIST_DIR"
        sha256sum -- "${pkgs[@]##*/}" > SHA256SUMS
    )
    echo "Checksums written to $DIST_DIR/SHA256SUMS"

    # Optional GPG signature over the checksum file itself (not each
    # package individually - signing SHA256SUMS transitively covers every
    # package listed in it with one signature, the same pattern most
    # projects that publish reproducible-ish release artifacts use).
    # Entirely opt-in: only runs if the maintainer has already configured
    # a signing key via VEILWIRE_GPG_KEY, so a normal dev build never
    # prompts for a passphrase or fails when no key is set up.
    if [ -n "${VEILWIRE_GPG_KEY:-}" ] && command -v gpg >/dev/null 2>&1; then
        (cd "$DIST_DIR" && gpg --batch --yes --local-user "$VEILWIRE_GPG_KEY" \
            --detach-sign --armor -o SHA256SUMS.asc SHA256SUMS)
        echo "Signature written to $DIST_DIR/SHA256SUMS.asc (key: $VEILWIRE_GPG_KEY)"
    else
        echo "NOTE: SHA256SUMS not GPG-signed (set VEILWIRE_GPG_KEY to a key id/email to sign)"
    fi
}

main() {
    local target="${1:-}"
    [ -n "$target" ] || usage
    shift

    local new_version=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --version)
                new_version="${2:-}"
                [ -n "$new_version" ] || { echo "ERROR: --version needs a value" >&2; exit 1; }
                shift 2
                ;;
            *)
                usage
                ;;
        esac
    done

    if [ -n "$new_version" ]; then
        set_version "$new_version"
    fi

    run_tests
    mkdir -p "$DIST_DIR"

    case "$target" in
        deb)      build_deb;      write_checksums ;;
        rpm)      build_rpm;      write_checksums ;;
        arch)     build_arch;     write_checksums ;;
        appimage) build_appimage; write_checksums ;;
        flatpak)  build_flatpak;  write_checksums ;;
        all)
            local results=()
            for fn in build_deb build_rpm build_arch build_appimage build_flatpak; do
                if "$fn"; then
                    results+=("${fn#build_}: built")
                else
                    results+=("${fn#build_}: skipped (see message above)")
                fi
            done
            write_checksums
            echo ""
            echo "=== Build summary ==="
            printf '%s\n' "${results[@]}"
            ;;
        *) usage ;;
    esac
}

main "$@"
