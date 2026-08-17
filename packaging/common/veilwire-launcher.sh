#!/bin/sh
# Installed as /usr/bin/veilwire by every distro package format.
#
# Deliberately dependency-free (POSIX sh, no bashisms) and dependent on
# nothing but the absolute path baked in here at package-build time - no
# cd, no $PWD, no reliance on the current working directory, no source-repo
# assumption. app.py resolves its own icon/data/tor paths (see paths.py and
# app.py's icon_file()) via its own installed location and XDG environment
# variables, never via how it was invoked.
#
# Runtime dependency check, before exec'ing into Python: package managers
# (apt/dnf/pacman) already install every declared dependency automatically
# when the package itself is installed correctly (apt install ./file.deb,
# dnf install ./file.rpm, pacman -U ./file.pkg.tar.zst all resolve
# dependencies on their own - that's what Depends:/Requires:/depends()
# already declare, and nothing extra needs to be added there). This check
# exists only as a safety net for the one common mistake that bypasses
# that: running `dpkg -i` directly, which unpacks files but does NOT fetch
# missing dependencies from the repositories. Rather than let a missing
# module surface as a confusing Python ImportError traceback, fail fast
# here with one clear line and the exact command to fix it - no attempt
# to silently auto-install anything (that would mean this script running
# `sudo` unattended, which it never does).
missing=""
for module in PySide6 nacl stem socks segno; do
    if ! python3 -c "import $module" >/dev/null 2>&1; then
        missing="$missing $module"
    fi
done

if [ -n "$missing" ]; then
    echo "Veilwire is missing required Python packages:$missing" >&2
    echo >&2
    if command -v apt >/dev/null 2>&1; then
        echo "Fix with: sudo apt install -f" >&2
    elif command -v dnf >/dev/null 2>&1; then
        echo "Fix with: sudo dnf install python3-pyside6 python3-pynacl python3-stem python3-pysocks python3-segno" >&2
    elif command -v pacman >/dev/null 2>&1; then
        echo "Fix with: sudo pacman -S pyside6 python-pynacl python-stem python-pysocks python-segno" >&2
    else
        echo "Install the missing Python packages listed above using your distribution's package manager." >&2
    fi
    exit 1
fi

if ! command -v tor >/dev/null 2>&1; then
    echo "Veilwire requires Tor, which is not installed or not on PATH." >&2
    echo >&2
    if command -v apt >/dev/null 2>&1; then
        echo "Fix with: sudo apt install tor" >&2
    elif command -v dnf >/dev/null 2>&1; then
        echo "Fix with: sudo dnf install tor" >&2
    elif command -v pacman >/dev/null 2>&1; then
        echo "Fix with: sudo pacman -S tor" >&2
    else
        echo "Install Tor using your distribution's package manager and restart Veilwire." >&2
    fi
    exit 1
fi

exec python3 /usr/lib/veilwire/app.py "$@"
