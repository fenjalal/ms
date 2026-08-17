#!/usr/bin/env bash
# Shared by every packaging/<format>/build.sh: stages the ONE application
# source tree into a destination directory. This is what makes "one
# codebase, many packages" a structural fact rather than a promise - no
# packaging format's build script has its own copy of app.py/crypto.py/
# vault.py/transport.py/tor_service.py/etc. They all call this.
#
# Usage: copy-source.sh <repo_root> <destination_dir>
set -euo pipefail

REPO_ROOT="$1"
DEST="$2"

mkdir -p "$DEST"

# Runtime application modules. Explicitly NOT make_icon.py (a dev-only
# tool that regenerates icon PNGs from source and needs Pillow, which is
# not a runtime dependency of the application - shipping it would pull in
# an unnecessary dependency and unused code for every end user) and
# explicitly NOT any test_*.py file (development-only, not part of what
# runs when a user launches the app).
APP_MODULES=(
    app.py
    bundle.py
    crypto.py
    i18n.py
    paths.py
    platform_support.py
    theme.py
    tor_service.py
    transport.py
    vault.py
    version.py
)

for module in "${APP_MODULES[@]}"; do
    cp "$REPO_ROOT/$module" "$DEST/$module"
done

mkdir -p "$DEST/icons"
cp "$REPO_ROOT"/icons/veilwire*.png "$DEST/icons/"

# The four independent brand illustrations app.py loads at runtime for
# empty-state/security-section/send-button decoration (see
# app.py:brand_image_path) - not just the app-icon set above.
mkdir -p "$DEST/icons/brand"
cp "$REPO_ROOT"/icons/brand/*.png "$DEST/icons/brand/"

# Compiled translations only (.qm) - the .ts sources are human/agent-
# editable development files, not needed at runtime (see i18n.py's
# install_language(), which loads .qm directly).
mkdir -p "$DEST/translations"
cp "$REPO_ROOT"/translations/*.qm "$DEST/translations/"

echo "Staged application source into $DEST"
