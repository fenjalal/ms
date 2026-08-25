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
    envelope.py
    group_invite.py
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

# Small load-bearing UI icons (verified badge, person/group avatar glyph -
# see app.py:ui_icon_path) - PNGs, not the SVGs this folder used to hold,
# since QSvgRenderer needs the optional PySide6.QtSvg module that is not
# guaranteed present everywhere this app runs (see app.py's ui_icon()).
mkdir -p "$DEST/icons/ui"
cp "$REPO_ROOT"/icons/ui/*.png "$DEST/icons/ui/"

# Compiled translations only (.qm) - the .ts sources are human/agent-
# editable development files, not needed at runtime (see i18n.py's
# install_language(), which loads .qm directly).
mkdir -p "$DEST/translations"
cp "$REPO_ROOT"/translations/*.qm "$DEST/translations/"

# Strip every non-pixel PNG chunk (EXIF, XMP/Adobe private chunks, text
# comments, embedded creation timestamps, an AI tool's provenance/
# InstanceID metadata) from every image this package ships - a source PNG
# under icons/ can pick up any of that from whatever editor/tool produced
# it (verified empirically: some of this repo's own brand illustrations
# carried exactly this - see strip_image_metadata.py's docstring), and
# none of it belongs in a distributed package regardless of which image it
# came from. Applied here, in the one shared staging step every packaging
# format already goes through, rather than trusted to be remembered by
# hand before each new image is added.
python3 "$REPO_ROOT/strip_image_metadata.py" "$DEST"/icons/*.png "$DEST"/icons/brand/*.png "$DEST"/icons/ui/*.png

echo "Staged application source into $DEST"
