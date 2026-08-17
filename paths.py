"""
paths.py

Single source of truth for where Veilwire's user data lives on disk.

Application files (this source tree, or an installed copy under
/usr/lib/veilwire) are never where user data goes - that directory is
package-owned, read-only to the running user once installed, and gets
replaced wholesale on every upgrade. User data - the encrypted vault.dat
and Tor's own data directory - lives under the XDG Base Directory locations
instead, which:

* survive package upgrade/reinstall/uninstall (nothing under /usr/lib
  ever touches them)
* work correctly for a source checkout, a distro package (.deb/.rpm/Arch),
  an AppImage, and a Flatpak with no format-specific code - Flatpak sets
  XDG_DATA_HOME/XDG_CONFIG_HOME to its own sandboxed locations before the
  app ever runs, so respecting those environment variables (rather than
  hardcoding ~/.local/share) is what makes this automatically correct
  inside a Flatpak sandbox too.

The directory name itself ("veilwire") is a literal, not derived from
version.APP_NAME - a future display-name change must never silently move
where a user's identity and message history live.
"""

from __future__ import annotations

import os

_DIR_NAME = "veilwire"


def _ensure_private_dir(path: str) -> str:
    """
    Create `path` (and parents) at mode 0700 if it doesn't exist, and
    enforce 0700 even if it already existed.

    os.makedirs(mode=...) only applies its mode to directories it actually
    creates - exist_ok=True silently leaves a pre-existing directory at
    whatever mode it already had (e.g. inherited from an earlier umask, or
    a prior version of the app). Since this directory holds vault.dat and
    Tor's data directory, its own permissions matter too: a
    group/world-readable directory leaks filenames/sizes/mtimes even
    though vault.dat itself is separately written 0600.
    """
    os.makedirs(path, mode=0o700, exist_ok=True)
    os.chmod(path, 0o700)
    return path


def data_dir() -> str:
    """Where vault.dat and Tor's data directory live. Created on first use."""
    base = os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share")
    return _ensure_private_dir(os.path.join(base, _DIR_NAME))


def config_dir() -> str:
    """Reserved for future configuration use. Created on first use."""
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    return _ensure_private_dir(os.path.join(base, _DIR_NAME))
