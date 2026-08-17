"""
platform_support.py

Makes the app behave the same on every Linux distribution.

Distributions differ in three annoying ways:

* the package manager and package name used to install Tor
* the group that owns Tor's control authentication cookie
  (debian-tor on Debian/Ubuntu/Kali, toranon on Fedora/RHEL, tor on Arch)
* where the tor binary lives (/usr/bin vs /usr/sbin vs /usr/local/bin)

Rather than assuming Debian like most scripts do, we detect the distribution
and give the user the exact command for *their* system.
"""

from __future__ import annotations

import getpass
import grp
import os
import shutil
from dataclasses import dataclass

# Places Tor may live. /usr/sbin is not always on a normal user's PATH, which
# is a common reason "tor is installed" but shutil.which() cannot find it.
TOR_SEARCH_PATHS = (
    "/usr/bin/tor",
    "/usr/sbin/tor",
    "/usr/local/bin/tor",
    "/usr/local/sbin/tor",
    "/bin/tor",
    "/opt/tor/bin/tor",
)


@dataclass(frozen=True)
class DistroProfile:
    distro_id: str
    name: str
    install_command: str
    tor_group: str
    service_command: str


# Keyed by the ID (or ID_LIKE) field of /etc/os-release.
_PROFILES = {
    "debian": DistroProfile(
        "debian", "Debian/Ubuntu", "sudo apt install tor", "debian-tor",
        "sudo systemctl start tor",
    ),
    "ubuntu": DistroProfile(
        "ubuntu", "Ubuntu", "sudo apt install tor", "debian-tor",
        "sudo systemctl start tor",
    ),
    "kali": DistroProfile(
        "kali", "Kali Linux", "sudo apt install tor", "debian-tor",
        "sudo systemctl start tor",
    ),
    "fedora": DistroProfile(
        "fedora", "Fedora", "sudo dnf install tor", "toranon",
        "sudo systemctl start tor",
    ),
    "rhel": DistroProfile(
        "rhel", "RHEL/CentOS", "sudo dnf install tor", "toranon",
        "sudo systemctl start tor",
    ),
    "arch": DistroProfile(
        "arch", "Arch Linux", "sudo pacman -S tor", "tor",
        "sudo systemctl start tor",
    ),
    "opensuse": DistroProfile(
        "opensuse", "openSUSE", "sudo zypper install tor", "tor",
        "sudo systemctl start tor",
    ),
    "alpine": DistroProfile(
        "alpine", "Alpine Linux", "sudo apk add tor", "tor",
        "sudo rc-service tor start",
    ),
    "void": DistroProfile(
        "void", "Void Linux", "sudo xbps-install -S tor", "tor",
        "sudo sv up tor",
    ),
    "gentoo": DistroProfile(
        "gentoo", "Gentoo", "sudo emerge net-vpn/tor", "tor",
        "sudo rc-service tor start",
    ),
}

_FALLBACK = DistroProfile(
    "linux", "Linux", "install the 'tor' package with your package manager",
    "debian-tor", "start the tor service",
)


def detect_distro() -> DistroProfile:
    """Identify the distribution from /etc/os-release."""
    fields: dict[str, str] = {}
    try:
        with open("/etc/os-release", encoding="utf-8") as f:
            for line in f:
                if "=" in line:
                    key, _, value = line.partition("=")
                    fields[key.strip()] = value.strip().strip('"').strip("'")
    except OSError:
        return _FALLBACK

    distro_id = fields.get("ID", "").lower()
    if distro_id in _PROFILES:
        return _PROFILES[distro_id]

    # ID_LIKE lets derivatives (Mint, Pop!_OS, Manjaro, Nobara...) resolve to
    # their parent distribution.
    for like in fields.get("ID_LIKE", "").lower().split():
        if like in _PROFILES:
            base = _PROFILES[like]
            pretty = fields.get("PRETTY_NAME") or fields.get("NAME") or base.name
            return DistroProfile(
                distro_id or like, pretty, base.install_command,
                base.tor_group, base.service_command,
            )

    return _FALLBACK


def find_tor_binary() -> str | None:
    """Locate the tor executable, including paths outside a user's PATH."""
    found = shutil.which("tor")
    if found:
        return found
    for path in TOR_SEARCH_PATHS:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return None


def tor_is_installed() -> bool:
    return find_tor_binary() is not None


def user_in_tor_group(profile: DistroProfile | None = None) -> bool | None:
    """
    Check whether the current user can read Tor's control cookie.

    Returns True/False, or None if the group does not exist on this system
    (in which case cookie permissions are not the relevant problem).
    """
    profile = profile or detect_distro()
    try:
        group = grp.getgrnam(profile.tor_group)
    except KeyError:
        return None

    username = getpass.getuser()
    if username in group.gr_mem:
        return True
    try:
        return group.gr_gid in os.getgroups()
    except OSError:
        return False


def permission_fix_instructions(profile: DistroProfile | None = None) -> str:
    """The exact commands this user needs, for their distribution."""
    profile = profile or detect_distro()
    return (
        f"Add yourself to Tor's group so the app can control it:\n\n"
        f"    sudo usermod -aG {profile.tor_group} $USER\n\n"
        f"Then log out and back in for it to take effect.\n\n"
        f"Alternatively, stop the system Tor and let this app run its own:\n\n"
        f"    sudo systemctl stop tor"
    )


def install_instructions(profile: DistroProfile | None = None) -> str:
    profile = profile or detect_distro()
    return (
        f"Tor is not installed.\n\n"
        f"Detected: {profile.name}\n\n"
        f"Install it with:\n\n    {profile.install_command}"
    )
