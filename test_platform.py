"""
Tests for cross-distribution support and the health monitor.

These cover the parts that make the app behave identically on any Linux
system, and the checks that notice when the onion service silently dies.
"""

from __future__ import annotations

from unittest.mock import MagicMock, mock_open, patch

import platform_support as ps
import tor_service as ts

results: list[tuple[str, bool]] = []


def check(label: str, condition: bool) -> None:
    results.append((label, condition))
    print(f"  {'PASS' if condition else 'FAIL'}  {label}")


def os_release(content: str):
    return patch("builtins.open", mock_open(read_data=content))


def main() -> None:
    print("\nDistribution detection:")

    expectations = [
        ("ID=debian", "apt", "debian-tor"),
        ("ID=ubuntu", "apt", "debian-tor"),
        ("ID=kali\nID_LIKE=debian", "apt", "debian-tor"),
        ("ID=fedora", "dnf", "toranon"),
        ("ID=arch", "pacman", "tor"),
        ("ID=alpine", "apk", "tor"),
        ("ID=void", "xbps", "tor"),
        ("ID=gentoo", "emerge", "tor"),
        ("ID=opensuse", "zypper", "tor"),
    ]
    for content, expected_pm, expected_group in expectations:
        with os_release(content):
            profile = ps.detect_distro()
        ok = expected_pm in profile.install_command and profile.tor_group == expected_group
        check(f"{content.splitlines()[0]:28s} -> {expected_pm}/{expected_group}", ok)

    print("\nDerivatives resolve to their parent:")
    derivatives = [
        ("ID=linuxmint\nID_LIKE=ubuntu", "apt"),
        ("ID=pop\nID_LIKE=\"ubuntu debian\"", "apt"),
        ("ID=manjaro\nID_LIKE=arch", "pacman"),
        ("ID=nobara\nID_LIKE=fedora", "dnf"),
        ("ID=endeavouros\nID_LIKE=arch", "pacman"),
    ]
    for content, expected_pm in derivatives:
        with os_release(content):
            profile = ps.detect_distro()
        check(f"{content.splitlines()[0]:28s} -> {expected_pm}", expected_pm in profile.install_command)

    print("\nUnknown distributions degrade gracefully:")
    with os_release("ID=someweirdos"):
        profile = ps.detect_distro()
    check("unknown distro returns a usable profile", bool(profile.install_command))
    with patch("builtins.open", side_effect=OSError):
        profile = ps.detect_distro()
    check("missing /etc/os-release handled", bool(profile.install_command))

    print("\nTor binary discovery:")
    with patch("shutil.which", return_value=None), \
         patch("os.path.isfile", side_effect=lambda p: p == "/usr/sbin/tor"), \
         patch("os.access", return_value=True):
        found = ps.find_tor_binary()
    check("finds /usr/sbin/tor when not on PATH", found == "/usr/sbin/tor")

    with patch("shutil.which", return_value=None), \
         patch("os.path.isfile", return_value=False):
        check("reports missing tor correctly", ps.find_tor_binary() is None)

    print("\nInstructions are distro-specific:")
    with os_release("ID=fedora"):
        text = ps.permission_fix_instructions()
    check("Fedora instructions mention toranon", "toranon" in text)
    with os_release("ID=arch"):
        text = ps.install_instructions()
    check("Arch instructions mention pacman", "pacman" in text)

    print("\nHealth checks:")
    controller = MagicMock()
    manager = ts.TorManager("/tmp/unused")
    manager._controller = controller
    manager.service = ts.OnionService("abc.onion", "ED25519-V3:KEY", "abc")

    controller.get_info.return_value = "0.4.8.10"
    check("live controller detected", manager.is_controller_alive())

    controller.get_info.side_effect = Exception("gone")
    check("dead controller detected", not manager.is_controller_alive())
    controller.get_info.side_effect = None

    controller.get_info.return_value = "1"
    check("circuits detected", manager.circuit_established())
    controller.get_info.return_value = "0"
    check("missing circuits detected", not manager.circuit_established())

    controller.list_ephemeral_hidden_services.return_value = ["abc"]
    check("published service detected", manager.is_service_published())
    controller.list_ephemeral_hidden_services.return_value = []
    check("vanished service detected", not manager.is_service_published())

    response = MagicMock()
    response.service_id = "abc"
    response.private_key = "KEY"
    response.private_key_type = "ED25519-V3"
    controller.create_ephemeral_hidden_service.return_value = response
    service = manager.republish(5555)
    call = controller.create_ephemeral_hidden_service.call_args
    check("republish reuses the stored key", call[1]["key_content"] == "KEY")
    check("republish keeps the same address", service.onion == "abc.onion")

    passed = sum(1 for _, ok in results if ok)
    print(f"\n{passed}/{len(results)} checks passed")
    if passed != len(results):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
