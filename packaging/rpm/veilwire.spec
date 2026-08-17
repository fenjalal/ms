%global app_name veilwire

Name:           veilwire
Version:        %{_veilwire_version}
Release:        1%{?dist}
Summary:        Peer-to-peer encrypted messenger over Tor
License:        MIT
URL:            https://github.com/yourname/veilwire
BuildArch:      x86_64
BuildRoot:      %{_tmppath}/%{name}-%{version}-build

# Fedora/RHEL package names. openSUSE names some of these differently
# (notably python3-PySide6 with different capitalization, and the Tor
# bindings/socks package split may vary) - adjust this Requires: line for
# openSUSE builds; documented here rather than silently assumed correct
# across every RPM-based distro.
Requires:       python3 >= 3.9
Requires:       python3-pyside6
Requires:       python3-pynacl
Requires:       python3-stem
Requires:       python3-pysocks
Requires:       python3-segno
Requires:       tor

%description
Veilwire is a serverless, peer-to-peer encrypted messenger that
communicates exclusively through Tor v3 onion services. There is no
server, no account, and no phone number - your onion address and public
key are your whole identity. Messages are end-to-end encrypted with NaCl
(X25519 + XSalsa20-Poly1305) on top of Tor's own transport encryption, and
the local vault is encrypted at rest with a key derived from your
passphrase via Argon2id.

This package installs the application under /usr/lib/veilwire and a
launcher at /usr/bin/veilwire. It depends on the distribution's own tor
package rather than bundling one, so Tor receives the distribution's
normal security updates.

# BUILD NOTE: this spec must be built with rpmbuild on a system that has
# it (Fedora/RHEL/Rocky/AlmaLinux, or a mock/container targeting one of
# those) - rpmbuild is not available on every Linux distribution (it is
# NOT present, for example, on the Debian/Kali machine this packaging
# system was developed on). Build with:
#
#   rpmbuild --define "_veilwire_version 1.0.0" \
#            --define "_topdir $(pwd)/rpmbuild" \
#            -bb packaging/rpm/veilwire.spec
#
# with the application source pre-staged into
# rpmbuild/BUILD/%{name}-%{version}/ by packaging/rpm/build.sh (see that
# script - it stages source via packaging/common/copy-source.sh, the same
# helper every other packaging format uses, so this spec never contains
# its own copy of the Python source).

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}/usr/lib/veilwire
mkdir -p %{buildroot}/usr/bin
mkdir -p %{buildroot}/usr/share/applications
mkdir -p %{buildroot}/usr/share/icons/hicolor

cp -r %{_sourcedir}/app/* %{buildroot}/usr/lib/veilwire/
install -m 0755 %{_sourcedir}/veilwire-launcher.sh %{buildroot}/usr/bin/veilwire
install -m 0644 %{_sourcedir}/veilwire.desktop %{buildroot}/usr/share/applications/veilwire.desktop

for size in 16 24 32 48 64 128 256 512; do
    if [ -f "%{_sourcedir}/icons/veilwire-${size}.png" ]; then
        mkdir -p "%{buildroot}/usr/share/icons/hicolor/${size}x${size}/apps"
        install -m 0644 "%{_sourcedir}/icons/veilwire-${size}.png" \
            "%{buildroot}/usr/share/icons/hicolor/${size}x${size}/apps/veilwire.png"
    fi
done

%files
%defattr(-,root,root,-)
/usr/lib/veilwire/
%attr(0755,root,root) /usr/bin/veilwire
/usr/share/applications/veilwire.desktop
/usr/share/icons/hicolor/*/apps/veilwire.png

# Refresh desktop/icon caches only - never touch a user's home directory.
# The vault is created by the application itself, running as the user, on
# first launch - not by any RPM scriptlet.
%post
update-desktop-database /usr/share/applications &>/dev/null || :
gtk-update-icon-cache -f -t /usr/share/icons/hicolor &>/dev/null || :

%postun
update-desktop-database /usr/share/applications &>/dev/null || :
gtk-update-icon-cache -f -t /usr/share/icons/hicolor &>/dev/null || :

%changelog
* Sat Aug 15 2026 Veilwire Project <veilwire@example.invalid> - 1.0.0-1
- Initial packaged release.
