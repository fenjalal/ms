# Veilwire 1.0.0

<!-- Fill in before publishing a release. -->

## Install (.deb)

```bash
sudo apt install ./veilwire_1.0.0_amd64.deb
```

Use `apt install ./file.deb`, **not** `sudo dpkg -i file.deb` — `dpkg -i`
does not fetch missing dependencies from your repositories and will fail
with "dependency problems" if `python3-stem`/`python3-segno`/etc. aren't
already installed. If you already hit that, run `sudo apt install -f` to
finish resolving them.

## Highlights

-

## Changes

-

## Upgrade notes

Existing vaults (identity, contacts, message history) are preserved
automatically across upgrades. No manual migration is required.

## Checksums

See `SHA256SUMS` in this directory.

## Known limitations

- Only `.deb` is built and installation-tested as part of this release
  process on this build machine. `.rpm`, Arch, AppImage, and Flatpak have
  complete packaging configurations but require their respective build
  tooling (rpmbuild, makepkg, appimagetool, flatpak-builder) which is not
  installed here - see `packaging/<format>/build.sh` for exact build
  commands and environment requirements for each.
