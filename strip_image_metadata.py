#!/usr/bin/env python3
"""
Strips every non-pixel PNG chunk (EXIF, XMP/Adobe private chunks, text
comments, timestamps, colour-management chunks, anything else) from one or
more PNG files in place, keeping only the chunks that actually affect how
the image renders: IHDR, PLTE, tRNS, IDAT, IEND.

Run at package-build time (see packaging/common/copy-source.sh) so no
metadata an image editor/AI tool embedded - creation timestamps, an XMP
InstanceID, a generating tool's name/version - ever ships inside a
distributed package, regardless of what any individual source image in
icons/ happens to carry. Also usable standalone: `./strip_image_metadata.py
path/to/one.png path/to/two.png`.

Stdlib-only (struct + zlib for the CRC check) so this never needs Pillow or
any other runtime/build dependency.
"""

from __future__ import annotations

import struct
import sys
import zlib

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
KEEP_CHUNK_TYPES = {b"IHDR", b"PLTE", b"tRNS", b"IDAT", b"IEND"}


def strip_metadata(data: bytes) -> bytes:
    if data[:8] != PNG_SIGNATURE:
        raise ValueError("not a PNG file (bad signature)")

    out = bytearray(PNG_SIGNATURE)
    pos = 8
    while pos < len(data):
        length = struct.unpack(">I", data[pos:pos + 4])[0]
        ctype = data[pos + 4:pos + 8]
        chunk_end = pos + 12 + length
        if ctype in KEEP_CHUNK_TYPES:
            out += data[pos:chunk_end]
        pos = chunk_end
    return bytes(out)


def clean_file(path: str) -> tuple[int, int]:
    with open(path, "rb") as f:
        original = f.read()
    cleaned = strip_metadata(original)
    if cleaned != original:
        with open(path, "wb") as f:
            f.write(cleaned)
    return len(original), len(cleaned)


def main(argv: list[str]) -> int:
    if not argv:
        print("Usage: strip_image_metadata.py <file.png> [more.png ...]", file=sys.stderr)
        return 1
    for path in argv:
        before, after = clean_file(path)
        saved = before - after
        note = f"stripped {saved} bytes of metadata" if saved else "already clean"
        print(f"{path}: {note}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
