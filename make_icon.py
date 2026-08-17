"""
Generates the application icon set at every size Linux desktops expect,
from the real Veilwire brand mark.

Source: icons/brand/veilwire-mark.png (RGBA, non-square). Each output size
is a square canvas with the mark fit inside it, aspect ratio preserved and
never stretched or distorted, padded with full transparency rather than
any solid color - the mark is meant to blend into whatever background a
desktop's icon theme puts behind it.

Run this only when the brand mark changes:

    python3 make_icon.py
"""

from __future__ import annotations

import os

from PIL import Image

SIZES = (16, 24, 32, 48, 64, 128, 256, 512)
SOURCE = os.path.join("icons", "brand", "veilwire-mark.png")


def _fit_on_square(source: Image.Image, size: int) -> Image.Image:
    """Scale `source` to fit within a `size`x`size` transparent canvas,
    preserving aspect ratio - never crops, stretches, or adds an opaque
    background."""
    sw, sh = source.size
    scale = min(size / sw, size / sh)
    new_w, new_h = max(1, round(sw * scale)), max(1, round(sh * scale))
    resized = source.resize((new_w, new_h), Image.LANCZOS)

    canvas = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    offset = ((size - new_w) // 2, (size - new_h) // 2)
    canvas.paste(resized, offset, resized)
    return canvas


def main() -> None:
    base_dir = os.path.dirname(os.path.abspath(__file__))
    out_dir = os.path.join(base_dir, "icons")
    os.makedirs(out_dir, exist_ok=True)

    source = Image.open(os.path.join(base_dir, SOURCE)).convert("RGBA")

    for size in SIZES:
        _fit_on_square(source, size).save(os.path.join(out_dir, f"veilwire-{size}.png"))

    # The default icon the app loads directly.
    _fit_on_square(source, 256).save(os.path.join(out_dir, "veilwire.png"))

    print(f"Wrote {len(SIZES) + 1} PNGs to {out_dir}")


if __name__ == "__main__":
    main()
