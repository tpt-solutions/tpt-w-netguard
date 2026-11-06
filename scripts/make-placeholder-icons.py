#!/usr/bin/env python
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Generate placeholder app icons (solid TPT-blue badge) using only the standard library.

These are stand-ins so the Tauri build has icon files. Replace them with real TPT Solutions
branding (Phase 13) by running `npx tauri icon <source.png>` or by overwriting the files.

Outputs under src-tauri/icons/: icon.png (512x512) and icon.ico (PNG-compressed ICO, 256x256).
"""
import os
import struct
import zlib

OUT = os.path.join(os.path.dirname(__file__), "..", "src-tauri", "icons")
SIZE = 256
COLOR = (0x1F, 0x6F, 0xEB, 0xFF)  # blue badge
CENTER = (SIZE // 2, SIZE // 2)
RADIUS = SIZE * 0.36


def pixel(x, y):
    dx, dy = x - CENTER[0], y - CENTER[1]
    return COLOR if dx * dx + dy * dy <= RADIUS * RADIUS else (0, 0, 0, 0)


def png(width, height, rgba_fn):
    raw = bytearray()
    for y in range(height):
        raw.append(0)  # filter type: none
        for x in range(width):
            raw.extend(rgba_fn(x, y))

    def chunk(tag, data):
        body = tag + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)

    header = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)  # 8-bit RGBA
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", header)
        + chunk(b"IDAT", zlib.compress(bytes(raw), 9))
        + chunk(b"IEND", b"")
    )


def ico_from_png(png_bytes, size):
    # ICONDIR header, one ICONDIRENTRY, then the PNG payload (valid since Windows Vista).
    dim = 0 if size >= 256 else size
    header = struct.pack("<HHH", 0, 1, 1)
    entry = struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32, len(png_bytes), 6 + 16)
    return header + entry + png_bytes


def main():
    os.makedirs(OUT, exist_ok=True)
    big = png(SIZE, SIZE, pixel)
    with open(os.path.join(OUT, "icon.png"), "wb") as f:
        f.write(big)
    with open(os.path.join(OUT, "icon.ico"), "wb") as f:
        f.write(ico_from_png(big, SIZE))
    print("wrote placeholder icons to", os.path.normpath(OUT))


if __name__ == "__main__":
    main()
