#!/usr/bin/env python3
"""Render an ANSI terminal dump to a PNG so a TUI layout can be reviewed as an
image rather than guessed at from escape codes.

Usage: render_terminal.py <input.txt> <output.png> [--title "..."]

The input is the stdout of the TUI screen dump. Escape sequences are parsed for
bold, faint, reverse video and the 256-colour SGR codes that the interface
uses; anything it cannot parse is treated as plain text. Character cells are
assumed to be one column wide apart from the box-drawing, block and arrow
ranges, which are also single width in the fonts used here.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

# Cell geometry. A monospace cell is roughly 0.6 of the font size wide.
FONT_SIZE = 17
CELL_W = 10
CELL_H = 22
PAD = 18

# A dark terminal, matching the common case the tool is used in.
BG = (16, 17, 20)
FG = (222, 224, 228)

ANSI_RE = re.compile(r"\x1b\[([0-9;]*)m")

# The xterm 256-colour cube plus greyscale ramp, which is what lipgloss emits.
CUBE = [0, 95, 135, 175, 215, 255]


def colour_256(n: int) -> tuple[int, int, int]:
    if n < 16:
        base = [
            (0, 0, 0), (170, 0, 0), (0, 170, 0), (170, 85, 0),
            (0, 0, 170), (170, 0, 170), (0, 170, 170), (170, 170, 170),
            (85, 85, 85), (255, 85, 85), (85, 255, 85), (255, 255, 85),
            (85, 85, 255), (255, 85, 255), (85, 255, 255), (255, 255, 255),
        ]
        return base[n]
    if n < 232:
        n -= 16
        return (CUBE[n // 36], CUBE[(n // 6) % 6], CUBE[n % 6])
    v = 8 + (n - 232) * 10
    return (v, v, v)


class Style:
    def __init__(self) -> None:
        self.bold = False
        self.faint = False
        self.reverse = False
        self.fg: tuple[int, int, int] | None = None
        self.bg: tuple[int, int, int] | None = None

    def apply(self, params: str) -> None:
        codes = [int(p) for p in params.split(";") if p != ""] or [0]
        i = 0
        while i < len(codes):
            c = codes[i]
            if c == 0:
                self.__init__()
            elif c == 1:
                self.bold = True
            elif c == 2:
                self.faint = True
            elif c == 7:
                self.reverse = True
            elif c == 22:
                self.bold = self.faint = False
            elif c == 27:
                self.reverse = False
            elif c == 39:
                self.fg = None
            elif c == 49:
                self.bg = None
            elif c in (38, 48) and i + 2 < len(codes) and codes[i + 1] == 5:
                col = colour_256(codes[i + 2])
                if c == 38:
                    self.fg = col
                else:
                    self.bg = col
                i += 2
            i += 1

    def ink(self) -> tuple[int, int, int]:
        fg = self.fg if self.fg is not None else FG
        if self.reverse:
            return self.bg if self.bg is not None else BG
        if self.faint:
            # Stand in for SGR 2 with a blend towards the background.
            return tuple(int(fg[k] * 0.55 + BG[k] * 0.45) for k in range(3))
        return fg

    def paper(self) -> tuple[int, int, int]:
        if self.reverse:
            return self.fg if self.fg is not None else FG
        return self.bg if self.bg is not None else BG


def load_font(size: int) -> ImageFont.FreeTypeFont:
    candidates = [
        r"C:\Windows\Fonts\consola.ttf",
        r"C:\Windows\Fonts\CascadiaMono.ttf",
        r"C:\Windows\Fonts\lucon.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        "/System/Library/Fonts/Menlo.ttc",
    ]
    for path in candidates:
        if Path(path).exists():
            try:
                return ImageFont.truetype(path, size)
            except OSError:
                continue
    return ImageFont.load_default()


def parse(stream: str) -> list[list[tuple[str, Style]]]:
    """Split the stream into rows of (text, style) cells."""
    rows: list[list[tuple[str, Style]]] = []
    style = Style()
    for raw in stream.split("\n"):
        row: list[tuple[str, Style]] = []
        pos = 0
        for m in ANSI_RE.finditer(raw):
            if m.start() > pos:
                row.append((raw[pos:m.start()], style))
            style.apply(m.group(1))
            pos = m.end()
        if pos < len(raw):
            row.append((raw[pos:], style))
        rows.append(row)
    return rows


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("input")
    ap.add_argument("output")
    ap.add_argument("--title", default="")
    ap.add_argument("--scale", type=float, default=1.0)
    args = ap.parse_args()

    text = Path(args.input).read_text(encoding="utf-8", errors="replace")
    rows = parse(text)

    width_cells = max((sum(len(t) for t, _ in row) for row in rows), default=1)
    height_cells = len(rows)

    cell_w = int(CELL_W * args.scale)
    cell_h = int(CELL_H * args.scale)
    font = load_font(int(FONT_SIZE * args.scale))

    top = PAD + (int(20 * args.scale) if args.title else 0)
    img_w = width_cells * cell_w + PAD * 2
    img_h = height_cells * cell_h + top + PAD
    img = Image.new("RGB", (img_w, img_h), BG)
    draw = ImageDraw.Draw(img)

    if args.title:
        draw.text((PAD, PAD - 4), args.title, font=font, fill=(150, 155, 165))

    for r, row in enumerate(rows):
        y = top + r * cell_h
        x = PAD
        for chunk, style in row:
            if chunk:
                draw.rectangle([x, y, x + len(chunk) * cell_w, y + cell_h], fill=style.paper())
                draw.text((x, y + 1), chunk, font=font, fill=style.ink())
                x += len(chunk) * cell_w

    # A hairline frame makes it read as a captured screen rather than a crop.
    draw.rectangle([0, 0, img_w - 1, img_h - 1], outline=(48, 50, 56))
    img.save(args.output)
    print(f"wrote {args.output} ({img_w}x{img_h}, {width_cells}x{height_cells} cells)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
