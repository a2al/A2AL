"""Generate assets/logo-400.png matching a2al.org brand styling."""
from __future__ import annotations

import os
from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter, ImageFont

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "assets" / "logo-400.png"

W, H = 400, 400
BG = (10, 15, 14)  # #0a0f0e
ACCENT = (0, 212, 170)  # #00d4aa


def load_font(size: int) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    candidates = [
        r"C:\Windows\Fonts\bahnschrift.ttf",
        r"C:\Windows\Fonts\arialbi.ttf",
        r"C:\Windows\Fonts\arialbd.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-BoldOblique.ttf",
        "/System/Library/Fonts/Supplemental/Arial Bold Italic.ttf",
    ]
    for path in candidates:
        if os.path.exists(path):
            return ImageFont.truetype(path, size)
    return ImageFont.load_default()


def main() -> None:
    img = Image.new("RGB", (W, H), BG)
    font = load_font(132)
    text = "A2AL"

    probe = ImageDraw.Draw(img)
    bbox = probe.textbbox((0, 0), text, font=font)
    tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
    x = (W - tw) // 2 - bbox[0]
    y = (H - th) // 2 - bbox[1] - 4

    glow = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    gdraw = ImageDraw.Draw(glow)
    gdraw.text((x, y), text, font=font, fill=(*ACCENT, 55))
    glow = glow.filter(ImageFilter.GaussianBlur(radius=10))

    img = Image.alpha_composite(img.convert("RGBA"), glow)
    draw = ImageDraw.Draw(img)
    draw.text((x, y), text, font=font, fill=ACCENT)

    OUT.parent.mkdir(parents=True, exist_ok=True)
    img.convert("RGB").save(OUT, "PNG")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
