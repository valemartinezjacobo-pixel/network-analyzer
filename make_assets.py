#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Genera los recursos gráficos del instalador de macOS:
  - assets/icon_1024.png  + carpeta netaudit.iconset (todas las resoluciones)
  - assets/dmg_background.png

Requiere Pillow (se instala en el runner de CI). Estética: squircle oscuro
con un radar en degradado teal/azul, al estilo de un icono de app de Apple.
"""

import math
import os

from PIL import Image, ImageDraw, ImageFont

# Compatibilidad con Pillow nuevo (Resampling) y antiguo
try:
    LANCZOS = Image.Resampling.LANCZOS
except AttributeError:
    LANCZOS = Image.LANCZOS

ASSETS = "assets"
os.makedirs(ASSETS, exist_ok=True)

BG_TOP    = (15, 59, 46)     # teal profundo
BG_BOTTOM = (11, 15, 23)     # casi negro azulado
ACC       = (55, 211, 154)   # verde
ACC2      = (74, 163, 255)   # azul
WARN      = (255, 180, 84)
TXT       = (231, 237, 245)
MUTED     = (107, 122, 147)


def _font(size, bold=False):
    paths = [
        "/System/Library/Fonts/SFNSDisplay.ttf",
        "/System/Library/Fonts/Supplemental/Helvetica.ttc",
        "/Library/Fonts/Arial Bold.ttf" if bold else "/Library/Fonts/Arial.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf" if bold
        else "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    ]
    for p in paths:
        try:
            return ImageFont.truetype(p, size)
        except Exception:
            continue
    return ImageFont.load_default()


def vertical_gradient(size, top, bottom):
    w, h = size
    base = Image.new("RGB", size, top)
    draw = ImageDraw.Draw(base)
    for y in range(h):
        t = y / max(1, h - 1)
        # ease para un degradado más suave
        t = t * t * (3 - 2 * t)
        col = tuple(int(top[i] + (bottom[i] - top[i]) * t) for i in range(3))
        draw.line([(0, y), (w, y)], fill=col)
    return base


def make_icon(size=1024):
    S = size
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    # squircle con máscara redondeada
    grad = vertical_gradient((S, S), BG_TOP, BG_BOTTOM).convert("RGBA")
    mask = Image.new("L", (S, S), 0)
    md = ImageDraw.Draw(mask)
    r = int(S * 0.225)
    md.rounded_rectangle([0, 0, S - 1, S - 1], radius=r, fill=255)
    img.paste(grad, (0, 0), mask)

    d = ImageDraw.Draw(img)
    cx = cy = S / 2
    # brillo sutil arriba
    glow = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    gd = ImageDraw.Draw(glow)
    gd.ellipse([S * 0.1, -S * 0.35, S * 0.9, S * 0.45], fill=(55, 211, 154, 26))
    glow.putalpha(glow.split()[3])
    img.alpha_composite(Image.composite(glow, Image.new("RGBA", (S, S)), mask))

    # radar: arcos concéntricos
    rings = [(0.34, ACC, 11), (0.24, ACC2, 9), (0.14, (43, 111, 90), 7)]
    for frac, col, wdt in rings:
        rr = S * frac
        w = max(3, int(wdt * S / 1024))
        d.ellipse([cx - rr, cy - rr, cx + rr, cy + rr], outline=col + (255,), width=w)

    # sector de barrido (gradiente angular falso con varias líneas)
    R = S * 0.34
    for i in range(60):
        ang = math.radians(-55 + i * 0.9)
        a = int(120 * (1 - i / 60))
        d.line([cx, cy, cx + R * math.cos(ang), cy + R * math.sin(ang)],
               fill=ACC + (a,), width=max(2, int(2 * S / 1024)))
    # línea principal
    d.line([cx, cy, cx + R * math.cos(math.radians(-55)),
            cy + R * math.sin(math.radians(-55))], fill=ACC + (255,),
           width=max(4, int(5 * S / 1024)))

    # nodos
    def dot(fx, fy, col, rad=0.022):
        rr = S * rad
        px, py = cx + S * fx, cy + S * fy
        d.ellipse([px - rr, py - rr, px + rr, py + rr], fill=col + (255,))
    dot(0, 0, ACC, 0.028)
    dot(0.20, -0.12, ACC2)
    dot(-0.18, 0.16, WARN)
    dot(0.10, 0.22, ACC2, 0.016)

    img.save(os.path.join(ASSETS, "icon_1024.png"))

    # iconset con todas las resoluciones que pide iconutil
    iconset = "netaudit.iconset"
    os.makedirs(iconset, exist_ok=True)
    specs = [(16, 1), (16, 2), (32, 1), (32, 2), (128, 1), (128, 2),
             (256, 1), (256, 2), (512, 1), (512, 2)]
    for base, scale in specs:
        px = base * scale
        name = f"icon_{base}x{base}{'@2x' if scale == 2 else ''}.png"
        img.resize((px, px), LANCZOS).save(os.path.join(iconset, name))
    print("icono generado:", os.path.join(ASSETS, "icon_1024.png"))


def make_dmg_background(w=640, h=420):
    img = vertical_gradient((w, h), (16, 22, 34), (11, 15, 23)).convert("RGBA")
    d = ImageDraw.Draw(img)
    # wordmark
    f_title = _font(34, bold=True)
    f_sub = _font(16)
    d.text((w / 2, 54), "netaudit", font=f_title, fill=TXT, anchor="mm")
    d.text((w / 2, 88), "Auditoría de red · arrastra la app a Aplicaciones",
           font=f_sub, fill=MUTED, anchor="mm")
    # flecha guía entre la app (izq) y Aplicaciones (der)
    y = h * 0.62
    x1, x2 = w * 0.40, w * 0.60
    d.line([(x1, y), (x2, y)], fill=ACC + (180,), width=4)
    d.polygon([(x2, y - 10), (x2 + 18, y), (x2, y + 10)], fill=ACC + (220,))
    img.convert("RGB").save(os.path.join(ASSETS, "dmg_background.png"))
    # versión @2x para retina
    img2 = img.resize((w * 2, h * 2), LANCZOS)
    img2.convert("RGB").save(os.path.join(ASSETS, "dmg_background@2x.png"))
    print("fondo DMG generado:", os.path.join(ASSETS, "dmg_background.png"))


if __name__ == "__main__":
    make_icon()
    make_dmg_background()
