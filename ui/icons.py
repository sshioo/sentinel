"""Iconos de Font Awesome Free (licencia SIL OFL), dibujados con Pillow y en caché."""
import customtkinter as ctk
from PIL import Image, ImageDraw, ImageFont

from config import PROJECT_DIR

_FONT = PROJECT_DIR / "assets" / "fa-solid-900.ttf"
GLYPHS = {
    "home": "\uf015", "activity": "\uf83e", "reports": "\uf15c", "config": "\uf013",
    "arrow": "\uf061", "shield": "\uf3ed", "upload": "\uf093", "alert": "\uf071",
    "check": "\uf00c", "circle": "\uf111", "bolt": "\uf0e7", "file": "\uf15b",
    "chart": "\uf201", "play": "\uf04b", "pause": "\uf04c",
}
_cache = {}


def icon(name, size=18, color="#9296A2"):
    """CTkImage del icono, a 4x para que los bordes salgan suaves."""
    key = (name, size, color)
    img = _cache.get(key)
    if img is None:
        big = size * 4
        canvas = Image.new("RGBA", (big, big), (0, 0, 0, 0))
        try:
            font = ImageFont.truetype(str(_FONT), int(big * 0.78))
            d = ImageDraw.Draw(canvas)
            d.text((big / 2, big / 2), GLYPHS[name], font=font, fill=color, anchor="mm")
        except OSError:
            pass
        img = ctk.CTkImage(light_image=canvas, dark_image=canvas, size=(size, size))
        _cache[key] = img
    return img


