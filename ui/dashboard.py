"""Piezas del panel de inicio: tarjetas, mini gráficas, línea de riesgo y anillo.

Todo se dibuja con PIL a varias veces el tamaño final y se reduce con filtro,
igual que ui/widgets.py. Las imágenes son RGB y se dibuja con
ImageDraw(img, "RGBA") para que las transparencias se mezclen con el fondo.
"""
import time

import customtkinter as ctk
from PIL import Image, ImageChops, ImageDraw

from ui import theme as T
from ui.widgets import FRAME_MS, _AACanvas, ease_out, mix, rgb

CARD_BORDER = "#23262E"
_GRADIENTS = {}


def card(parent, **kw):
    return ctk.CTkFrame(parent, fg_color=T.SURFACE, corner_radius=14, border_width=1,
                        border_color=CARD_BORDER, **kw)


def _rgb(color):
    return rgb(color)[:3]


def smooth(points, steps=8):
    """Curva Catmull-Rom que pasa por todos los puntos."""
    if len(points) < 3:
        return list(points)
    pts = [points[0]] + list(points) + [points[-1]]
    out = []
    for i in range(1, len(pts) - 2):
        p0, p1, p2, p3 = pts[i - 1], pts[i], pts[i + 1], pts[i + 2]
        for s in range(steps):
            t = s / steps
            t2, t3 = t * t, t * t * t
            out.append(tuple(
                0.5 * (2 * p1[k] + (-p0[k] + p2[k]) * t
                       + (2 * p0[k] - 5 * p1[k] + 4 * p2[k] - p3[k]) * t2
                       + (-p0[k] + 3 * p1[k] - 3 * p2[k] + p3[k]) * t3)
                for k in (0, 1)))
    out.append(points[-1])
    return out


def _fade_mask(w, h, top_alpha):
    key = (w, h, top_alpha)
    mask = _GRADIENTS.get(key)
    if mask is None:
        if len(_GRADIENTS) > 6:
            _GRADIENTS.clear()
        col = Image.new("L", (1, h))
        px = col.load()
        for y in range(h):
            px[0, y] = int(top_alpha * (1 - y / h) ** 1.4)
        mask = col.resize((w, h))
        _GRADIENTS[key] = mask
    return mask


def _fill_under(img, curve, base_y, color, top_alpha):
    W, H = img.size
    poly = list(curve) + [(curve[-1][0], base_y), (curve[0][0], base_y)]
    area = Image.new("L", (W, H), 0)
    ImageDraw.Draw(area).polygon(poly, fill=255)
    img.paste(_rgb(color), (0, 0), ImageChops.multiply(_fade_mask(W, H, top_alpha), area))


class _Animated(_AACanvas):
    def _kick(self):
        self._last = time.perf_counter()
        if getattr(self, "_job", None) is None:
            self._tick()


class Sparkline(_Animated):
    SS = 3

    def __init__(self, master, width=110, height=44, color=T.PRIMARY, bg=T.SURFACE):
        super().__init__(master, width, height, bg)
        self.w, self.h, self.color = width, height, color
        self.values = []
        self.t0 = 0.0
        self._job = None
        self._render(1.0)

    def set(self, values):
        values = list(values)
        if values == self.values:
            return
        self.values = values
        self.t0 = time.perf_counter()
        self._kick()

    def _tick(self):
        k = min(1.0, (time.perf_counter() - self.t0) / 0.8)
        self._render(ease_out(k))
        self._job = self.after(FRAME_MS, self._tick) if k < 1 else None

    def _render(self, p):
        w, h, S = self.w, self.h, self.SS
        W, H = w * S, h * S
        img = Image.new("RGB", (W, H), _rgb(self.bg))
        d = ImageDraw.Draw(img, "RGBA")
        pad = 5 * S
        vals = self.values
        if len(vals) < 2:
            for x in range(pad, W - pad, 8 * S):
                d.line([(x, H / 2), (x + 4 * S, H / 2)], fill=rgb(T.BORDER), width=int(1.6 * S))
            self._present(img, w, h)
            return
        lo, hi = min(vals), max(vals)
        base = H - pad
        n = len(vals)
        raw = []
        for i, v in enumerate(vals):
            norm = (v - lo) / (hi - lo) if hi > lo else 0.5
            y = base - (H - 2 * pad) * (0.12 + 0.88 * norm)
            raw.append((pad + (W - 2 * pad) * i / (n - 1), base - (base - y) * p))
        curve = [(x, min(base, max(pad, y))) for x, y in smooth(raw, 6)]
        _fill_under(img, curve, base, self.color, 70)
        d = ImageDraw.Draw(img, "RGBA")
        d.line(curve, fill=rgb(self.color), width=int(2.2 * S), joint="curve")
        ex, ey = curve[-1]
        d.ellipse((ex - 6 * S, ey - 6 * S, ex + 6 * S, ey + 6 * S), fill=rgb(self.color, 60))
        d.ellipse((ex - 3 * S, ey - 3 * S, ex + 3 * S, ey + 3 * S), fill=rgb(self.color))
        self._present(img, w, h)


class KpiCard(ctk.CTkFrame):
    def __init__(self, master, title, color=T.TEXT, spark_color=T.PRIMARY):
        super().__init__(master, fg_color=T.SURFACE, corner_radius=14, border_width=1,
                         border_color=CARD_BORDER)
        self.grid_columnconfigure(0, weight=1)
        head = ctk.CTkFrame(self, fg_color="transparent")
        head.grid(row=0, column=0, columnspan=2, sticky="w", padx=18, pady=(14, 0))
        ctk.CTkLabel(head, text="●", font=(T.UI_FONT, 9), text_color=spark_color).pack(side="left")
        ctk.CTkLabel(head, text=title, font=(T.UI_FONT, 12), text_color=T.TEXT_SECONDARY).pack(
            side="left", padx=(6, 0))
        self.value = ctk.CTkLabel(self, text="0", font=(T.MONO_FONT, 32, "bold"), text_color=color,
                                  anchor="w")
        self.value.grid(row=1, column=0, sticky="w", padx=18, pady=(4, 0))
        self.spark = Sparkline(self, 110, 44, spark_color)
        self.spark.grid(row=1, column=1, sticky="e", padx=(0, 16))
        self.caption = ctk.CTkLabel(self, text="", font=(T.UI_FONT, 11), text_color=T.TEXT_SECONDARY,
                                    anchor="w", justify="left", wraplength=260)
        self.caption.grid(row=2, column=0, columnspan=2, sticky="w", padx=18, pady=(2, 14))
        self._shown = 0.0
        self._target = 0
        self._job = None

    def set(self, value, caption, series):
        self._target = value
        self.caption.configure(text=caption)
        self.spark.set(series)
        if self._job is None:
            self._count()

    def _count(self):
        gap = self._target - self._shown
        self._shown = self._target if abs(gap) < 0.6 else self._shown + gap * 0.16
        self.value.configure(text=f"{self._shown:.0f}")
        self._job = self.after(FRAME_MS, self._count) if self._shown != self._target else None


class RiskTimeline(_Animated):
    """Riesgo de los últimos análisis: un punto por archivo, color del veredicto."""

    SS = 2
    L, R, TOP, BOT = 38, 16, 14, 26
    LEVELS = (0, 25, 60, 100)

    def __init__(self, master, bg=T.SURFACE):
        super().__init__(master, 10, 10, bg)
        self.items = []
        self.active = False
        self.hover = None
        self.t0 = time.perf_counter()
        self._job = None
        self._pts = []
        self._bd_key = None
        self._frame_key = None
        mono = (T.MONO_FONT, 9)
        self._ylabels = {lv: self.create_text(0, 0, text=str(lv), anchor="e",
                                              fill=T.TEXT_DISABLED, font=mono)
                         for lv in self.LEVELS}
        self._band_hi = self.create_text(0, 0, text="PELIGRO", anchor="ne",
                                         fill=mix(T.DANGER, bg, 0.35), font=(T.UI_FONT, 8, "bold"))
        self._band_mid = self.create_text(0, 0, text="REVISAR", anchor="ne",
                                          fill=mix(T.WARNING, bg, 0.45), font=(T.UI_FONT, 8, "bold"))
        self._xl = self.create_text(0, 0, text="", anchor="w", fill=T.TEXT_DISABLED, font=mono)
        self._xr = self.create_text(0, 0, text="", anchor="e", fill=T.TEXT_DISABLED, font=mono)
        self._msg = self.create_text(0, 0, text="", fill=T.TEXT_SECONDARY, justify="center",
                                     font=(T.UI_FONT, 12))
        self._tip_bg = self.create_rectangle(0, 0, 0, 0, fill=T.ELEVATED, outline=T.BORDER,
                                             state="hidden")
        self._tip = self.create_text(0, 0, text="", anchor="s", fill=T.TEXT, state="hidden",
                                     font=(T.UI_FONT, 11, "bold"))
        self.bind("<Configure>", self._debounced_kick)
        self.bind("<Motion>", self._on_motion)
        self.bind("<Leave>", lambda _e: self._set_hover(None))

    def set(self, items):
        """items: [(score, estado, nombre)], del más antiguo al más reciente."""
        items = list(items)[-30:]
        if items == self.items:
            return
        self.items = items
        self.t0 = time.perf_counter()
        self._kick()

    def set_active(self, on):
        self.active = on
        self._kick()

    def _on_motion(self, event):
        best, dist = None, 26
        for i, (x, _y) in enumerate(self._pts):
            if abs(event.x - x) < dist:
                best, dist = i, abs(event.x - x)
        self._set_hover(best)

    def _set_hover(self, idx):
        if idx != self.hover:
            self.hover = idx
            self._kick()

    def _tick(self):
        if not self.winfo_ismapped():
            self._job = self.after(250, self._tick)
            return
        now = time.perf_counter()
        self._render(now)
        growing = now - self.t0 < 0.95
        if self.active or growing:
            self._job = self.after(self._delay(now), self._tick)
        else:
            self._job = None

    def _backdrop(self, w, h):
        """Zonas y rejilla: solo cambian al redimensionar, se dibujan una vez."""
        if self._bd_key != (w, h):
            S = self.SS
            x0, y0, x1, y1 = self.L, self.TOP, w - self.R, h - self.BOT
            img = Image.new("RGB", (w * S, h * S), _rgb(self.bg))
            d = ImageDraw.Draw(img, "RGBA")

            def Y(score):
                return (y1 - (y1 - y0) * score / 100) * S

            d.rectangle((x0 * S, Y(100), x1 * S, Y(60)), fill=rgb(T.DANGER, 16))
            d.rectangle((x0 * S, Y(60), x1 * S, Y(25)), fill=rgb(T.WARNING, 12))
            for lv in self.LEVELS:
                for x in range(int(x0 * S), int(x1 * S), 9 * S):
                    d.line([(x, Y(lv)), (x + 4 * S, Y(lv))], fill=rgb(T.BORDER, 200),
                           width=int(1.2 * S))
            self._bd, self._bd_key = img, (w, h)
        return self._bd

    def _draw_data(self, w, h, now):
        S = self.SS
        x0, y0, x1, y1 = self.L, self.TOP, w - self.R, h - self.BOT

        def Y(score):
            return y1 - (y1 - y0) * score / 100

        img = self._backdrop(w, h).copy()
        d = ImageDraw.Draw(img, "RGBA")
        n = len(self.items)
        p = ease_out(min(1.0, (now - self.t0) / 0.9))
        raw = []
        for i, (score, _estado, _name) in enumerate(self.items):
            x = (x0 + x1) / 2 if n == 1 else x0 + (x1 - x0) * i / (n - 1)
            raw.append((x * S, (y1 - (y1 - Y(score)) * p) * S))
        self._pts = [(x / S, y / S) for x, y in raw]

        if n >= 2:
            curve = [(x, min(y1 * S, max(y0 * S, y))) for x, y in smooth(raw, 10)]
            _fill_under(img, curve, y1 * S, T.PRIMARY, 95)
            d = ImageDraw.Draw(img, "RGBA")
            d.line(curve, fill=rgb(T.PRIMARY, 45), width=int(7 * S), joint="curve")
            d.line(curve, fill=rgb(T.PRIMARY), width=int(2.4 * S), joint="curve")
        elif n == 1:
            d.line([(raw[0][0], raw[0][1]), (raw[0][0], y1 * S)], fill=rgb(T.PRIMARY, 90),
                   width=int(2 * S))

        for i, (cx, cy) in enumerate(raw):
            color = T.STATE_COLORS.get(self.items[i][1], T.TEXT_SECONDARY)
            r = (6.4 if i == self.hover else 4.4) * S
            if i == self.hover:
                d.ellipse((cx - r * 2.3, cy - r * 2.3, cx + r * 2.3, cy + r * 2.3),
                          fill=rgb(color, 55))
            d.ellipse((cx - r - 1.8 * S, cy - r - 1.8 * S, cx + r + 1.8 * S, cy + r + 1.8 * S),
                      fill=rgb(self.bg))
            d.ellipse((cx - r, cy - r, cx + r, cy + r), fill=rgb(color))
        return img

    def _sweep(self, img, w, h, now):
        S = self.SS
        x0, y0, x1, y1 = self.L, self.TOP, w - self.R, h - self.BOT
        d = ImageDraw.Draw(img, "RGBA")
        sx = (x0 + ((now / 5.0) % 1.0) * (x1 - x0)) * S
        for k in range(16):
            d.line([(sx - k * 3 * S, y0 * S), (sx - k * 3 * S, y1 * S)],
                   fill=rgb(T.PRIMARY, int(46 * (1 - k / 16) ** 1.5)), width=int(3 * S))

    def _place_text(self, w, h):
        x0, y0, x1, y1 = self.L, self.TOP, w - self.R, h - self.BOT
        n = len(self.items)

        def Y(score):
            return y1 - (y1 - y0) * score / 100

        for lv, item in self._ylabels.items():
            self.coords(item, x0 - 8, Y(lv))
        self.coords(self._band_hi, x1 - 6, Y(100) + 5)
        self.coords(self._band_mid, x1 - 6, Y(60) + 5)
        self.coords(self._xl, x0, h - 10)
        self.coords(self._xr, x1, h - 10)
        self.itemconfigure(self._xl, text="más antiguo" if n > 1 else "")
        self.itemconfigure(self._xr, text="último" if n > 1 else "")
        self.coords(self._msg, (x0 + x1) / 2, (Y(60) + Y(25)) / 2)
        self.itemconfigure(self._msg, text="" if n else
                           "Aquí aparecerá el riesgo de cada archivo\nactiva la protección o analiza uno")
        self._tooltip(w)

    def _render(self, now):
        w, h = self.winfo_width(), self.winfo_height()
        if w < 120 or h < 80:
            return
        growing = now - self.t0 < 0.95
        key = (w, h, tuple(self.items), self.hover)
        if growing or key != self._frame_key:
            base = self._draw_data(w, h, now)
            self._place_text(w, h)
            if not growing:
                self._frame, self._frame_key = base, key
        else:
            base = self._frame
        if self.active:
            base = base.copy()
            self._sweep(base, w, h, now)
        self._present(base, w, h)

    def _tooltip(self, w):
        i = self.hover
        if i is None or i >= len(self.items):
            self.itemconfigure(self._tip, state="hidden")
            self.itemconfigure(self._tip_bg, state="hidden")
            return
        score, estado, name = self.items[i]
        name = name if len(name) <= 26 else name[:25] + "…"
        x, y = self._pts[i]
        self.itemconfigure(self._tip, text=f"{name}  ·  {score}", state="normal",
                           fill=T.STATE_COLORS.get(estado, T.TEXT))
        self.coords(self._tip, min(max(x, 90), w - 90), max(30, y - 14))
        bx0, by0, bx1, by1 = self.bbox(self._tip)
        self.coords(self._tip_bg, bx0 - 8, by0 - 4, bx1 + 8, by1 + 4)
        self.itemconfigure(self._tip_bg, state="normal")
        self.tag_raise(self._tip_bg)
        self.tag_raise(self._tip)


class Donut(_Animated):
    """Reparto de resultados: seguros, a revisar y en peligro."""

    SS = 3
    ORDER = (("limpio", T.SUCCESS), ("pendiente", T.WARNING), ("alerta", T.DANGER))

    def __init__(self, master, size=140, bg=T.SURFACE):
        super().__init__(master, size, size, bg)
        self.size = size
        self.counts = {}
        self.t0 = 0.0
        self._job = None
        self._num = self.create_text(size / 2, size / 2 - 7, text="0", fill=T.TEXT,
                                     font=(T.MONO_FONT, int(size / 5), "bold"))
        self._cap = self.create_text(size / 2, size / 2 + 12, text="archivos",
                                     fill=T.TEXT_SECONDARY, font=(T.UI_FONT, 8))
        self._render(1.0)

    def set(self, counts):
        counts = {k: counts.get(k, 0) for k, _ in self.ORDER}
        if counts == self.counts:
            return
        self.counts = counts
        total = str(sum(counts.values()))
        self.itemconfigure(self._num, text=total,
                           font=(T.MONO_FONT, int(self.size / (5 if len(total) < 3 else 6.5)), "bold"))
        self.t0 = time.perf_counter()
        self._kick()

    def _tick(self):
        k = min(1.0, (time.perf_counter() - self.t0) / 0.9)
        self._render(ease_out(k))
        self._job = self.after(FRAME_MS, self._tick) if k < 1 else None

    def _render(self, p):
        s, S = self.size, self.SS
        Z = s * S
        img = Image.new("RGB", (Z, Z), _rgb(self.bg))
        d = ImageDraw.Draw(img, "RGBA")
        pad, width = 8 * S, 13 * S
        box = (pad, pad, Z - pad, Z - pad)
        d.arc(box, 0, 360, fill=rgb(T.BORDER), width=width)
        total = sum(self.counts.values())
        if total:
            live = [k for k, _ in self.ORDER if self.counts.get(k)]
            gap = 5 if len(live) > 1 else 0
            angle, limit = -90.0, -90.0 + 360 * p
            for key, color in self.ORDER:
                n = self.counts.get(key, 0)
                if not n:
                    continue
                span = 360 * n / total
                a0, a1 = angle + gap / 2, min(angle + span - gap / 2, limit)
                if a1 > a0:
                    d.arc(box, a0, a1, fill=rgb(color), width=width)
                angle += span
        self._present(img, s, s)
