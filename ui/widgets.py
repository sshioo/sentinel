"""Gráficos animados con antialiasing.

El Canvas de Tk dibuja sin suavizado, así que círculos y diagonales salen con
escalones. Aquí cada fotograma se dibuja con PIL a varias veces el tamaño
final y se reduce con un filtro de promedio: los bordes quedan suaves. El texto
sigue siendo texto de Tk, que ya se suaviza solo.
"""
import math
import time
import tkinter as tk

from PIL import Image, ImageDraw, ImageFilter, ImageTk

from ui import theme as T

FRAME_MS = 16


def rgb(color, alpha=255):
    c = color.lstrip("#")
    return (int(c[0:2], 16), int(c[2:4], 16), int(c[4:6], 16), alpha)


def mix(a, b, t):
    t = max(0.0, min(1.0, t))
    ca, cb = rgb(a), rgb(b)
    return "#" + "".join(f"{int(x + (y - x) * t):02x}" for x, y in zip(ca[:3], cb[:3]))


def ease_out(t):
    return 1 - (1 - t) ** 3


def ease_in_out(t):
    return 4 * t ** 3 if t < 0.5 else 1 - (-2 * t + 2) ** 3 / 2


def approach(current, target, dt, speed):
    """Acerca current a target de forma exponencial, independiente de los FPS."""
    return target + (current - target) * math.exp(-speed * dt)


def round_line(draw, points, color, width):
    draw.line(points, fill=color, width=int(width), joint="curve")
    r = width / 2
    for x, y in (points[0], points[-1]):
        draw.ellipse((x - r, y - r, x + r, y + r), fill=color)


class _AACanvas(tk.Canvas):
    SS = 3

    def __init__(self, master, width, height, bg):
        super().__init__(master, width=width, height=height, bg=bg, highlightthickness=0, bd=0)
        self.bg = bg
        self._photo = None
        self._img_item = self.create_image(0, 0, anchor="nw")
        self._last = time.perf_counter()

    def _dt(self):
        now = time.perf_counter()
        dt = min(0.1, now - self._last)
        self._last = now
        return dt

    def _present(self, img, w, h):
        img = img.resize((w, h), Image.BOX)
        self._photo = ImageTk.PhotoImage(img)
        self.itemconfigure(self._img_item, image=self._photo)
        self.tag_lower(self._img_item)


class ScoreGauge(_AACanvas):
    """Anillo de 0 a 100 que se llena hasta el score con un resplandor suave."""

    DURATION = 0.9

    def __init__(self, master, size=150, bg=T.SURFACE):
        super().__init__(master, size, size, bg)
        self.size = size
        self.shown = 0.0
        self.start = 0.0
        self.target = 0.0
        self.t0 = 0.0
        self.color = T.TEXT_DISABLED
        self.empty = True
        self._job = None
        self._num = self.create_text(size / 2, size / 2 - 6, text="—", fill=T.TEXT_DISABLED,
                                     font=(T.MONO_FONT, int(size / 4.3), "bold"))
        self._cap = self.create_text(size / 2, size / 2 + size / 5.2, text="sin datos",
                                     fill=T.TEXT_SECONDARY, font=(T.UI_FONT, 10))
        self._render()

    def set(self, score, estado, caption=None):
        self.start = self.shown if not self.empty else 0.0
        self.target = float(max(0, min(100, score)))
        self.color = T.STATE_COLORS.get(estado, T.TEXT_DISABLED)
        self.empty = False
        self.t0 = time.perf_counter()
        self.itemconfigure(self._cap, text=caption or "de 100")
        self.itemconfigure(self._num, fill=T.TEXT)
        if self._job is None:
            self._tick()

    def clear(self):
        self.empty = True
        self.shown = self.target = 0.0
        self.color = T.TEXT_DISABLED
        self.itemconfigure(self._num, text="—", fill=T.TEXT_DISABLED)
        self.itemconfigure(self._cap, text="sin datos")
        self._render()

    def _tick(self):
        k = min(1.0, (time.perf_counter() - self.t0) / self.DURATION)
        self.shown = self.start + (self.target - self.start) * ease_out(k)
        self.itemconfigure(self._num, text=f"{self.shown:.0f}")
        self._render()
        self._job = self.after(FRAME_MS, self._tick) if k < 1 else None

    def _arc_layer(self, S, box, width, start, end, color, alpha=255):
        layer = Image.new("RGBA", (S, S), (0, 0, 0, 0))
        d = ImageDraw.Draw(layer)
        d.arc(box, start, end, fill=rgb(color, alpha), width=int(width))
        cx = cy = S / 2
        r = (box[2] - box[0]) / 2 - width / 2
        for a in (start, end):
            x, y = cx + r * math.cos(math.radians(a)), cy + r * math.sin(math.radians(a))
            d.ellipse((x - width / 2, y - width / 2, x + width / 2, y + width / 2),
                      fill=rgb(color, alpha))
        return layer

    def _render(self):
        s, ss = self.size, self.SS
        S = s * ss
        pad, width = 14 * ss, 11 * ss
        box = (pad, pad, S - pad, S - pad)
        # PIL mide los ángulos en sentido horario desde las 3: 135° es abajo a
        # la izquierda y 405° abajo a la derecha, así el hueco queda abajo.
        img = Image.new("RGBA", (S, S), rgb(self.bg))
        img.alpha_composite(self._arc_layer(S, box, width, 135, 405, T.BORDER))
        if not self.empty and self.shown > 0.3:
            end = 135 + 270 * self.shown / 100
            glow = self._arc_layer(S, box, width * 1.6, 135, end, self.color, 120)
            glow = glow.resize((s, s), Image.BOX).filter(ImageFilter.GaussianBlur(5))
            img.alpha_composite(glow.resize((S, S), Image.BILINEAR))
            img.alpha_composite(self._arc_layer(S, box, width, 135, end, self.color))
        self._present(img, s, s)


class ShieldPulse(_AACanvas):
    """Escudo que respira y emite ondas mientras la protección está activa."""

    PERIOD = 2.4

    def __init__(self, master, size=120, bg=T.SURFACE):
        super().__init__(master, size, size, bg)
        self.size = size
        self.active = False
        self.level = 0.0
        self._idle_drawn = False
        self._tick()

    def set_active(self, on):
        self.active = on
        self._idle_drawn = False

    def _shield_points(self, cx, cy, w, h):
        top = cy - h / 2
        right = [(cx, top), (cx + w * 0.22, top + h * 0.07), (cx + w / 2, top + h * 0.14),
                 (cx + w / 2, top + h * 0.48)]
        p0, p1, p2 = (cx + w / 2, top + h * 0.48), (cx + w / 2, top + h * 0.82), (cx, top + h)
        for i in range(1, 17):
            t = i / 16
            x = (1 - t) ** 2 * p0[0] + 2 * (1 - t) * t * p1[0] + t * t * p2[0]
            y = (1 - t) ** 2 * p0[1] + 2 * (1 - t) * t * p1[1] + t * t * p2[1]
            right.append((x, y))
        left = [(2 * cx - x, y) for x, y in reversed(right[1:-1])]
        return right + left

    def _tick(self):
        dt = self._dt()
        self.level = approach(self.level, 1.0 if self.active else 0.0, dt, 6)
        settled = not self.active and self.level < 0.01
        if not (settled and self._idle_drawn):
            self._render(time.perf_counter())
            self._idle_drawn = settled
        self.after(FRAME_MS * 2, self._tick)

    def _render(self, now):
        s, ss = self.size, self.SS
        S = s * ss
        cx = cy = S / 2
        lvl = self.level
        color = mix(T.TEXT_DISABLED, T.SUCCESS, lvl)
        img = Image.new("RGBA", (S, S), rgb(self.bg))

        if lvl > 0.02:
            rings = Image.new("RGBA", (S, S), (0, 0, 0, 0))
            d = ImageDraw.Draw(rings)
            for k in range(3):
                p = ((now / self.PERIOD) + k / 3) % 1.0
                r = S * 0.23 + ease_out(p) * (S * 0.5 - S * 0.25)
                alpha = int(150 * (1 - p) ** 1.6 * lvl)
                d.ellipse((cx - r, cy - r, cx + r, cy + r), outline=rgb(T.SUCCESS, alpha),
                          width=int(2 * ss))
            img.alpha_composite(rings)

        breathe = 1 + 0.035 * math.sin(now * 2 * math.pi / self.PERIOD) * lvl
        w, h = S * 0.38 * breathe, S * 0.45 * breathe
        pts = self._shield_points(cx, cy, w, h)

        glow = Image.new("RGBA", (S, S), (0, 0, 0, 0))
        ImageDraw.Draw(glow).polygon(pts, fill=rgb(color, int(110 * lvl)))
        glow = glow.resize((s, s), Image.BOX).filter(ImageFilter.GaussianBlur(6))
        img.alpha_composite(glow.resize((S, S), Image.BILINEAR))

        d = ImageDraw.Draw(img)
        d.polygon(pts, fill=rgb(mix(color, self.bg, 0.8)))
        d.line(pts + [pts[0], pts[1]], fill=rgb(color), width=int(2.6 * ss), joint="curve")

        if lvl >= 0.5:
            mark = [(cx - w * 0.22, cy + h * 0.02), (cx - w * 0.05, cy + h * 0.18),
                    (cx + w * 0.25, cy - h * 0.16)]
            round_line(d, mark, rgb(color), 4.2 * ss)
        else:
            bw, bh = w * 0.1, h * 0.3
            for dx in (-w * 0.13, w * 0.13):
                d.rounded_rectangle((cx + dx - bw / 2, cy - bh / 2, cx + dx + bw / 2, cy + bh / 2),
                                    radius=bw / 2, fill=rgb(color))
        self._present(img, s, s)


class DropZone(_AACanvas):
    """Zona para elegir un archivo; se ilumina al pasar el ratón."""

    SS = 2

    def __init__(self, master, command, height=120, bg=T.SURFACE):
        super().__init__(master, 10, height, bg)
        self.configure(cursor="hand2")
        self.command = command
        self.hover = False
        self.busy = False
        self.h_level = 0.0
        self._job = None
        self._title = self.create_text(0, 0, text="", fill=T.TEXT, font=(T.UI_FONT, 14, "bold"))
        self._sub = self.create_text(0, 0, text="", fill=T.TEXT_SECONDARY, font=(T.UI_FONT, 11))
        self.bind("<Configure>", lambda _e: self._kick())
        self.bind("<Enter>", lambda _e: self._set_hover(True))
        self.bind("<Leave>", lambda _e: self._set_hover(False))
        self.bind("<Button-1>", lambda _e: None if self.busy else self.command())

    def set_busy(self, busy):
        self.busy = busy
        self.configure(cursor="watch" if busy else "hand2")
        self._kick()

    def _set_hover(self, on):
        self.hover = on
        self._kick()

    def _kick(self):
        self._last = time.perf_counter()
        if self._job is None:
            self._tick()

    def _tick(self):
        dt = self._dt()
        target = 1.0 if (self.hover or self.busy) else 0.0
        self.h_level = approach(self.h_level, target, dt, 10)
        self._render(time.perf_counter())
        moving = self.busy or abs(self.h_level - target) > 0.005
        self._job = self.after(FRAME_MS, self._tick) if moving else None

    def _render(self, now):
        w, h = self.winfo_width(), self.winfo_height()
        if w < 20:
            return
        ss = self.SS
        W, H = w * ss, h * ss
        lvl = self.h_level
        img = Image.new("RGBA", (W, H), rgb(self.bg))
        d = ImageDraw.Draw(img)
        fill = mix(T.ELEVATED, T.ELEVATED_HOVER, lvl)
        border = mix(T.BORDER, T.PRIMARY, lvl)
        d.rounded_rectangle((2 * ss, 2 * ss, W - 2 * ss, H - 2 * ss), radius=12 * ss,
                            fill=rgb(fill), outline=rgb(border), width=int(1.6 * ss))

        icx, icy, r = W / 2, H / 2 - 22 * ss, 17 * ss
        d.ellipse((icx - r, icy - r, icx + r, icy + r), fill=rgb(mix(T.BG, T.PRIMARY, 0.12 + 0.18 * lvl)))
        lift = math.sin(now * 3.2) * 2.2 * ss if self.busy else -lvl * 2 * ss
        arrow = rgb(mix(T.TEXT_SECONDARY, T.PRIMARY, lvl))
        round_line(d, [(icx, icy + 7 * ss + lift), (icx, icy - 7 * ss + lift)], arrow, 2.4 * ss)
        round_line(d, [(icx - 6 * ss, icy - 1 * ss + lift), (icx, icy - 7 * ss + lift),
                       (icx + 6 * ss, icy - 1 * ss + lift)], arrow, 2.4 * ss)

        if self.busy:
            tw, ty = W * 0.42, H - 9 * ss
            x0 = (W - tw) / 2
            d.rounded_rectangle((x0, ty - 2 * ss, x0 + tw, ty + 2 * ss), radius=2 * ss,
                                fill=rgb(T.BORDER))
            p = (now / 1.3) % 1.0
            a = x0 + tw * ease_in_out(max(0.0, p * 1.4 - 0.4))
            b = x0 + tw * ease_in_out(min(1.0, p * 1.4))
            if b - a > 4 * ss:
                d.rounded_rectangle((a, ty - 2 * ss, b, ty + 2 * ss), radius=2 * ss,
                                    fill=rgb(T.PRIMARY))
            title, sub = "Analizando…", "los ejecutables pueden tardar hasta 2 minutos"
        else:
            title, sub = "Elige un archivo para revisarlo", "cualquier tipo: ejecutables, documentos, scripts, ZIP"

        self._present(img, w, h)
        self.coords(self._title, w / 2, h / 2 + 6)
        self.coords(self._sub, w / 2, h / 2 + 25)
        self.itemconfigure(self._title, text=title)
        self.itemconfigure(self._sub, text=sub)


def ext_badge(name, tipo):
    ext = name.rsplit(".", 1)[-1].upper()[:4] if "." in name else "ARCH"
    if tipo == "CÓDIGO":
        return ext, T.INFO
    if ext in ("EXE", "DLL", "SCR", "MSI", "SYS", "COM", "BAT", "CMD", "PS1", "VBS"):
        return ext, T.PRIMARY
    return ext, T.TEXT_SECONDARY
