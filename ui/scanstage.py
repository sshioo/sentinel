import math
import time

from PIL import Image, ImageDraw, ImageFilter, ImageTk

from ui import theme as T
from ui.widgets import FRAME_MS, _AACanvas, approach, ease_in_out, mix, rgb

SS = 2
STEP = 4
PULSE_S = 2.6
PULSE_GAP_S = 0.7
PACKET_W = 46
# Tres ondas superpuestas: (amplitud relativa, frecuencia, velocidad, grosor, opacidad)
LAYERS = ((1.0, 0.011, 1.3, 2.2, 255), (0.65, 0.019, -0.9, 1.4, 120), (0.4, 0.007, 0.6, 1.2, 80))


class ScanStage(_AACanvas):
    """Señal en vivo de la vigilancia.

    En reposo, una onda casi plana y gris. Con la protección activa, ondas
    ámbar en movimiento. Cada análisis terminado envía un pulso del color del
    veredicto que recorre la señal con el nombre del archivo.
    """

    def __init__(self, master, height=110):
        super().__init__(master, 10, height, T.BG)
        self.active = False
        self.level = 0.0
        self.pulses = []
        self._job = None
        self._static_drawn = False
        self._label = self.create_text(16, 14, anchor="w", text="", fill=T.TEXT_SECONDARY,
                                       font=(T.MONO_FONT, 9, "bold"))
        self._tag = self.create_text(0, 0, text="", fill=T.TEXT, font=(T.UI_FONT, 11, "bold"))
        self.bind("<Configure>", lambda _e: self._kick(force=True))
        self._kick()

    def set_active(self, on):
        self.active = on
        self._kick()

    def push(self, name, estado):
        start = time.perf_counter()
        if self.pulses:
            start = max(start, self.pulses[-1]["t0"] + PULSE_GAP_S)
        short = name if len(name) <= 28 else name[:27] + "…"
        self.pulses.append({"t0": start, "color": T.STATE_COLORS.get(estado, T.TEXT_SECONDARY),
                            "text": f"{short} · {T.STATE_TEXT.get(estado, estado.upper())}"})
        self._kick()

    def _kick(self, force=False):
        if force:
            self._static_drawn = False
        self._last = time.perf_counter()
        if self._job is None:
            self._tick()

    def _tick(self):
        dt = self._dt()
        now = time.perf_counter()
        self.level = approach(self.level, 1.0 if self.active else 0.0, dt, 3.5)
        self.pulses = [p for p in self.pulses if now - p["t0"] < PULSE_S]
        moving = bool(self.pulses) or self.active or self.level > 0.005
        if moving or not self._static_drawn:
            self._render(now)
            self._static_drawn = not moving
        # Las ondas en reposo se mueven despacio: 30 fps bastan. Los pulsos van a 60.
        frame = FRAME_MS if self.pulses else FRAME_MS * 2
        self._job = self.after(frame, self._tick) if moving else None

    def _background(self, W, H):
        # Rejilla de puntos tenue, como el fondo de la web. Solo cambia al
        # redimensionar, así que se dibuja una vez.
        if getattr(self, "_bg_key", None) != (W, H):
            bg = Image.new("RGBA", (W, H), rgb(self.bg))
            d = ImageDraw.Draw(bg)
            dot = rgb(T.BORDER, 200)
            for gx in range(24 * SS, W, 32 * SS):
                for gy in range(26 * SS, H - 6 * SS, 24 * SS):
                    d.ellipse((gx - 1.4, gy - 1.4, gx + 1.4, gy + 1.4), fill=dot)
            self._bg_img, self._bg_key = bg, (W, H)
        return self._bg_img

    def _wave(self, w, h, now, layer):
        amp_rel, freq, speed, _width, _alpha = layer
        cy = h / 2 + 1
        amp = (3 + 15 * self.level) * amp_rel
        t = now if self.level > 0.005 else 0.0
        heads = []
        for p in self.pulses:
            k = (now - p["t0"]) / PULSE_S
            if 0 <= k < 1:
                heads.append((-PACKET_W * 2 + ease_in_out(k) * (w + PACKET_W * 4), math.sin(k * math.pi)))
        pts = []
        for x in range(0, w + STEP, STEP):
            env = max(0.0, math.sin(math.pi * min(x, w) / w)) ** 0.7
            y = amp * math.sin(x * freq + t * speed) + amp * 0.35 * math.sin(x * freq * 2.3 - t * speed * 1.7)
            for hx, strength in heads:
                d = (x - hx) / PACKET_W
                y += 22 * amp_rel * strength * math.exp(-d * d) * math.sin(x * 0.16 - now * 9)
            pts.append((x, cy + y * env))
        return pts, heads

    def _render(self, now):
        w, h = self.winfo_width(), self.winfo_height()
        if w < 40 or h < 30:
            return
        lvl = self.level
        base = mix(T.TEXT_DISABLED, T.PRIMARY, lvl)
        W, H = w * SS, h * SS

        img = self._background(W, H).copy()
        # El resplandor va difuminado: se dibuja a media resolución.
        gw, gh = w // 2, h // 2
        glow = Image.new("RGBA", (gw, gh), (0, 0, 0, 0))
        gd = ImageDraw.Draw(glow)
        d = ImageDraw.Draw(img)

        def half(points):
            return [(x / 2, y / 2) for x, y in points]

        main_pts = []
        for i, layer in enumerate(reversed(LAYERS)):
            pts, _heads = self._wave(w, h, now, layer)
            _amp, _f, _s, width, alpha = layer
            d.line([(x * SS, y * SS) for x, y in pts], fill=rgb(base, int(alpha * (0.45 + 0.55 * lvl))),
                   width=int(width * SS))
            if i == len(LAYERS) - 1:
                main_pts = pts
                if lvl > 0.02:
                    gd.line(half(pts), fill=rgb(base, int(70 * lvl)), width=3)

        # tramo del pulso, en el color del veredicto
        label = None
        for p in self.pulses:
            k = (now - p["t0"]) / PULSE_S
            if not 0 <= k < 1:
                continue
            hx = -PACKET_W * 2 + ease_in_out(k) * (w + PACKET_W * 4)
            fade = math.sin(k * math.pi)
            seg = [(x, y) for x, y in main_pts if abs(x - hx) < PACKET_W * 2.2]
            if len(seg) > 1:
                gd.line(half(seg), fill=rgb(p["color"], int(170 * fade)), width=4)
                d.line([(x * SS, y * SS) for x, y in seg], fill=rgb(p["color"], int(255 * min(1, fade * 1.6))),
                       width=int(2.6 * SS), joint="curve")
                peak = min(seg, key=lambda q: abs(q[0] - hx))
                r = 4.5 * SS
                d.ellipse((peak[0] * SS - r, peak[1] * SS - r, peak[0] * SS + r, peak[1] * SS + r),
                          fill=rgb(p["color"], int(255 * min(1, fade * 1.6))))
                if 0.12 < k < 0.88:
                    label = (hx, p)

        img = img.resize((w, h), Image.BOX)
        img.alpha_composite(glow.filter(ImageFilter.GaussianBlur(2)).resize((w, h), Image.BILINEAR))
        self._photo = ImageTk.PhotoImage(img)
        self.itemconfigure(self._img_item, image=self._photo)
        self.tag_lower(self._img_item)

        if label:
            hx, p = label
            self.coords(self._tag, max(120, min(w - 120, hx)), h - 11)
            self.itemconfigure(self._tag, text=p["text"], fill=p["color"])
        else:
            self.itemconfigure(self._tag, text="")
        estado = "EN LÍNEA" if self.active else "EN PAUSA"
        self.itemconfigure(self._label, text=f"SEÑAL DE VIGILANCIA · {estado}")
        self.tag_raise(self._label)
        self.tag_raise(self._tag)
