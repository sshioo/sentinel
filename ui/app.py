import os
import queue
import sys
import threading
import time
import tkinter as tk
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import customtkinter as ctk
from tkinter import filedialog

from config import CODE_EXTENSIONS, GUI_POLL_MS, PROJECT_DIR, REPORTS_DIR, WATCH_DIR

try:
    from PIL import Image
    _LOGO_PATH = PROJECT_DIR / "assets" / "logo.png"
    _LOGO = Image.open(_LOGO_PATH) if _LOGO_PATH.exists() else None
except Exception:
    _LOGO = None
from core import iocs as iocs_mod
from core import tracer
from core.analyzer import analyze
from core.dispatcher import classify
from core.scoring import confidence
from core.watcher import Watcher
from engines import ai_analyst
from reports import report
from ui import history
from ui import theme as T
from ui.icons import icon
from ui.dashboard import Donut, KpiCard, RiskTimeline, card
from ui.scanstage import ScanStage
from ui.widgets import DropZone, ScoreGauge, ShieldPulse, ext_badge

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

_MOTION_MS = 16
_PULSE_STEPS = 10
_MAX_ROWS = 60
_CONF_ORDER = {"alta": 0, "media": 1, "baja": 2}
_SEV_ORDER = {"crítico": 0, "alto": 1, "medio": 2, "bajo": 3}


def _resolve_color(estado):
    return T.STATE_COLORS.get(estado, T.TEXT_SECONDARY)


def _hex_rc(c, delta):
    h = c.lstrip("#")
    r = max(0, min(255, int(h[0:2], 16) + delta))
    g = max(0, min(255, int(h[2:4], 16) + delta))
    b = max(0, min(255, int(h[4:6], 16) + delta))
    return f"#{r:02x}{g:02x}{b:02x}"


def _bind_tree(widget, event, callback):
    widget.bind(event, callback, add="+")
    for child in widget.winfo_children():
        _bind_tree(child, event, callback)


class Splash(ctk.CTkToplevel):
    def __init__(self, master):
        super().__init__(master)
        self.overrideredirect(True)
        w, h = 520, 280
        self.configure(fg_color=T.BG)
        self._center(w, h)
        self.lift()
        self.attributes("-topmost", True)

        wrap = ctk.CTkFrame(self, fg_color=T.SURFACE, corner_radius=14, border_width=1,
                            border_color=T.BORDER)
        wrap.pack(fill="both", expand=True, padx=2, pady=2)
        inner = ctk.CTkFrame(wrap, fg_color="transparent")
        inner.pack(fill="both", expand=True, padx=30, pady=26)

        head = ctk.CTkFrame(inner, fg_color="transparent")
        head.pack(fill="x")
        self.shield = ShieldPulse(head, size=74, bg=T.SURFACE)
        self.shield.set_active(True)
        self.shield.pack(side="left")
        txt = ctk.CTkFrame(head, fg_color="transparent")
        txt.pack(side="left", padx=14)
        ctk.CTkLabel(txt, text="Sentinel", font=(T.UI_FONT, 28, "bold"),
                     text_color=T.TEXT).pack(anchor="w")
        ctk.CTkLabel(txt, text="¿Es seguro abrir este archivo?", font=(T.UI_FONT, 13),
                     text_color=T.TEXT_SECONDARY).pack(anchor="w")

        self.step_lbl = ctk.CTkLabel(inner, text="", font=T.F_MONO_SM, text_color=T.PRIMARY,
                                     anchor="w")
        self.step_lbl.pack(fill="x", pady=(30, 8))
        self.bar = ctk.CTkProgressBar(inner, height=6, corner_radius=3, fg_color=T.BORDER,
                                      progress_color=T.PRIMARY)
        self.bar.set(0)
        self.bar.pack(fill="x")

        self._steps = [
            "cargando reglas YARA",
            "motores: binario · PE · Office · PDF",
            "ingeniería inversa: capa + capstone",
            "verificación de firmas digitales",
            "listo",
        ]
        self._run_step(0)

    def _center(self, w, h):
        self.update_idletasks()
        x = (self.winfo_screenwidth() - w) // 2
        y = (self.winfo_screenheight() - h) // 2
        self.geometry(f"{w}x{h}+{x}+{y}")

    def _run_step(self, index):
        if index >= len(self._steps):
            self.after(220, self.destroy)
            return
        self.step_lbl.configure(text=f"› {self._steps[index]}")
        self.bar.set((index + 1) / len(self._steps))
        self.after(320, lambda: self._run_step(index + 1))


class SentinelApp(ctk.CTk):
    PADDING = {"home": (28, 20), "activity": (18, 16), "reports": (18, 16), "config": (18, 16)}

    def __init__(self, demo=False):
        super().__init__()
        self.demo = demo
        self._home_job = None
        self._save_job = None
        self._loading = False
        self.title("Sentinel — ¿es seguro este archivo?")
        self.geometry("1320x820")
        self.minsize(1180, 720)
        self.configure(fg_color=T.BG)
        icon = PROJECT_DIR / "assets" / "sentinel.ico"
        if icon.exists():
            # CustomTkinter pone su icono a los ~200 ms; el nuestro va después.
            self.after(300, lambda: self.iconbitmap(str(icon)))

        self.queue = queue.Queue()
        self.watcher = None
        self.watching = False
        self.rows = {}
        self.selected = None
        self.view = "home"
        self.monitor_ready = False
        self.busy = False
        self.stats = {"total": 0, "alerta": 0, "pendiente": 0, "limpio": 0, "score_sum": 0}

        self.withdraw()
        self._paint_window_background()
        self.splash = Splash(self)
        self.after(1850, self._reveal)
        self._build()

    def _reveal(self):
        if getattr(self, "splash", None) and self.splash.winfo_exists():
            try:
                self.splash.destroy()
            except Exception:
                pass
        self.deiconify()
        self.lift()

    # ── estructura ──
    def _build(self):
        self.sidebar = ctk.CTkFrame(self, fg_color=T.SURFACE, corner_radius=0, width=210)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)

        brand = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        brand.pack(fill="x", padx=18, pady=(22, 22))
        if _LOGO is not None:
            ctk.CTkLabel(brand, text="", image=ctk.CTkImage(light_image=_LOGO, size=(30, 30))).pack(
                side="left")
        names = ctk.CTkFrame(brand, fg_color="transparent")
        names.pack(side="left", padx=(8, 0))
        title_row = ctk.CTkFrame(names, fg_color="transparent")
        title_row.pack(anchor="w")
        ctk.CTkLabel(title_row, text="Sentinel", font=(T.UI_FONT, 18, "bold"),
                     text_color=T.TEXT).pack(side="left")
        if "beta" in T.SENTINEL_VER:
            ctk.CTkLabel(title_row, text=" BETA ", font=(T.UI_FONT, 9, "bold"), text_color=T.ON_PRIMARY,
                         fg_color=T.PRIMARY, corner_radius=4, height=16).pack(side="left", padx=(6, 0))
        ctk.CTkLabel(names, text=T.SENTINEL_VER, font=(T.MONO_FONT, 9),
                     text_color=T.TEXT_SECONDARY).pack(anchor="w")

        self.nav_buttons = {}
        for key, icon, label in (("home", "⌂", "Inicio"), ("activity", "☰", "Actividad")):
            self.nav_buttons[key] = self._nav_item(key, label, lambda k=key: self.show_view(k))
        ctk.CTkLabel(self.sidebar, text="ADMINISTRAR", font=(T.MONO_FONT, 9, "bold"),
                     text_color=T.TEXT_DISABLED, anchor="w").pack(fill="x", padx=22, pady=(18, 4))
        for key, icon, label in (("reports", "▤", "Informes"), ("config", "⚙", "Motores")):
            self.nav_buttons[key] = self._nav_item(key, label, lambda k=key: self.show_view(k))

        status = ctk.CTkFrame(self.sidebar, fg_color=T.ELEVATED, corner_radius=T.RADIUS_MD)
        status.pack(side="bottom", fill="x", padx=12, pady=14)
        ctk.CTkLabel(status, text="PROTECCIÓN", font=(T.UI_FONT, 10, "bold"),
                     text_color=T.TEXT_SECONDARY).pack(anchor="w", padx=12, pady=(10, 0))
        self.nav_dot = ctk.CTkLabel(status, text="●  desactivada", font=(T.UI_FONT, 13, "bold"),
                                    text_color=T.TEXT_SECONDARY)
        self.nav_dot.pack(anchor="w", padx=12, pady=(2, 10))

        main = ctk.CTkFrame(self, fg_color=T.BG, corner_radius=0)
        main.pack(side="left", fill="both", expand=True)

        # Las vistas viven en un lienzo de tamaño fijo que se reajusta una sola vez
        # cuando el usuario suelta el borde. Mientras arrastra, recalcular unos 120
        # widgets en cada paso tardaba ~300 ms y la ventana se veía a trompicones.
        # Es un tk.Frame para colocarlo en píxeles reales, sin el escalado de CTk.
        self._main = main
        self._stage_size = (0, 0)
        self._stage_job = None
        self.stage_frame = tk.Frame(main, bg=T.BG, bd=0, highlightthickness=0)
        self.stage_frame.place(x=0, y=0, width=1, height=1)
        main.bind("<Configure>", self._on_main_resize)

        self.views = {}
        for key, builder in (("home", self._build_home),
                             ("activity", self._build_activity),
                             ("reports", self._build_reports),
                             ("config", self._build_config)):
            self.views[key] = builder(self.stage_frame)

        self.show_view("home")
        self._refresh_home()
        self.after(GUI_POLL_MS, self._poll)
        if not self.demo:
            self.after(450, self._load_history)

    def _paint_window_background(self):
        """Al agrandar la ventana, Windows rellena la zona nueva con el pincel de fondo
        de la clase de ventana (blanco) hasta que Tk la repinta: ese parpadeo blanco
        es lo que se veía al redimensionar. Se sustituye por el color de la interfaz."""
        if sys.platform != "win32":
            return
        try:
            import ctypes
            from ctypes import wintypes

            user32, gdi32 = ctypes.windll.user32, ctypes.windll.gdi32
            gdi32.CreateSolidBrush.argtypes = [wintypes.COLORREF]
            gdi32.CreateSolidBrush.restype = wintypes.HBRUSH
            user32.SetClassLongPtrW.argtypes = [wintypes.HWND, ctypes.c_int, ctypes.c_void_p]
            user32.SetClassLongPtrW.restype = ctypes.c_void_p
            user32.GetParent.argtypes = [wintypes.HWND]
            user32.GetParent.restype = wintypes.HWND
            r, g, b = (int(T.BG[i:i + 2], 16) for i in (1, 3, 5))
            self._bg_brush = gdi32.CreateSolidBrush(r | (g << 8) | (b << 16))
            inner = self.winfo_id()
            for hwnd in (inner, user32.GetParent(inner)):
                if hwnd:
                    user32.SetClassLongPtrW(hwnd, -10, self._bg_brush)  # GCLP_HBRUSHBACKGROUND
        except Exception:  # noqa: BLE001 - cosmético: si falla, solo vuelve el parpadeo
            pass

    def _on_main_resize(self, event):
        self._main_size = (event.width, event.height)
        if self._stage_size == (0, 0):
            self._apply_stage()
            return
        if self._stage_job is not None:
            self.after_cancel(self._stage_job)
        self._stage_job = self.after(140, self._apply_stage)

    def _apply_stage(self):
        self._stage_job = None
        size = self._main_size
        if size != self._stage_size and size[0] > 1 and size[1] > 1:
            self.stage_frame.place_configure(width=size[0], height=size[1])
            self._stage_size = size

    def _nav_item(self, key, label, command):
        wrap = ctk.CTkFrame(self.sidebar, fg_color="transparent", height=42)
        wrap.pack(fill="x", padx=10, pady=2)
        wrap.pack_propagate(False)
        bar = ctk.CTkFrame(wrap, fg_color="transparent", width=3, corner_radius=2)
        bar.pack(side="left", fill="y", padx=(0, 8), pady=6)
        btn = ctk.CTkButton(wrap, text=f"  {label}", image=icon(key, 17, T.TEXT_SECONDARY),
                            compound="left", anchor="w", height=36, border_spacing=8,
                            fg_color="transparent", hover_color=T.ELEVATED,
                            text_color=T.TEXT_SECONDARY, font=(T.UI_FONT, 14),
                            corner_radius=T.RADIUS_SM, command=command)
        btn.pack(fill="x", side="left", expand=True)
        wrap.bar = bar
        wrap.btn = btn
        wrap.badge = ctk.CTkLabel(wrap, text="", width=22, height=20, corner_radius=10,
                                  font=(T.UI_FONT, 11, "bold"), text_color=T.ON_PRIMARY,
                                  fg_color=T.PRIMARY)
        wrap.badge.bind("<Button-1>", lambda _e: command())
        return wrap

    def _set_badge(self, key, count, color=T.PRIMARY):
        badge = self.nav_buttons[key].badge
        if count:
            badge.configure(text=str(count), fg_color=color)
            badge.place(relx=1.0, rely=0.5, x=-12, anchor="e")
        else:
            badge.place_forget()

    def show_view(self, key):
        self.view = key
        for k, frame in self.views.items():
            if k == key:
                px, py = self.PADDING[k]
                frame.pack(fill="both", expand=True, padx=px, pady=py)
            else:
                frame.pack_forget()
        for k, wrap in self.nav_buttons.items():
            active = (k == key)
            wrap.bar.configure(fg_color=T.PRIMARY if active else "transparent")
            wrap.btn.configure(image=icon(k, 17, T.PRIMARY if active else T.TEXT_SECONDARY),
                               text_color=T.TEXT if active else T.TEXT_SECONDARY,
                               fg_color=T.ELEVATED if active else "transparent",
                               font=(T.UI_FONT, 14, "bold" if active else "normal"))
        if key == "reports":
            self._refresh_reports()

    # ── vista de inicio (panel) ──
    def _card_header(self, parent, title, action_text=None, action=None, subtitle=None):
        head = ctk.CTkFrame(parent, fg_color="transparent")
        head.pack(fill="x", padx=20, pady=(14, 6))
        col = ctk.CTkFrame(head, fg_color="transparent")
        col.pack(side="left")
        ctk.CTkLabel(col, text=title, font=(T.UI_FONT, 15, "bold"), text_color=T.TEXT).pack(anchor="w")
        if subtitle:
            ctk.CTkLabel(col, text=subtitle, font=(T.UI_FONT, 11),
                         text_color=T.TEXT_SECONDARY).pack(anchor="w")
        if action_text:
            ctk.CTkButton(head, text=f"{action_text}  →", width=1, height=26, fg_color="transparent",
                          hover_color=T.ELEVATED, text_color=T.TEXT_SECONDARY,
                          font=(T.UI_FONT, 12), command=action).pack(side="right")
        return head

    def _build_home(self, parent):
        frame = ctk.CTkFrame(parent, fg_color=T.BG, corner_radius=0)

        head = ctk.CTkFrame(frame, fg_color="transparent")
        head.pack(fill="x")
        left = ctk.CTkFrame(head, fg_color="transparent")
        left.pack(side="left")
        ctk.CTkLabel(left, text="TU EQUIPO, DE UN VISTAZO", font=(T.MONO_FONT, 10, "bold"),
                     text_color=T.TEXT_SECONDARY).pack(anchor="w")
        self.home_title = ctk.CTkLabel(left, text="", font=(T.UI_FONT, 28, "bold"), text_color=T.TEXT)
        self.home_title.pack(anchor="w", pady=(4, 0))
        self.home_sub = ctk.CTkLabel(left, text="", font=T.F_BODY, text_color=T.TEXT_SECONDARY)
        self.home_sub.pack(anchor="w", pady=(2, 0))
        ctk.CTkButton(head, text="Ver toda la actividad  →", height=38, width=190,
                      command=lambda: self.show_view("activity"),
                      **T.button_style("secondary")).pack(side="right", anchor="s")

        kpis = ctk.CTkFrame(frame, fg_color="transparent")
        kpis.pack(fill="x", pady=(18, 0))
        self.kpis = {}
        for i, (key, title, color, spark) in enumerate((
                ("total", "Archivos analizados", T.TEXT, T.PRIMARY),
                ("alerta", "En peligro", T.DANGER, T.DANGER),
                ("pendiente", "Para revisar", T.WARNING, T.WARNING))):
            kpis.grid_columnconfigure(i, weight=1, uniform="kpi")
            k = KpiCard(kpis, title, color, spark)
            k.grid(row=0, column=i, sticky="nsew", padx=(0 if i == 0 else 5, 5))
            self.kpis[key] = k
        kpis.grid_columnconfigure(3, weight=1, uniform="kpi")
        ring_card = card(kpis)
        ring_card.grid(row=0, column=3, sticky="nsew", padx=(5, 0))
        self.ring = ScoreGauge(ring_card, size=104, bg=T.SURFACE)
        self.ring.pack(side="left", padx=(12, 4), pady=10)
        rt = ctk.CTkFrame(ring_card, fg_color="transparent")
        rt.pack(side="left", fill="both", expand=True, padx=(4, 14), pady=3)
        ctk.CTkLabel(rt, text="PUNTUACIÓN DE SEGURIDAD", font=(T.MONO_FONT, 9, "bold"),
                     text_color=T.TEXT_SECONDARY, anchor="w").pack(anchor="w", pady=(24, 0))
        self.ring_text = ctk.CTkLabel(rt, text="", font=(T.UI_FONT, 12, "bold"), text_color=T.TEXT,
                                      anchor="w", justify="left", wraplength=118)
        self.ring_text.pack(anchor="w", pady=(4, 0))

        mid = ctk.CTkFrame(frame, fg_color="transparent")
        mid.pack(fill="both", expand=True, pady=(12, 0))
        mid.grid_columnconfigure(0, weight=3, uniform="mid")
        mid.grid_columnconfigure(1, weight=2, uniform="mid")
        mid.grid_rowconfigure(0, weight=5)
        mid.grid_rowconfigure(1, weight=4)

        chart = card(mid)
        chart.grid(row=0, column=0, sticky="nsew", padx=(0, 6), pady=(0, 6))
        ch = self._card_header(chart, "Riesgo de los últimos análisis",
                               subtitle="Cada punto es un archivo. Pasa el ratón para ver cuál.")
        self.live_lbl = ctk.CTkLabel(ch, text="●  en pausa", font=(T.UI_FONT, 12, "bold"),
                                     text_color=T.TEXT_SECONDARY)
        self.live_lbl.pack(side="right")
        body = ctk.CTkFrame(chart, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=8, pady=(0, 10))
        dcol = ctk.CTkFrame(body, fg_color="transparent")
        dcol.pack(side="right", padx=(4, 14))
        self.timeline = RiskTimeline(body)
        self.timeline.pack(side="left", fill="both", expand=True)
        self.donut = Donut(dcol, size=108)
        self.donut.pack(pady=(4, 8))
        self.legend = {}
        for key, label, color in (("limpio", "Seguros", T.SUCCESS), ("pendiente", "Revisar", T.WARNING),
                                  ("alerta", "Peligro", T.DANGER)):
            row = ctk.CTkFrame(dcol, fg_color="transparent")
            row.pack(fill="x", pady=1)
            ctk.CTkLabel(row, text="●", font=(T.UI_FONT, 9), text_color=color).pack(side="left")
            ctk.CTkLabel(row, text=label, font=(T.UI_FONT, 12), text_color=T.TEXT_SECONDARY).pack(
                side="left", padx=(6, 0))
            self.legend[key] = ctk.CTkLabel(row, text="0", font=(T.MONO_FONT, 12, "bold"),
                                            text_color=T.TEXT)
            self.legend[key].pack(side="right")

        right = ctk.CTkFrame(mid, fg_color="transparent")
        right.grid(row=0, column=1, sticky="nsew", padx=(6, 0), pady=(0, 6))
        prot = card(right)
        prot.pack(fill="x")
        self.shield = ShieldPulse(prot, size=100, bg=T.SURFACE)
        self.shield.pack(side="left", padx=(12, 2), pady=10)
        pt = ctk.CTkFrame(prot, fg_color="transparent")
        pt.pack(side="left", fill="both", expand=True, padx=(4, 16), pady=14)
        self.prot_title = ctk.CTkLabel(pt, text="Protección desactivada", font=(T.UI_FONT, 17, "bold"),
                                       text_color=T.TEXT, anchor="w")
        self.prot_title.pack(anchor="w")
        self.prot_desc = ctk.CTkLabel(
            pt, text="Actívala y Sentinel revisará cada archivo que llegue a Descargas.",
            font=(T.UI_FONT, 12), text_color=T.TEXT_SECONDARY, anchor="w", justify="left",
            wraplength=230)
        self.prot_desc.pack(anchor="w", pady=(3, 10))
        self.watch_btn = ctk.CTkButton(pt, text="Activar protección", width=170, height=36,
                                       command=self.toggle, **self._btn("primary", 13))
        self.watch_btn.pack(anchor="w")
        pick = card(right)
        pick.pack(fill="both", expand=True, pady=(12, 0))
        ctk.CTkLabel(pick, text="ANALIZAR A MANO", font=(T.MONO_FONT, 9, "bold"),
                     text_color=T.TEXT_SECONDARY).pack(anchor="w", padx=18, pady=(12, 2))
        self.drop = DropZone(pick, command=self.manual, height=92, bg=T.SURFACE)
        self.drop.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        recent = card(mid)
        recent.grid(row=1, column=0, sticky="nsew", padx=(0, 6), pady=(6, 0))
        self._card_header(recent, "Atendido recientemente", "Toda la actividad",
                          lambda: self.show_view("activity"))
        self.recent_box = ctk.CTkFrame(recent, fg_color="transparent")
        self.recent_box.pack(fill="both", expand=True, padx=14, pady=(0, 10))

        steps = card(mid)
        steps.grid(row=1, column=1, sticky="nsew", padx=(6, 0), pady=(6, 0))
        sh = self._card_header(steps, "Tus siguientes pasos")
        self.steps_count = ctk.CTkLabel(sh, text="", width=24, height=22, corner_radius=11,
                                        font=(T.UI_FONT, 11, "bold"), text_color=T.TEXT_SECONDARY,
                                        fg_color=T.ELEVATED)
        self.steps_count.pack(side="right")
        self.steps_box = ctk.CTkFrame(steps, fg_color="transparent")
        self.steps_box.pack(fill="both", expand=True, padx=18, pady=(0, 10))
        return frame

    def _schedule_home(self):
        if self._home_job is None:
            self._home_job = self.after(60, self._refresh_home)

    @staticmethod
    def _when(entry):
        ts = entry.get("ts")
        if not ts:
            return entry.get("hora", "")
        if time.strftime("%Y%m%d", time.localtime(ts)) == time.strftime("%Y%m%d"):
            return time.strftime("%H:%M", time.localtime(ts))
        return time.strftime("%d/%m %H:%M", time.localtime(ts))

    def _open_entry(self, entry):
        self.show_view("activity")
        self._show_detail(entry)

    def _refresh_home(self):
        self._home_job = None
        s = self.stats
        entries = [self.rows[k] for k in sorted(self.rows)]
        window = entries[-20:]

        def running(pred):
            n, out = 0, []
            for e in window:
                n += 1 if pred(e) else 0
                out.append(n)
            return out

        today = time.strftime("%Y%m%d")
        hoy = sum(1 for e in entries if e.get("ts")
                  and time.strftime("%Y%m%d", time.localtime(e["ts"])) == today)
        self.kpis["total"].set(s["total"], f"{hoy} hoy" if s["total"] else "Aún no has analizado nada",
                               running(lambda e: True))
        self.kpis["alerta"].set(s["alerta"], "No los abras ni los ejecutes" if s["alerta"]
                                else "Nada peligroso detectado",
                                running(lambda e: e.get("estado") == "alerta"))
        self.kpis["pendiente"].set(s["pendiente"], "Ábrelos solo si confías en el origen"
                                   if s["pendiente"] else "Nada pendiente de revisar",
                                   running(lambda e: e.get("estado") == "pendiente"))

        total = s["total"]
        if total:
            pct = round(100 * s["limpio"] / total)
            self.ring.set(pct, "limpio" if pct >= 80 else "pendiente" if pct >= 50 else "alerta",
                          "seguros")
            self.ring_text.configure(text=f"{s['limpio']} de {total} archivos son seguros.")
        else:
            self.ring.clear()
            self.ring_text.configure(text="Analiza tu primer archivo para obtener tu puntuación.")

        if s["alerta"]:
            n = s["alerta"]
            self.home_title.configure(text=f"Hay {n} archivo{'s' if n != 1 else ''} en peligro.")
            self.home_sub.configure(text="Revisa la actividad y bórralos antes de abrirlos.",
                                    text_color=T.DANGER)
        elif self.watching:
            self.home_title.configure(text="Tus descargas están protegidas.")
            self.home_sub.configure(text="Sentinel revisa cada archivo nuevo en cuanto termina de llegar.",
                                    text_color=T.TEXT_SECONDARY)
        else:
            self.home_title.configure(text="Tus descargas están sin vigilar.")
            self.home_sub.configure(text="Activa la protección para revisar cada archivo que llegue.",
                                    text_color=T.TEXT_SECONDARY)

        self.timeline.set([(e.get("score", 0), e.get("estado", ""), e["archivo"]) for e in entries])
        self.donut.set(s)
        for key, lbl in self.legend.items():
            lbl.configure(text=str(s[key]))
        self.live_lbl.configure(text="●  en vivo" if self.watching else "●  en pausa",
                                text_color=T.SUCCESS if self.watching else T.TEXT_SECONDARY)

        sig = tuple((id(e), e.get("estado"), e.get("score")) for e in entries[-3:])
        if sig != getattr(self, "_recent_sig", None):
            self._recent_sig = sig
            for w in self.recent_box.winfo_children():
                w.destroy()
            if entries:
                for e in reversed(entries[-3:]):
                    self._recent_row(self.recent_box, e)
            else:
                ctk.CTkLabel(self.recent_box, text="Todavía no hay actividad.\nActiva la protección o "
                             "elige un archivo.", font=T.F_BODY, text_color=T.TEXT_SECONDARY,
                             justify="center").pack(expand=True, pady=24)

        steps = self._steps()
        pending = [x for x in steps if not x[1]]
        sig = tuple((x[0], x[1]) for x in steps)
        if sig != getattr(self, "_steps_sig", None):
            self._steps_sig = sig
            for w in self.steps_box.winfo_children():
                w.destroy()
            self.steps_count.configure(text=str(len(pending)),
                                       text_color=T.ON_PRIMARY if pending else T.TEXT_SECONDARY,
                                       fg_color=T.PRIMARY if pending else T.ELEVATED)
            for text, done, label, action in pending + [x for x in steps if x[1]]:
                self._step_row(self.steps_box, text, done, label, action)

        self._set_badge("activity", s["alerta"] + s["pendiente"],
                        T.DANGER if s["alerta"] else T.PRIMARY)

    def _steps(self):
        s = self.stats
        out = [("Activar la protección de Descargas", self.watching, "Activar", self.toggle)]
        if s["alerta"]:
            n = s["alerta"]
            out.append((f"Revisar {n} archivo{'s' if n != 1 else ''} en peligro", False, "Revisar",
                        lambda: self.show_view("activity")))
        try:
            has_vt = self._vt_state() == "disponible"
        except Exception:
            has_vt = False
        out.append(("Conectar VirusTotal (opcional)", has_vt, "Configurar",
                    lambda: self.show_view("config")))
        try:
            has_ai = bool(ai_analyst.status()["configured"])
        except Exception:
            has_ai = False
        out.append(("Activar el analista IA (opcional)", has_ai, "Configurar",
                    lambda: self.show_view("config")))
        try:
            has_report = REPORTS_DIR.exists() and any(REPORTS_DIR.glob("*.html"))
        except OSError:
            has_report = False
        out.append(("Generar tu primer informe", has_report, "Ver informes",
                    lambda: self.show_view("reports")))
        return out

    def _step_row(self, parent, text, done, action_text, action):
        row = ctk.CTkFrame(parent, fg_color="transparent", height=32)
        row.pack(fill="x", pady=1)
        row.pack_propagate(False)
        ctk.CTkLabel(row, text="✓" if done else "○", width=22, font=(T.UI_FONT, 14, "bold"),
                     text_color=T.SUCCESS if done else T.PRIMARY).pack(side="left")
        ctk.CTkLabel(row, text=text, font=(T.UI_FONT, 12), anchor="w",
                     text_color=T.TEXT_DISABLED if done else T.TEXT).pack(side="left", padx=(6, 0))
        if not done:
            ctk.CTkButton(row, text=f"{action_text} →", width=70, height=24, fg_color="transparent",
                          hover_color=T.ELEVATED, text_color=T.PRIMARY,
                          font=(T.UI_FONT, 12, "bold"), command=action).pack(side="right")

    def _recent_row(self, parent, entry):
        estado = entry.get("estado", "")
        color = _resolve_color(estado)
        row = ctk.CTkFrame(parent, fg_color=T.ELEVATED, corner_radius=10, height=40)
        row.pack(fill="x", pady=3)
        row.pack_propagate(False)
        ctk.CTkFrame(row, fg_color=color, width=4, height=1, corner_radius=2).pack(
            side="left", fill="y", padx=(6, 8), pady=8)
        ext, ext_color = ext_badge(entry["archivo"], entry.get("tipo"))
        ctk.CTkLabel(row, text=ext, width=42, height=24, font=(T.MONO_FONT, 10, "bold"),
                     text_color=ext_color, fg_color=T.BG, corner_radius=6).pack(side="left")
        name = entry["archivo"] if len(entry["archivo"]) <= 40 else entry["archivo"][:39] + "…"
        ctk.CTkLabel(row, text=name, font=(T.UI_FONT, 13, "bold"), text_color=T.TEXT,
                     anchor="w").pack(side="left", padx=10)
        ctk.CTkLabel(row, text=f" {T.STATE_TEXT.get(estado, estado.upper())} · {entry.get('score', 0)} ",
                     font=(T.UI_FONT, 11, "bold"), text_color=color,
                     fg_color=T.STATE_BG.get(estado, T.BG), corner_radius=6, height=24).pack(
            side="right", padx=10)
        ctk.CTkLabel(row, text=self._when(entry), font=(T.UI_FONT, 11),
                     text_color=T.TEXT_SECONDARY).pack(side="right")
        _bind_tree(row, "<Button-1>", lambda _e, e=entry: self._open_entry(e))
        _bind_tree(row, "<Enter>", lambda _e, r=row: r.configure(fg_color=T.ROW_HOVER))
        _bind_tree(row, "<Leave>", lambda _e, r=row: r.configure(fg_color=T.ELEVATED))
        row.configure(cursor="hand2")

    # ── vista de actividad ──
    def _build_activity(self, parent):
        frame = ctk.CTkFrame(parent, fg_color=T.BG, corner_radius=0)
        self.stage = ScanStage(frame, height=104)
        self.stage.pack(fill="x", pady=(6, 0))

        body = ctk.CTkFrame(frame, fg_color="transparent")
        body.pack(fill="both", expand=True, pady=(10, 0))
        body.grid_columnconfigure(0, weight=5, uniform="body")
        body.grid_columnconfigure(1, weight=6, uniform="body")
        body.grid_rowconfigure(0, weight=1)

        feed = ctk.CTkFrame(body, fg_color=T.SURFACE, corner_radius=14)
        feed.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        fh = ctk.CTkFrame(feed, fg_color="transparent")
        fh.pack(fill="x", padx=18, pady=(14, 6))
        ctk.CTkLabel(fh, text="Actividad reciente", font=(T.UI_FONT, 15, "bold"),
                     text_color=T.TEXT).pack(side="left")
        self.hint = ctk.CTkLabel(fh, text="pulsa un archivo para ver por qué",
                                 font=(T.UI_FONT, 11), text_color=T.TEXT_SECONDARY)
        self.hint.pack(side="right")
        self.table = ctk.CTkScrollableFrame(feed, fg_color="transparent")
        self.table.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        self.empty_box = ctk.CTkFrame(self.table, fg_color="transparent")
        self.empty_box.pack(fill="x", pady=40)
        self.empty_lbl = ctk.CTkLabel(
            self.empty_box, text="Todavía no hay archivos analizados.",
            font=(T.UI_FONT, 14, "bold"), text_color=T.TEXT)
        self.empty_lbl.pack()
        self.empty_sub = ctk.CTkLabel(
            self.empty_box,
            text="Activa la protección o elige un archivo arriba.\nCada resultado aparecerá aquí con su color.",
            font=T.F_BODY, text_color=T.TEXT_SECONDARY, justify="center")
        self.empty_sub.pack(pady=(6, 0))

        self._build_detail(body)
        return frame

    def _build_detail(self, body):
        panel = ctk.CTkFrame(body, fg_color=T.SURFACE, corner_radius=14)
        panel.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
        self.detail_panel = panel

        top = ctk.CTkFrame(panel, fg_color="transparent")
        top.pack(fill="x", padx=16, pady=(14, 4))
        self.gauge = ScoreGauge(top, size=132, bg=T.SURFACE)
        self.gauge.pack(side="left")
        info = ctk.CTkFrame(top, fg_color="transparent")
        info.pack(side="left", fill="both", expand=True, padx=(14, 0))
        self.detail_pill = ctk.CTkLabel(info, text="  SIN SELECCIÓN  ", font=(T.UI_FONT, 11, "bold"),
                                        text_color=T.TEXT_SECONDARY, fg_color=T.ELEVATED,
                                        corner_radius=6)
        self.detail_pill.pack(anchor="w")
        self.detail_verdict = ctk.CTkLabel(info, text="Elige un archivo", font=(T.UI_FONT, 21, "bold"),
                                           text_color=T.TEXT, anchor="w")
        self.detail_verdict.pack(anchor="w", pady=(6, 0))
        self.detail_reason = ctk.CTkLabel(
            info, text="Aquí verás si es seguro abrirlo y por qué.", font=T.F_BODY,
            text_color=T.TEXT_SECONDARY, anchor="w", justify="left", wraplength=380)
        self.detail_reason.pack(anchor="w", pady=(2, 0))
        self.detail_action = ctk.CTkLabel(info, text="", font=(T.UI_FONT, 13, "bold"),
                                          text_color=T.TEXT, anchor="w", justify="left",
                                          wraplength=380)
        self.detail_action.pack(anchor="w", pady=(6, 0))

        self.detail_file = ctk.CTkLabel(panel, text="", anchor="w", font=T.F_MONO_SM,
                                        text_color=T.TEXT_SECONDARY, justify="left", wraplength=560)
        self.detail_file.pack(fill="x", padx=18, pady=(4, 6))

        self.tabs = ctk.CTkTabview(panel, fg_color=T.ELEVATED, corner_radius=10,
                                   segmented_button_fg_color=T.BG,
                                   segmented_button_selected_color=T.PRIMARY,
                                   segmented_button_selected_hover_color=T.PRIMARY_HOVER,
                                   segmented_button_unselected_color=T.BG,
                                   segmented_button_unselected_hover_color=T.ELEVATED_HOVER,
                                   text_color=T.TEXT, height=220)
        self.tabs.pack(fill="both", expand=True, padx=12, pady=(0, 8))
        why = self.tabs.add("Por qué")
        tools = self.tabs.add("Herramientas")
        self.tabs._segmented_button.configure(font=(T.UI_FONT, 12, "bold"))

        self.why_box = ctk.CTkScrollableFrame(why, fg_color="transparent")
        self.why_box.pack(fill="both", expand=True)
        ctk.CTkLabel(self.why_box, text="Selecciona un archivo de la actividad reciente.",
                     font=T.F_BODY, text_color=T.TEXT_SECONDARY).pack(pady=24)

        self.detail_box = ctk.CTkTextbox(tools, wrap="word", fg_color=T.BG, font=T.F_MONO_SM,
                                         text_color=T.TEXT, border_width=0, corner_radius=8)
        self.detail_box.pack(fill="both", expand=True)
        tb = self.detail_box._textbox
        tb.tag_config("dim", foreground=T.TEXT_SECONDARY)
        tb.tag_config("head", foreground=T.PRIMARY)
        for sev, color in T.SEV_COLORS.items():
            tb.tag_config(f"sev_{sev}", foreground=color)

        actions = ctk.CTkFrame(panel, fg_color="transparent")
        actions.pack(side="bottom", fill="x", padx=12, pady=(0, 12), before=self.tabs)
        self.report_btn = ctk.CTkButton(actions, text="Generar informe", height=34,
                                        command=self.export_report, state="disabled",
                                        **T.disabled_button_style("secondary"))
        self.report_btn.pack(side="left", expand=True, fill="x", padx=4)
        self.trace_btn = ctk.CTkButton(actions, text="Trazar código", height=34,
                                       command=self.trace_selected, state="disabled",
                                       **T.disabled_button_style("secondary"))
        self.trace_btn.pack(side="left", expand=True, fill="x", padx=4)
        self.ai_btn = ctk.CTkButton(actions, text="Preguntar a la IA", height=34,
                                    command=self.ai_selected, state="disabled",
                                    **T.disabled_button_style("secondary"))
        self.ai_btn.pack(side="left", expand=True, fill="x", padx=4)

    def _btn(self, kind, size=13):
        style = dict(T.button_style(kind))
        style["font"] = (T.UI_FONT, size, "bold")
        style["corner_radius"] = 10
        return style

    # ── informes y motores ──
    def _build_reports(self, parent):
        frame = ctk.CTkFrame(parent, fg_color=T.SURFACE, corner_radius=14)
        top = ctk.CTkFrame(frame, fg_color="transparent")
        top.pack(fill="x", padx=20, pady=(18, 10))
        ctk.CTkLabel(top, text="Informes generados", font=(T.UI_FONT, 20, "bold"),
                     text_color=T.TEXT).pack(side="left")
        ctk.CTkButton(top, text="Actualizar", width=110, height=32,
                      command=self._refresh_reports, **T.button_style("secondary")).pack(side="right")
        self.reports_box = ctk.CTkScrollableFrame(frame, fg_color="transparent")
        self.reports_box.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        self.reports_empty = ctk.CTkLabel(
            self.reports_box,
            text="Sin informes todavía.\nAbre un resultado en Inicio y pulsa «Generar informe».",
            font=(T.UI_FONT, 14), text_color=T.TEXT_SECONDARY, justify="center")
        self.reports_empty.pack(padx=16, pady=60)
        return frame

    def _build_config(self, parent):
        frame = ctk.CTkScrollableFrame(parent, fg_color=T.SURFACE, corner_radius=14)
        ctk.CTkLabel(frame, text="Motores de análisis", font=(T.UI_FONT, 20, "bold"),
                     text_color=T.TEXT).pack(anchor="w", padx=20, pady=(18, 2))
        ctk.CTkLabel(frame, text="Cada archivo pasa por todos los motores que le corresponden.",
                     font=T.F_BODY, text_color=T.TEXT_SECONDARY).pack(anchor="w", padx=20, pady=(0, 12))
        cards = ctk.CTkFrame(frame, fg_color="transparent")
        cards.pack(fill="both", expand=True, padx=14, pady=(0, 14))
        cards.grid_columnconfigure((0, 1), weight=1, uniform="cfg")
        self.cfg_engine_state = {}
        rows = [
            ("YARA", "Busca patrones conocidos de malware en el contenido.", self._engine_state("yara"), "yara"),
            ("Ejecutables (pefile)", "Lee imports, secciones y punto de entrada de .exe y .dll.",
             self._engine_state("pefile"), "pe"),
            ("Ingeniería inversa (capa)", "Desensambla el ejecutable y deduce qué sabe hacer.",
             self._engine_state("capa"), "capa"),
            ("Desensamblador (capstone)", "Lee las primeras instrucciones del programa.",
             self._engine_state("capstone"), "capstone"),
            ("PDF (pypdf)", "Detecta JavaScript y acciones automáticas.", self._engine_state("pypdf"), "pdf"),
            ("Office (oletools)", "Extrae y revisa macros VBA.", self._engine_state("oletools"), "ole"),
            ("VirusTotal", "Consulta opcional con tu propia clave.", self._vt_state(), "vt"),
            ("Carpeta protegida", str(WATCH_DIR), None, None),
        ]
        for i, (label, desc, value, alias) in enumerate(rows):
            card = ctk.CTkFrame(cards, fg_color=T.ELEVATED, corner_radius=12)
            card.grid(row=i // 2, column=i % 2, sticky="nsew", padx=6, pady=6)
            ctk.CTkLabel(card, text=label, font=(T.UI_FONT, 14, "bold"), text_color=T.TEXT,
                         anchor="w").pack(anchor="w", padx=16, pady=(14, 0))
            ctk.CTkLabel(card, text=desc, font=T.F_BODY, text_color=T.TEXT_SECONDARY, anchor="w",
                         justify="left", wraplength=360).pack(anchor="w", padx=16, pady=(2, 0))
            if alias:
                color = T.SUCCESS if value == "disponible" else (
                    T.WARNING if value == "sin clave API" else T.DANGER)
                state_lbl = ctk.CTkLabel(card, text=f"●  {value}", font=(T.UI_FONT, 12, "bold"),
                                         text_color=color, anchor="w")
                state_lbl.pack(anchor="w", padx=16, pady=(6, 14))
                self.cfg_engine_state[alias] = state_lbl
            else:
                ctk.CTkFrame(card, fg_color="transparent", height=10).pack()
        return frame

    def _engine_state(self, name):
        try:
            import importlib.util
            return "disponible" if importlib.util.find_spec(name) else "no instalado"
        except Exception:
            return "error"

    def _vt_state(self):
        try:
            from engines import virustotal
            return "disponible" if virustotal.has_api_key() else "sin clave API"
        except Exception:
            return "no disponible"

    def _refresh_reports(self):
        for w in self.reports_box.winfo_children():
            if w is not self.reports_empty:
                w.destroy()
        if not REPORTS_DIR.exists():
            self._reports_empty_state(True)
            return
        files = sorted(REPORTS_DIR.glob("*.html"), key=lambda p: p.stat().st_mtime, reverse=True)
        for f in files:
            row = ctk.CTkFrame(self.reports_box, fg_color=T.ELEVATED, corner_radius=10)
            row.pack(fill="x", padx=4, pady=4)
            size_kb = f.stat().st_size / 1024.0
            stamp = time.strftime("%d %b %H:%M", time.localtime(f.stat().st_mtime))
            ctk.CTkLabel(row, text="▤", font=(T.UI_FONT, 18), text_color=T.PRIMARY).pack(
                side="left", padx=(14, 6), pady=10)
            ctk.CTkLabel(row, text=f.name, font=T.F_MONO_SM, text_color=T.TEXT,
                         anchor="w").pack(side="left", padx=4)
            ctk.CTkLabel(row, text=f"{size_kb:.1f} KB · {stamp}", font=T.F_MONO_SM,
                         text_color=T.TEXT_SECONDARY).pack(side="left", padx=12)
            ctk.CTkButton(row, text="Abrir", width=80, height=30,
                          command=lambda p=str(f): os.startfile(p),
                          **T.button_style("primary")).pack(side="right", padx=10, pady=8)
        self._reports_empty_state(not files)

    def _reports_empty_state(self, show):
        if show:
            self.reports_empty.pack(padx=16, pady=60)
        else:
            self.reports_empty.pack_forget()

    # ── vigilancia ──
    def toggle(self):
        if self.watching:
            self._stop_watch()
        else:
            self._start_watch()

    def _start_watch(self):
        if self.watcher:
            return
        self.watcher = Watcher(self.queue)
        self.watcher.prepare()
        self.watcher.start()
        self.watching = True
        self.monitor_ready = True
        self.watch_btn.configure(text="Desactivar", **self._btn("secondary", 14))
        self.nav_dot.configure(text="●  activa", text_color=T.SUCCESS)
        self.prot_title.configure(text="Protección activa", text_color=T.SUCCESS)
        self.prot_desc.configure(text="Cada archivo nuevo en Descargas se analiza en cuanto termina de llegar.")
        self.shield.set_active(True)
        self.stage.set_active(True)
        self.timeline.set_active(True)
        self._schedule_home()

    def _stop_watch(self):
        if self.watcher:
            self.watcher.stop()
            self.watcher = None
        self.watching = False
        self.monitor_ready = False
        self.watch_btn.configure(text="Activar protección", **self._btn("primary", 14))
        self.nav_dot.configure(text="●  desactivada", text_color=T.TEXT_SECONDARY)
        self.prot_title.configure(text="Protección desactivada", text_color=T.TEXT)
        self.prot_desc.configure(
            text="Actívala y Sentinel revisará cada archivo que llegue a tu carpeta Descargas.")
        self.shield.set_active(False)
        self.stage.set_active(False)
        self.timeline.set_active(False)
        self._schedule_home()

    def _check_watcher(self):
        """Si el hilo de vigilancia muere, la interfaz no puede seguir diciendo «activa»."""
        if self.watching and self.watcher and not self.watcher.is_alive() \
                and time.time() - getattr(self, "_watch_restart", 0) > 5:
            self._watch_restart = time.time()
            reason = self.watcher.last_error or "el hilo terminó inesperadamente"
            self._stop_watch()
            self._start_watch()
            self.hint.configure(text=f"vigilancia reiniciada: {reason}"[:70])

    def _poll(self):
        self._check_watcher()
        try:
            while True:
                entry = self.queue.get_nowait()
                self._add_row(entry)
        except queue.Empty:
            pass
        self.after(GUI_POLL_MS, self._poll)

    # ── lista de actividad ──
    def _add_row(self, entry):
        if entry.get("estado") in ("limpio", "pendiente", "alerta") and not entry.get("staged"):
            entry["staged"] = True
            self.stage.push(entry.get("archivo", ""), entry["estado"])
        existing = entry.get("row")
        if existing and existing in self.rows and entry.get("update"):
            self._update_row(existing, entry)
            return
        if entry.get("update"):
            return

        row = len(self.rows) + 1
        entry["row"] = row
        entry.setdefault("hora", time.strftime("%H:%M:%S"))
        entry.setdefault("ts", time.time())
        self.rows[row] = entry
        self.empty_box.pack_forget()

        card = tk.Frame(self.table, bg=T.ELEVATED, bd=0, highlightthickness=1,
                        highlightbackground=T.ELEVATED, highlightcolor=T.ELEVATED, height=60)
        newest = next((e["card"] for e in reversed(list(self.rows.values()))
                       if e is not entry and e.get("card") and e["card"].winfo_exists()), None)
        if newest is not None:
            card.pack(fill="x", padx=4, pady=3, before=newest)
        else:
            card.pack(fill="x", padx=4, pady=3)
        card.pack_propagate(False)
        entry["card"] = card
        self._fill_card(card, entry)

        self._bump_stats(entry)
        self._pulse_card(card)
        if self.view == "reports":
            self._refresh_reports()
        if len(self.rows) > _MAX_ROWS:
            self._drop_oldest()

    def _paint_card(self, card, bg, border=None):
        card.configure(bg=bg, highlightbackground=border or bg, highlightcolor=border or bg)
        for w in card.winfo_children():
            if getattr(w, "_row_bg", False):
                w.configure(bg=bg)
            for g in w.winfo_children():
                if getattr(g, "_row_bg", False):
                    g.configure(bg=bg)

    def _fill_card(self, card, entry):
        """Fila de actividad con widgets planos de Tk: las tarjetas redondeadas de CTk
        dibujan un lienzo por widget y hacían que la lista se pegara al deslizar."""
        for w in card.winfo_children():
            w.destroy()
        estado = entry["estado"]
        color = _resolve_color(estado)

        def label(parent, row_bg=True, **kw):
            lbl = tk.Label(parent, bd=0, highlightthickness=0, **kw)
            lbl._row_bg = row_bg
            return lbl

        tk.Frame(card, bg=color, width=5, bd=0).pack(side="left", fill="y", padx=(6, 10), pady=10)
        ext, ext_color = ext_badge(entry["archivo"], entry.get("tipo"))
        label(card, row_bg=False, text=ext, width=5, font=(T.MONO_FONT, 10, "bold"), fg=ext_color,
              bg=T.BG).pack(side="left", pady=14, ipady=3)
        pill = label(card, row_bg=False, text=f"{T.STATE_TEXT.get(estado, estado.upper())} · "
                     f"{entry.get('score', 0)}", font=(T.UI_FONT, 10, "bold"), fg=color,
                     bg=T.STATE_BG.get(estado, T.BG), padx=8, pady=3)
        pill.pack(side="right", padx=12)
        names = tk.Frame(card, bg=T.ELEVATED, bd=0)
        names._row_bg = True
        names.pack(side="left", fill="x", expand=True, padx=12)
        name = entry["archivo"] if len(entry["archivo"]) <= 38 else entry["archivo"][:37] + "…"
        label(names, text=name, font=(T.UI_FONT, 11, "bold"), fg=T.TEXT, bg=T.ELEVATED,
              anchor="w").pack(anchor="w", pady=(10, 0))
        n = len([f for f in entry.get("findings", []) if confidence(f) != "baja"])
        sub = f"{self._when(entry)} · {entry.get('tipo', '').lower()} · " + (
            f"{n} indicio{'s' if n != 1 else ''}" if n else "sin indicios")
        label(names, text=sub, font=(T.UI_FONT, 9), fg=T.TEXT_SECONDARY, bg=T.ELEVATED,
              anchor="w").pack(anchor="w")
        _bind_tree(card, "<Button-1>", lambda _e, e=entry: self._show_detail(e))
        _bind_tree(card, "<Enter>", lambda _e, e=entry: self._hover(e, True))
        _bind_tree(card, "<Leave>", lambda _e, e=entry: self._hover(e, False))
        card.configure(cursor="hand2")

    def _hover(self, entry, on):
        card = entry.get("card")
        if not card or not card.winfo_exists() or self.selected is entry:
            return
        self._paint_card(card, T.ROW_HOVER if on else T.ELEVATED)

    def _pulse_card(self, card):
        for i in range(_PULSE_STEPS, -1, -1):
            shade = _hex_rc(T.ELEVATED, int(22 * i / _PULSE_STEPS))
            self.after((_PULSE_STEPS - i) * _MOTION_MS * 2,
                       lambda s=shade: card.winfo_exists() and self.selected is None and
                       self._paint_card(card, s))

    def _drop_oldest(self):
        oldest = min(self.rows)
        entry = self.rows.pop(oldest)
        card = entry.get("card")
        if card and card.winfo_exists():
            card.destroy()

    def _update_row(self, row, entry):
        old = self.rows[row]
        self._bump_stats(old, removing=True)
        entry["card"] = old.get("card")
        self.rows[row] = entry
        self._bump_stats(entry)
        if entry.get("card") and entry["card"].winfo_exists():
            self._fill_card(entry["card"], entry)
        if self.selected is old or self.selected is entry:
            self._show_detail(entry)

    def _bump_stats(self, entry, removing=False):
        delta = -1 if removing else 1
        self.stats["total"] += delta
        self.stats["score_sum"] += entry.get("score", 0) * delta
        estado = entry.get("estado", "")
        if estado in ("alerta", "pendiente", "limpio"):
            self.stats[estado] += delta
        self._refresh_stats()

    def _refresh_stats(self):
        self._schedule_home()
        self._schedule_save()

    def _schedule_save(self):
        if self.demo or self._loading or self._save_job is not None:
            return
        self._save_job = self.after(2000, self._save_history)

    def _save_history(self):
        self._save_job = None
        history.save([self.rows[k] for k in sorted(self.rows)])

    def _load_history(self):
        items = history.load()
        self._loading = True

        def step():
            for e in items[:8]:
                e["staged"] = True
                self._add_row(e)
            del items[:8]
            if items:
                self.after(25, step)
            else:
                self._loading = False

        step()

    # ── detalle ──
    def _show_detail(self, entry):
        previous = self.selected
        self.selected = entry
        if previous is not None and previous is not entry and previous.get("card") \
                and previous["card"].winfo_exists():
            self._paint_card(previous["card"], T.ELEVATED, T.ELEVATED)
        card = entry.get("card")
        estado = entry["estado"]
        color = _resolve_color(estado)
        if card and card.winfo_exists():
            self._paint_card(card, T.ROW_SELECTED, color)

        title, reason, action = T.VERDICT_TEXT.get(estado, (estado, "", ""))
        errors = entry.get("errors") or []
        if estado == "pendiente" and errors and not [f for f in entry.get("findings", [])
                                                     if confidence(f) != "baja"]:
            title = "No se pudo revisar del todo"
            reason = errors[0][:140]
            action = "Trátalo como no verificado: ábrelo solo si confías en quien te lo envió."
        self.gauge.set(entry.get("score", 0), estado, "riesgo / 100")
        self.detail_pill.configure(text=f"  {T.STATE_TEXT.get(estado, estado.upper())}  ",
                                   text_color=color, fg_color=T.STATE_BG.get(estado, T.ELEVATED))
        self.detail_verdict.configure(text=title, text_color=color)
        self.detail_reason.configure(text=reason)
        self.detail_action.configure(text=f"→ {action}" if action else "")
        self.detail_file.configure(text=entry.get("ruta", ""))
        self.hint.configure(text=entry["archivo"][:40])
        self._set_trace_button(entry)
        self._render_why(entry)

        self.detail_box.delete("1.0", "end")
        engine = entry.get("engine", "")
        if engine:
            self.detail_box.insert("end", "MOTORES USADOS\n", "head")
            self.detail_box.insert("end", f"  {engine.replace('multi:', '').replace('+', ' · ')}\n\n", "dim")
        if entry.get("errors"):
            self.detail_box.insert("end", "AVISOS DEL ANÁLISIS\n", "head")
            for err in entry["errors"]:
                self.detail_box.insert("end", f"  {err}\n", "dim")
            self.detail_box.insert("end", "\n")
        self._render_iocs(entry)
        self._render_ai(entry)

    def _render_why(self, entry):
        for w in self.why_box.winfo_children():
            w.destroy()
        findings = sorted(entry.get("findings", []),
                          key=lambda f: (_CONF_ORDER.get(confidence(f), 1),
                                         _SEV_ORDER.get(f.get("severidad"), 3)))
        strong = [f for f in findings if confidence(f) != "baja"]
        weak = [f for f in findings if confidence(f) == "baja"]

        if not findings:
            msg = {"limpio": "Ningún motor encontró nada que señalar.",
                   "pendiente": "El análisis no pudo completarse. Vuelve a intentarlo."}.get(
                entry["estado"], "Sin coincidencias.")
            if entry.get("errors"):
                msg = "El análisis no pudo completarse:\n" + "\n".join(
                    f"· {e[:150]}" for e in entry["errors"][:4])
            ctk.CTkLabel(self.why_box, text=msg, font=T.F_BODY, text_color=T.TEXT_SECONDARY).pack(pady=24)
            return

        seen = set()
        for f in strong:
            key = (f.get("rule_id") or f.get("regla"), f.get("detalle"))
            if key in seen:
                continue
            seen.add(key)
            self._finding_card(f)

        if weak:
            kinds = sorted({f.get("regla", "") for f in weak})
            box = ctk.CTkFrame(self.why_box, fg_color=T.BG, corner_radius=8)
            box.pack(fill="x", padx=2, pady=(6, 4))
            ctk.CTkLabel(box, text=f"{len(weak)} señal{'es' if len(weak) != 1 else ''} débil"
                                   f"{'es' if len(weak) != 1 else ''} · normales en software legítimo",
                         font=(T.UI_FONT, 12, "bold"), text_color=T.TEXT_SECONDARY,
                         anchor="w").pack(anchor="w", padx=12, pady=(8, 0))
            ctk.CTkLabel(box, text=" · ".join(kinds)[:400], font=(T.UI_FONT, 11),
                         text_color=T.TEXT_DISABLED, anchor="w", justify="left",
                         wraplength=520).pack(anchor="w", padx=12, pady=(2, 8))

    def _finding_card(self, f):
        conf = confidence(f)
        sev = f.get("severidad", "")
        sev_color = T.SEV_COLORS.get(sev, T.TEXT_SECONDARY)
        card = ctk.CTkFrame(self.why_box, fg_color=T.BG, corner_radius=8)
        card.pack(fill="x", padx=2, pady=4)
        ctk.CTkFrame(card, fg_color=sev_color, width=4, height=1, corner_radius=2).pack(
            side="left", fill="y", padx=(6, 0), pady=8)
        body = ctk.CTkFrame(card, fg_color="transparent", height=1)
        body.pack(side="left", fill="both", expand=True, padx=10, pady=8)
        head = ctk.CTkFrame(body, fg_color="transparent", height=1)
        head.pack(fill="x")
        ctk.CTkLabel(head, text=f.get("regla", ""), font=(T.UI_FONT, 13, "bold"), text_color=T.TEXT,
                     anchor="w", justify="left", wraplength=330).pack(side="left", anchor="w")
        ctk.CTkLabel(head, text=f" {T.CONFIDENCE_TEXT.get(conf, conf)} ", font=(T.UI_FONT, 10, "bold"),
                     text_color=T.CONFIDENCE_COLORS.get(conf, T.TEXT_SECONDARY),
                     fg_color=T.ELEVATED, corner_radius=5).pack(side="right")
        detalle = f.get("detalle", "")
        line = f.get("line", 0)
        if line:
            detalle = f"línea {line}: {detalle}"
        if detalle:
            ctk.CTkLabel(body, text=detalle[:220], font=T.F_MONO_SM, text_color=T.TEXT_SECONDARY,
                         anchor="w", justify="left", wraplength=440).pack(anchor="w", pady=(3, 0))
        meta = []
        if f.get("mitre_id"):
            meta.append(f"MITRE {f['mitre_id']} · {f.get('mitre_name', '')}")
        if f.get("atenuado"):
            meta.append(f["atenuado"])
        if meta:
            ctk.CTkLabel(body, text="   ".join(meta)[:200], font=(T.UI_FONT, 10),
                         text_color=T.TEXT_DISABLED, anchor="w").pack(anchor="w", pady=(3, 0))

    def _render_ai(self, entry):
        text = entry.get("ai_text")
        if not text:
            return
        meta = entry.get("ai_meta") or {}
        origen = "caché" if meta.get("cached") else "nuevo"
        self.detail_box.insert("end", f"\nANALISTA IA · {meta.get('provider', '')} · "
                                      f"{meta.get('model', '')} · {origen}\n", "head")
        for line in text.splitlines():
            self.detail_box.insert("end", f"  {line}\n")

    def _tools_note(self, title, body):
        self.tabs.set("Herramientas")
        self.detail_box.insert("end", f"\n{title}\n", "head")
        self.detail_box.insert("end", body)
        self.detail_box.see("end")

    def ai_selected(self):
        entry = self.selected
        if not entry:
            return
        state = ai_analyst.status()
        if not state["configured"]:
            self._tools_note("ANALISTA IA", "  no configurado: " + state["reason"] + "\n"
                             "  guía en README.md > Analista IA (opcional)\n")
            return
        self.ai_btn.configure(text="Pensando…", state="disabled", **T.disabled_button_style("secondary"))
        threading.Thread(target=self._ai_worker, args=(entry,), daemon=True).start()

    def _ai_worker(self, entry):
        result = ai_analyst.explain(entry)
        self.after(0, lambda: self._ai_done(entry, result))

    def _ai_done(self, entry, result):
        self.ai_btn.configure(text="Preguntar a la IA", state="normal", **T.button_style("secondary"))
        if not result["ok"]:
            self._tools_note("ANALISTA IA · sin respuesta", f"  {result['error']}\n")
            return
        entry["ai_text"] = result["text"]
        entry["ai_meta"] = {"provider": result["provider"], "model": result["model"],
                            "cached": result["cached"]}
        self._schedule_save()
        if self.selected is entry:
            self.tabs.set("Herramientas")
            self._render_ai(entry)
            self.detail_box.see("end")

    def _set_trace_button(self, entry):
        if not entry:
            for b in (self.trace_btn, self.report_btn, self.ai_btn):
                b.configure(state="disabled", **T.disabled_button_style("secondary"))
            return
        self.report_btn.configure(state="normal", **T.button_style("secondary"))
        self.ai_btn.configure(state="normal", **T.button_style("secondary"))
        if entry.get("tipo") == "CÓDIGO":
            self.trace_btn.configure(text="Trazar código", state="normal", **T.button_style("secondary"))
        else:
            self.trace_btn.configure(text="Trazar (solo Python)", state="disabled",
                                     **T.disabled_button_style("secondary"))

    def _render_iocs(self, entry):
        ruta = entry.get("ruta")
        found = entry.get("iocs")
        if found is None:
            found = iocs_mod.extract_file(ruta) if ruta else []
            entry["iocs"] = found
        if not found:
            return
        self.detail_box.insert("end", "INDICADORES DE COMPROMISO (IOC)\n", "head")
        for ioc in found:
            self.detail_box.insert("end", f"  {ioc['tipo']:<7} {ioc['valor']}\n")

    def trace_selected(self):
        entry = self.selected
        if not entry or entry.get("tipo") != "CÓDIGO":
            return
        self.trace_btn.configure(text="Trazando…", state="disabled", **T.disabled_button_style("secondary"))
        self.after(40, lambda: self._run_trace(entry))

    def _run_trace(self, entry):
        try:
            result = tracer.trace(entry["ruta"])
            entry["trace_events"] = result.get("events", [])
            entry["trace_findings"] = result.get("findings", [])
            events = result.get("events", [])
            body = "  sin llamadas peligrosas en el código\n" if not events else "".join(
                f"  L{ev['line']:<4} {ev['evento']:<16} {ev['args']}\n" for ev in events)
            note = result.get("error")
            if note:
                body += f"  no se pudo completar: {note}\n"
            self._tools_note("TRAZA ESTÁTICA (el archivo no se ejecuta)", body)
        finally:
            self.trace_btn.configure(text="Trazar código", state="normal", **T.button_style("secondary"))

    def export_report(self):
        entry = self.selected
        if not entry:
            return
        path = report.write(entry)
        self._tools_note("INFORME GENERADO", f"  {path}\n")
        if self.view == "reports":
            self._refresh_reports()

    # ── análisis manual en segundo plano ──
    def manual(self):
        if self.busy:
            return
        path = filedialog.askopenfilename(initialdir=str(WATCH_DIR))
        if not path:
            return
        self.busy = True
        self.drop.set_busy(True)
        self.stage.set_active(True)
        threading.Thread(target=self._manual_worker, args=(path,), daemon=True).start()

    def _manual_worker(self, path):
        # Quien elige un archivo a mano espera un veredicto: se analiza aunque el
        # vigilante lo ignoraría (temporal, oculto, dentro de la carpeta de Sentinel).
        tipo = classify(path)
        if tipo == "IGNORAR":
            tipo = "CÓDIGO" if Path(path).suffix.lower() in CODE_EXTENSIONS else "BINARIO"
        entry = {
            "hora": time.strftime("%H:%M:%S"),
            "ts": time.time(),
            "archivo": Path(path).name,
            "ruta": path,
            "tipo": tipo,
            "estado": "pendiente",
            "score": 0,
            "findings": [],
            "engine": "",
            "online": False,
        }
        result = analyze(path, online=self._vt_state() == "disponible", force=True)
        entry["estado"] = result["estado"]
        entry["score"] = result.get("score", 0)
        entry["findings"] = result["findings"]
        entry["engine"] = result.get("engine", "")
        if result.get("errors"):
            entry["errors"] = result["errors"]
        self.after(0, lambda: self._manual_done(entry))

    def _manual_done(self, entry):
        self.busy = False
        self.drop.set_busy(False)
        if not self.watching:
            self.stage.set_active(False)
        self._add_row(entry)
        self.show_view("activity")
        self._show_detail(entry)


def run():
    app = SentinelApp()
    app.mainloop()


if __name__ == "__main__":
    run()
