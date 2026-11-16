import os
import queue
import sys
import threading
import time
import tkinter as tk
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import customtkinter as ctk
from tkinter import filedialog, messagebox

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
from core import quarantine
from core.analyzer import entry_extras
from reports import report
from ui import history
from ui import settings as user_settings
from ui import theme as T
from ui.icons import icon

try:  # arrastrar y soltar: opcional, la app funciona sin ello
    from tkinterdnd2 import DND_FILES, TkinterDnD
    _DND_BASES = (TkinterDnD.DnDWrapper,)
except Exception:  # noqa: BLE001
    TkinterDnD, DND_FILES, _DND_BASES = None, None, ()

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

_MOTION_MS = 16
_PULSE_STEPS = 10
_MAX_ROWS = 60
_FLASH_MS = 4500
_CONF_ORDER = {"alta": 0, "media": 1, "baja": 2}
_SEV_ORDER = {"crítico": 0, "alto": 1, "medio": 2, "bajo": 3}
_FILTERS = (("todos", "Todos", None), ("alerta", "Peligro", T.DANGER),
            ("pendiente", "Revisar", T.WARNING), ("limpio", "Seguros", T.SUCCESS))


def _resolve_color(estado):
    return T.STATE_COLORS.get(estado, T.TEXT_SECONDARY)


def _hex_rc(c, delta):
    h = c.lstrip("#")
    r = max(0, min(255, int(h[0:2], 16) + delta))
    g = max(0, min(255, int(h[2:4], 16) + delta))
    b = max(0, min(255, int(h[4:6], 16) + delta))
    return f"#{r:02x}{g:02x}{b:02x}"


def _mix(a, b, t):
    """Color entre a y b (t de 0 a 1), para transiciones cortas."""
    a, b = a.lstrip("#"), b.lstrip("#")
    out = [round(int(a[i:i + 2], 16) * (1 - t) + int(b[i:i + 2], 16) * t) for i in (0, 2, 4)]
    return "#" + "".join(f"{v:02x}" for v in out)


def _ease(t):
    return 1 - (1 - t) ** 3


_KINDS = (
    ({"exe", "dll", "scr", "msi", "com", "sys", "cpl"}, "Programa"),
    ({"py", "ps1", "bat", "cmd", "vbs", "js", "jse", "sh", "php", "hta", "wsf"}, "Script"),
    ({"jpg", "jpeg", "png", "gif", "bmp", "webp", "ico", "svg"}, "Imagen"),
    ({"pdf"}, "PDF"),
    ({"doc", "docx", "docm", "dot", "dotm", "rtf", "odt"}, "Documento"),
    ({"xls", "xlsx", "xlsm", "xlsb", "xlam", "csv", "ods"}, "Hoja de cálculo"),
    ({"ppt", "pptx", "pptm"}, "Presentación"),
    ({"zip", "rar", "7z", "tar", "gz", "iso"}, "Comprimido"),
    ({"txt", "md", "log", "json", "xml", "html", "htm"}, "Texto"),
    ({"mp3", "wav", "mp4", "mkv", "avi", "mov"}, "Multimedia"),
)


def kind_label(name, tipo=""):
    """Tipo de archivo en palabras de usuario, no «binario»."""
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    for exts, label in _KINDS:
        if ext in exts:
            return label
    return "Script" if tipo == "CÓDIGO" else "Archivo"


def _size(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


class TabBar(ctk.CTkFrame):
    """Pestañas con subrayado: más legibles que el botón segmentado de CTk."""

    def __init__(self, master):
        super().__init__(master, fg_color="transparent")
        self.head = ctk.CTkFrame(self, fg_color="transparent")
        self.head.pack(fill="x")
        ctk.CTkFrame(self, fg_color=T.BORDER, height=1).pack(fill="x")
        self.body = ctk.CTkFrame(self, fg_color="transparent")
        self.body.pack(fill="both", expand=True, pady=(8, 0))
        self.pages, self.btns, self.current = {}, {}, None

    def add(self, name):
        wrap = ctk.CTkFrame(self.head, fg_color="transparent", width=1, height=1)
        wrap.pack(side="left", padx=(0, 18))
        btn = ctk.CTkButton(wrap, text=name, width=1, height=32, fg_color="transparent",
                            hover_color=T.SURFACE, text_color=T.TEXT_SECONDARY,
                            font=(T.UI_FONT, 13, "bold"), corner_radius=0, border_spacing=2,
                            command=lambda n=name: self.set(n))
        btn.pack()
        bar = ctk.CTkFrame(wrap, fg_color="transparent", width=1, height=2, corner_radius=0)
        bar.pack(fill="x")
        page = ctk.CTkFrame(self.body, fg_color="transparent")
        self.pages[name], self.btns[name] = page, (btn, bar)
        if self.current is None:
            self.set(name)
        return page

    def set(self, name):
        if name == self.current:
            return
        for n, page in self.pages.items():
            btn, bar = self.btns[n]
            on = n == name
            btn.configure(text_color=T.TEXT if on else T.TEXT_SECONDARY)
            bar.configure(fg_color=T.PRIMARY if on else "transparent")
            if on:
                page.pack(fill="both", expand=True)
            else:
                page.pack_forget()
        self.current = name


def _bind_tree(widget, event, callback):
    widget.bind(event, callback, add="+")
    for child in widget.winfo_children():
        _bind_tree(child, event, callback)


class RiskBar(tk.Canvas):
    """Barra horizontal 0-100 con el riesgo del archivo; se desliza al cambiar."""

    def __init__(self, master, bg=T.SURFACE):
        super().__init__(master, height=10, bg=bg, bd=0, highlightthickness=0)
        self._value = 0.0
        self._target = 0.0
        self._color = T.TEXT_DISABLED
        self._job = None
        self.bind("<Configure>", lambda _e: self._draw())

    def set(self, score, color):
        self._target = max(0.0, min(100.0, float(score)))
        self._color = color
        self._start, self._t0 = self._value, time.perf_counter()
        if self._job is None:
            self._tick()

    def _tick(self):
        t = min(1.0, (time.perf_counter() - self._t0) * 1000 / 260)
        self._value = self._start + (self._target - self._start) * _ease(t)
        self._draw()
        self._job = self.after(_MOTION_MS, self._tick) if t < 1 else None

    def _draw(self):
        self.delete("all")
        w, h = self.winfo_width(), self.winfo_height()
        if w < 4:
            return
        self.create_rectangle(0, 3, w, h - 3, fill=T.ELEVATED, outline="")
        x = max(4, w * self._value / 100)
        self.create_rectangle(0, 3, x, h - 3, fill=self._color, outline="")
        self.create_rectangle(x - 2, 0, x + 1, h, fill=self._color, outline="")


class ActivityLine(tk.Canvas):
    """Línea fina bajo la barra de estado: un tramo que recorre mientras hay análisis."""

    def __init__(self, master, bg=T.SURFACE):
        super().__init__(master, height=2, bg=bg, bd=0, highlightthickness=0)
        self._on = False
        self._job = None
        self._color = T.INFO

    def set(self, on, color=T.INFO):
        self._color = color
        if on == self._on:
            return
        self._on = on
        if on and self._job is None:
            self._t0 = time.perf_counter()
            self._tick()
        if not on:
            self.delete("all")

    def _tick(self):
        if not self._on:
            self._job = None
            return
        w = self.winfo_width()
        p = ((time.perf_counter() - self._t0) / 1.1) % 1.0
        seg = w * 0.28
        x = -seg + (w + seg) * _ease(p)
        self.delete("all")
        self.create_rectangle(x, 0, x + seg, 2, fill=self._color, outline="")
        self._job = self.after(_MOTION_MS, self._tick)


class SentinelApp(ctk.CTk, *_DND_BASES):
    PADDING = {"files": (20, 16), "quarantine": (20, 16), "reports": (20, 16), "settings": (20, 16)}

    def __init__(self):
        super().__init__()
        self.prefs = user_settings.load()
        self._status_job = None
        self._save_job = None
        self._flash = None
        self._flash_job = None
        self._breath_job = None
        self._user_picked = False
        self._loading = False
        self.title("Sentinel — ¿es seguro este archivo?")
        self.geometry("1280x800")
        self.minsize(1024, 640)
        self.configure(fg_color=T.BG)
        icon_path = PROJECT_DIR / "assets" / "sentinel.ico"
        if icon_path.exists():
            # CustomTkinter pone su icono a los ~200 ms; el nuestro va después.
            self.after(300, lambda: self.iconbitmap(str(icon_path)))

        self.queue = queue.Queue()
        self.watcher = None
        self.watching = False
        self.rows = {}
        self.selected = None
        self.view = "files"
        self.filter = "todos"
        self.monitor_ready = False
        self.busy = False
        self.busy_name = ""
        self.stats = {"total": 0, "alerta": 0, "pendiente": 0, "limpio": 0, "score_sum": 0}

        self.jobs = []
        self.job_total = 0
        self.query = ""
        self._paint_window_background()
        self._build()
        self._enable_drop()

    # ── estructura ──
    def _build(self):
        self.sidebar = ctk.CTkFrame(self, fg_color=T.SURFACE, corner_radius=0, width=200)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)

        brand = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        brand.pack(fill="x", padx=18, pady=(22, 24))
        if _LOGO is not None:
            ctk.CTkLabel(brand, text="", image=ctk.CTkImage(light_image=_LOGO, size=(28, 28))).pack(
                side="left")
        names = ctk.CTkFrame(brand, fg_color="transparent")
        names.pack(side="left", padx=(10, 0))
        ctk.CTkLabel(names, text="SENTINEL", font=(T.DISPLAY_FONT, 18, "bold"),
                     text_color=T.TEXT).pack(anchor="w")
        ctk.CTkLabel(names, text=T.SENTINEL_VER, font=(T.MONO_FONT, 10),
                     text_color=T.TEXT_DISABLED).pack(anchor="w")

        self.nav_buttons = {}
        for key, glyph, label in (("files", "shield", "Archivos"), ("quarantine", "alert", "Cuarentena"),
                                  ("reports", "reports", "Informes"), ("settings", "config", "Ajustes")):
            self.nav_buttons[key] = self._nav_item(key, glyph, label, lambda k=key: self.show_view(k))

        ctk.CTkLabel(self.sidebar, text="Todo el análisis ocurre\nen tu equipo.", font=(T.UI_FONT, 11),
                     text_color=T.TEXT_DISABLED, justify="left", anchor="w").pack(
            side="bottom", fill="x", padx=22, pady=18)

        main = ctk.CTkFrame(self, fg_color=T.BG, corner_radius=0)
        main.pack(side="left", fill="both", expand=True)

        # Las vistas viven en un lienzo de tamaño fijo que se reajusta una sola vez
        # cuando el usuario suelta el borde: recalcular todos los widgets en cada paso
        # del arrastre hacía que la ventana fuera a trompicones.
        self._main = main
        self._stage_size = (0, 0)
        self._stage_job = None
        self.stage_frame = tk.Frame(main, bg=T.BG, bd=0, highlightthickness=0)
        self.stage_frame.place(x=0, y=0, width=1, height=1)
        main.bind("<Configure>", self._on_main_resize)

        self.views = {}
        for key, builder in (("files", self._build_files),
                             ("quarantine", self._build_quarantine),
                             ("reports", self._build_reports),
                             ("settings", self._build_settings)):
            self.views[key] = builder(self.stage_frame)

        self.bind("<Control-o>", lambda _e: self.manual())
        self.bind("<Control-f>", lambda _e: (self.show_view("files"), self.search.focus_set()))
        self.bind("<Delete>", lambda _e: self.selected and self.view == "files"
                  and self.focus_get() is not self.search._entry and self._remove_entry(self.selected))
        self.bind("<Up>", lambda _e: self._move_selection(-1))
        self.bind("<Down>", lambda _e: self._move_selection(1))

        self.show_view("files")
        self._refresh_status()
        self.after(GUI_POLL_MS, self._poll)
        self.after(300, self._load_history)
        if self.prefs.get("watch_on_start"):
            self.after(500, self._start_watch)

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

    def _nav_item(self, key, glyph, label, command):
        wrap = ctk.CTkFrame(self.sidebar, fg_color="transparent", height=40)
        wrap.pack(fill="x", padx=10, pady=1)
        wrap.pack_propagate(False)
        bar = ctk.CTkFrame(wrap, fg_color="transparent", width=3, corner_radius=2)
        bar.pack(side="left", fill="y", padx=(0, 6), pady=8)
        btn = ctk.CTkButton(wrap, text=f"  {label}", image=icon(glyph, 16, T.TEXT_SECONDARY),
                            compound="left", anchor="w", height=36, border_spacing=8,
                            fg_color="transparent", hover_color=T.ELEVATED,
                            text_color=T.TEXT_SECONDARY, font=(T.UI_FONT, 14),
                            corner_radius=T.RADIUS_SM, command=command)
        btn.pack(fill="x", side="left", expand=True)
        wrap.bar = bar
        wrap.btn = btn
        wrap.glyph = glyph
        wrap.badge = ctk.CTkLabel(wrap, text="", width=22, height=20, corner_radius=2,
                                  font=(T.UI_FONT, 11, "bold"), text_color=T.ON_PRIMARY,
                                  fg_color=T.PRIMARY)
        wrap.badge.bind("<Button-1>", lambda _e: command())
        return wrap

    def _set_badge(self, key, count, color=T.PRIMARY):
        badge = self.nav_buttons[key].badge
        if count:
            badge.configure(text=str(count), fg_color=color)
            badge.place(relx=1.0, rely=0.5, x=-10, anchor="e")
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
            wrap.btn.configure(image=icon(wrap.glyph, 16, T.PRIMARY if active else T.TEXT_SECONDARY),
                               text_color=T.TEXT if active else T.TEXT_SECONDARY,
                               fg_color=T.ELEVATED if active else "transparent",
                               font=(T.UI_FONT, 14, "bold" if active else "normal"))
        if key == "reports":
            self._refresh_reports()

    # ── vista principal: estado, filtros, lista y veredicto ──
    def _build_files(self, parent):
        frame = ctk.CTkFrame(parent, fg_color=T.BG, corner_radius=0)

        # Barra de estado: la única fuente de «qué está pasando ahora».
        self.status_bar = ctk.CTkFrame(frame, fg_color=T.SURFACE, corner_radius=T.RADIUS_PANEL,
                                       border_width=1, border_color=T.BORDER)
        self.status_bar.pack(fill="x")
        inner = ctk.CTkFrame(self.status_bar, fg_color="transparent")
        inner.pack(fill="x", padx=18, pady=(14, 12))
        self.status_dot = ctk.CTkLabel(inner, text="■", font=(T.UI_FONT, 14),
                                       text_color=T.TEXT_SECONDARY, width=16)
        self.status_dot.pack(side="left", anchor="n", pady=(1, 0))
        txt = ctk.CTkFrame(inner, fg_color="transparent")
        txt.pack(side="left", fill="x", expand=True, padx=(8, 12))
        self.status_title = ctk.CTkLabel(txt, text="", font=(T.DISPLAY_FONT, 20, "bold"),
                                         text_color=T.TEXT, anchor="w")
        self.status_title.pack(anchor="w")
        self.status_sub = ctk.CTkLabel(txt, text="", font=(T.MONO_FONT, 11), text_color=T.TEXT_SECONDARY,
                                       anchor="w", justify="left")
        self.status_sub.pack(anchor="w")
        self.watch_btn = ctk.CTkButton(inner, text="Activar vigilancia", width=170, height=38,
                                       image=icon("play", 13, T.ON_PRIMARY), compound="left",
                                       command=self.toggle, **self._btn("primary"))
        self.watch_btn.pack(side="right")
        self.pick_btn = ctk.CTkButton(inner, text="Analizar archivos…", width=180, height=38,
                                      image=icon("upload", 13, T.TEXT), compound="left",
                                      command=self.manual, **self._btn("secondary"))
        self.pick_btn.pack(side="right", padx=(0, 8))
        self.activity_line = ActivityLine(self.status_bar)
        self.activity_line.pack(fill="x", side="bottom", padx=1, pady=(0, 1))

        # Filtros: sustituyen a las tarjetas de métricas y además sirven para algo.
        bar = ctk.CTkFrame(frame, fg_color="transparent")
        bar.pack(fill="x", pady=(14, 8))
        self.filter_btns = {}
        for key, label, color in _FILTERS:
            col = ctk.CTkFrame(bar, fg_color="transparent", width=1, height=1)
            col.pack(side="left", padx=(0, 4))
            b = ctk.CTkButton(col, text=label.upper(), width=1, height=30, corner_radius=0,
                              border_spacing=10, font=(T.MONO_FONT, 11, "bold"),
                              fg_color="transparent", hover_color=T.SURFACE,
                              text_color=T.TEXT_SECONDARY, command=lambda k=key: self.set_filter(k))
            b.pack()
            b.underline = ctk.CTkFrame(col, fg_color="transparent", width=1, height=2, corner_radius=0)
            b.underline.pack(fill="x")
            b.label, b.color = label.upper(), color
            self.filter_btns[key] = b
        self.search = ctk.CTkEntry(bar, width=240, height=30, corner_radius=0, border_width=1,
                                   border_color=T.BORDER, fg_color=T.BG, text_color=T.TEXT,
                                   placeholder_text="/ buscar archivo   ctrl+f",
                                   placeholder_text_color=T.TEXT_DISABLED, font=(T.MONO_FONT, 11))
        self.search.pack(side="right")
        self.search.bind("<KeyRelease>", self._on_search)
        self.search.bind("<Escape>", lambda _e: (self.search.delete(0, "end"), self._on_search()))

        body = ctk.CTkFrame(frame, fg_color="transparent")
        body.pack(fill="both", expand=True)
        body.grid_columnconfigure(0, weight=5, uniform="body")
        body.grid_columnconfigure(1, weight=6, uniform="body")
        body.grid_rowconfigure(0, weight=1)

        feed = ctk.CTkFrame(body, fg_color=T.SURFACE, corner_radius=0, border_width=1, border_color=T.BORDER)
        feed.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        head = tk.Frame(feed, bg=T.SURFACE, height=30)
        head.pack(fill="x", padx=1, pady=(1, 0))
        for text, side, w in (("HORA", "left", 7), ("ARCHIVO", "left", 0), ("VEREDICTO", "right", 11),
                              ("RIESGO", "right", 12)):
            tk.Label(head, text=text, bg=T.SURFACE, fg=T.TEXT_DISABLED, font=(T.MONO_FONT, 8, "bold"),
                     width=w or None, anchor="w").pack(side=side, padx=(14 if side == "left" else 6, 4), pady=8)
        tk.Frame(feed, bg=T.BORDER, height=1).pack(fill="x", padx=1)
        self.table = ctk.CTkScrollableFrame(feed, fg_color="transparent",
                                            scrollbar_button_color=T.ELEVATED,
                                            scrollbar_button_hover_color=T.BORDER)
        self.table.pack(fill="both", expand=True, padx=1, pady=(0, 1))

        self.empty_box = ctk.CTkFrame(self.table, fg_color="transparent")
        self.empty_box.pack(fill="x", pady=(70, 20))
        self.empty_lbl = ctk.CTkLabel(self.empty_box, text="Aún no hay archivos",
                                      font=(T.DISPLAY_FONT, 20, "bold"), text_color=T.TEXT)
        self.empty_lbl.pack()
        self.empty_sub = ctk.CTkLabel(
            self.empty_box, text="Arrastra archivos aquí, elige uno con el botón,\n"
                                 "o activa la vigilancia y descarga algo.",
            font=T.F_BODY, text_color=T.TEXT_SECONDARY, justify="center")
        self.empty_sub.pack(pady=(6, 14))
        self.empty_btn = ctk.CTkButton(self.empty_box, text="Elegir archivo", width=150, height=34,
                                       command=self.manual, **self._btn("secondary"))
        self.empty_btn.pack()

        self._build_detail(body)
        return frame

    def _build_detail(self, body):
        panel = ctk.CTkFrame(body, fg_color=T.SURFACE, corner_radius=0, border_width=1, border_color=T.BORDER)
        panel.grid(row=0, column=1, sticky="nsew")
        self.detail_panel = panel

        # Sin selección: cómo funciona, en tres pasos y con los tres veredictos.
        idle = ctk.CTkFrame(panel, fg_color="transparent")
        self.detail_idle = idle
        ctk.CTkLabel(idle, text="Cómo funciona", font=(T.DISPLAY_FONT, 22, "bold"),
                     text_color=T.TEXT).pack(anchor="w", pady=(0, 14))
        for n, (head, body_txt) in enumerate((
                ("Llega un archivo", "Cuando algo termina de descargarse, o cuando eliges uno a mano."),
                ("Sentinel lo revisa", "Varios motores locales miran su contenido sin ejecutarlo."),
                ("Te da un veredicto", "Con las pruebas que lo justifican. Pulsa un archivo para verlas.")),
                start=1):
            row = ctk.CTkFrame(idle, fg_color="transparent")
            row.pack(fill="x", pady=5)
            ctk.CTkLabel(row, text=str(n), width=28, height=28, corner_radius=2, fg_color=T.ELEVATED,
                         font=(T.MONO_FONT, 12, "bold"), text_color=T.PRIMARY).pack(side="left", anchor="n")
            col = ctk.CTkFrame(row, fg_color="transparent")
            col.pack(side="left", fill="x", expand=True, padx=(12, 0))
            ctk.CTkLabel(col, text=head, font=(T.UI_FONT, 13, "bold"), text_color=T.TEXT,
                         anchor="w").pack(anchor="w")
            ctk.CTkLabel(col, text=body_txt, font=(T.UI_FONT, 12), text_color=T.TEXT_SECONDARY,
                         anchor="w", justify="left").pack(anchor="w")
        ctk.CTkFrame(idle, fg_color=T.BORDER, height=1).pack(fill="x", pady=(18, 14))
        for estado in ("limpio", "pendiente", "alerta"):
            title, _reason, action = T.VERDICT_TEXT[estado]
            row = ctk.CTkFrame(idle, fg_color="transparent")
            row.pack(fill="x", pady=3)
            ctk.CTkLabel(row, text=f"[ {T.STATE_TEXT[estado]} ]", width=110, anchor="w",
                         font=(T.MONO_FONT, 11, "bold"), text_color=T.STATE_COLORS[estado]).pack(side="left")
            ctk.CTkLabel(row, text=action, font=(T.UI_FONT, 12), text_color=T.TEXT_SECONDARY,
                         anchor="w").pack(side="left", padx=(12, 0))

        # Con selección: veredicto arriba, pruebas debajo, acciones al pie.
        sel = ctk.CTkFrame(panel, fg_color="transparent")
        self.detail_main = sel
        head = ctk.CTkFrame(sel, fg_color="transparent")
        head.pack(fill="x", padx=20, pady=(16, 0))
        self.detail_pill = ctk.CTkLabel(head, text="", font=(T.MONO_FONT, 11, "bold"))
        self.detail_pill.pack(side="left")
        self.detail_name = ctk.CTkLabel(head, text="", font=(T.MONO_FONT, 11),
                                        text_color=T.TEXT_SECONDARY, anchor="w")
        self.detail_name.pack(side="left", padx=(10, 0))

        hero = ctk.CTkFrame(sel, fg_color="transparent", height=1)
        hero.pack(fill="x", padx=20, pady=(10, 0))
        score_col = ctk.CTkFrame(hero, fg_color="transparent", width=1, height=1)
        score_col.pack(side="left", anchor="n")
        self.risk_lbl = ctk.CTkLabel(score_col, text="0", font=(T.DISPLAY_FONT, 64, "bold"),
                                     text_color=T.TEXT, anchor="w", height=70)
        self.risk_lbl.pack(anchor="w")
        ctk.CTkLabel(score_col, text="RIESGO / 100", font=(T.MONO_FONT, 9, "bold"),
                     text_color=T.TEXT_DISABLED, anchor="w").pack(anchor="w")
        ctk.CTkFrame(hero, fg_color=T.BORDER, width=1, height=1).pack(side="left", fill="y", padx=18, pady=6)
        txt = ctk.CTkFrame(hero, fg_color="transparent", height=1)
        txt.pack(side="left", fill="both", expand=True)
        self.detail_verdict = ctk.CTkLabel(txt, text="", font=(T.DISPLAY_FONT, 28, "bold"),
                                           text_color=T.TEXT, anchor="w")
        self.detail_verdict.pack(fill="x", pady=(4, 0))
        self.detail_reason = ctk.CTkLabel(txt, text="", font=T.F_BODY, text_color=T.TEXT_SECONDARY,
                                          anchor="w", justify="left", wraplength=400)
        self.detail_reason.pack(fill="x", pady=(2, 0))
        self.detail_action = ctk.CTkLabel(txt, text="", font=(T.UI_FONT, 13, "bold"), text_color=T.TEXT,
                                          anchor="w", justify="left", wraplength=400)
        self.detail_action.pack(fill="x", pady=(8, 0))
        self.chips = ctk.CTkFrame(sel, fg_color="transparent")
        self.chips.pack(fill="x", padx=20, pady=(12, 0))

        self.risk_bar = RiskBar(sel)
        self.risk_bar.pack(fill="x", padx=20, pady=(14, 0))

        self.detail_file = ctk.CTkLabel(sel, text="", anchor="w", font=T.F_MONO_SM,
                                        text_color=T.TEXT_DISABLED, justify="left", wraplength=520)
        self.detail_file.pack(fill="x", padx=18, pady=(8, 8))

        actions = ctk.CTkFrame(sel, fg_color="transparent")
        actions.pack(side="bottom", fill="x", padx=12, pady=(0, 12))
        self.report_btn = ctk.CTkButton(actions, text="Generar informe", height=34,
                                        command=self.export_report, **T.button_style("secondary"))
        self.report_btn.pack(side="left", expand=True, fill="x", padx=4)
        self.trace_btn = ctk.CTkButton(actions, text="Trazar código", height=34,
                                       command=self.trace_selected, **T.button_style("secondary"))
        self.trace_btn.pack(side="left", expand=True, fill="x", padx=4)
        self.q_btn = ctk.CTkButton(actions, text="Mover a cuarentena", height=34,
                                   command=self.quarantine_selected, **T.button_style("secondary"))
        self.q_btn.pack(side="left", expand=True, fill="x", padx=4)

        self.tabs = TabBar(sel)
        self.tabs.pack(fill="both", expand=True, padx=18, pady=(4, 8))
        why = self.tabs.add("Por qué")
        rev = self.tabs.add("Ingeniería inversa")
        tools = self.tabs.add("Detalles técnicos")
        self.re_box = ctk.CTkTextbox(rev, wrap="word", fg_color=T.SURFACE, font=T.F_MONO_SM,
                                     text_color=T.TEXT, border_width=0, corner_radius=T.RADIUS_SM)
        self.re_box.pack(fill="both", expand=True)
        rtb = self.re_box._textbox
        rtb.tag_config("head", foreground=T.PRIMARY)
        rtb.tag_config("dim", foreground=T.TEXT_SECONDARY)
        rtb.tag_config("bad", foreground=T.DANGER)
        rtb.tag_config("ok", foreground=T.SUCCESS)

        self.why_box = ctk.CTkScrollableFrame(why, fg_color="transparent")
        self.why_box.pack(fill="both", expand=True)

        self.detail_box = ctk.CTkTextbox(tools, wrap="word", fg_color=T.SURFACE, font=T.F_MONO_SM,
                                         text_color=T.TEXT, border_width=0, corner_radius=T.RADIUS_SM)
        self.detail_box.pack(fill="both", expand=True)
        tb = self.detail_box._textbox
        tb.tag_config("dim", foreground=T.TEXT_SECONDARY)
        tb.tag_config("head", foreground=T.PRIMARY)
        for sev, color in T.SEV_COLORS.items():
            tb.tag_config(f"sev_{sev}", foreground=color)

        self._set_detail_mode(False)

    def _set_detail_mode(self, selected):
        if selected:
            self.detail_idle.pack_forget()
            if not self.detail_main.winfo_manager():
                self.detail_main.pack(fill="both", expand=True)
        else:
            self.detail_main.pack_forget()
            self.detail_idle.pack(fill="both", expand=True, padx=28, pady=28)

    def _btn(self, kind, size=13):
        style = dict(T.button_style(kind))
        style["font"] = (T.UI_FONT, size, "bold")
        style["corner_radius"] = T.RADIUS_MD
        return style

    @staticmethod
    def _when(entry):
        ts = entry.get("ts")
        if not ts:
            return entry.get("hora", "")
        if time.strftime("%Y%m%d", time.localtime(ts)) == time.strftime("%Y%m%d"):
            return time.strftime("%H:%M", time.localtime(ts))
        return time.strftime("%d/%m %H:%M", time.localtime(ts))

    # ── estado y filtros ──
    def _schedule_status(self):
        if self._status_job is None:
            self._status_job = self.after(40, self._refresh_status)

    def _refresh_status(self):
        self._status_job = None
        s = self.stats
        vt = any(e.get("estado") == "consultando VT" for e in self.rows.values())
        border = T.BORDER
        if self.busy:
            dot, title = T.INFO, f"Analizando {self.busy_name}…"
            sub = "Los motores están revisando el contenido. Suele tardar uno o dos segundos."
        elif self._flash is not None:
            e = self._flash
            dot = _resolve_color(e.get("estado", ""))
            title = f"{e['archivo'][:48]}  →  {T.VERDICT_TEXT.get(e['estado'], ('',))[0]}"
            sub = "Acaba de analizarse. Lo tienes seleccionado abajo." if self.selected is e \
                else "Acaba de analizarse. Púlsalo en la lista para ver por qué."
            border = dot
        elif s["alerta"]:
            n = s["alerta"]
            dot, border = T.DANGER, T.DANGER
            title = f"{n} archivo{'s' if n != 1 else ''} peligroso{'s' if n != 1 else ''}"
            sub = "No los abras. Usa el filtro «Peligro» para verlos y bórralos."
        elif self.watching:
            dot, title = T.SUCCESS, "Vigilando tu carpeta Descargas"
            sub = f"{WATCH_DIR}  ·  cada archivo nuevo se revisa en cuanto termina de llegar"
        else:
            dot, title = T.TEXT_SECONDARY, "Vigilancia en pausa"
            sub = "Actívala para revisar lo que descargues, o analiza un archivo concreto."
        if vt and not self.busy:
            sub = "Consultando VirusTotal para confirmar el resultado…"
        self.status_dot.configure(text_color=dot)
        self._status_color = dot
        self.status_title.configure(text=title)
        self.status_sub.configure(text=sub)
        self.status_bar.configure(border_color=border)
        self.activity_line.set(self.busy or vt, T.INFO)
        self._breathe(self.watching and not self.busy and self._flash is None and not s["alerta"])

        for key, b in self.filter_btns.items():
            n = s["total"] if key == "todos" else s[key]
            active = key == self.filter
            b.configure(text=f"{b.label} {n:02d}",
                        text_color=(b.color if (b.color and n) else T.TEXT) if active or n
                        else T.TEXT_DISABLED)
            b.underline.configure(fg_color=(b.color or T.TEXT) if active else "transparent")
        self._set_badge("files", s["alerta"] + s["pendiente"], T.DANGER if s["alerta"] else T.PRIMARY)

    def _breathe(self, on):
        """El punto verde respira mientras vigila: se ve que está vivo sin distraer."""
        if not on:
            if self._breath_job is not None:
                self.after_cancel(self._breath_job)
                self._breath_job = None
            return
        if self._breath_job is not None:
            return

        def step():
            p = (time.perf_counter() % 2.4) / 2.4
            t = 0.5 - 0.5 * __import__("math").cos(p * 6.2832)
            self.status_dot.configure(text_color=_mix(T.SUCCESS, T.SURFACE, 0.55 * t))
            self._breath_job = self.after(70, step)

        step()

    def _flash_entry(self, entry):
        self._flash = entry
        if self._flash_job is not None:
            self.after_cancel(self._flash_job)
        self._flash_job = self.after(_FLASH_MS, self._end_flash)
        self._schedule_status()

    def _end_flash(self):
        self._flash = None
        self._flash_job = None
        self._schedule_status()

    def set_filter(self, key):
        self.filter = key
        self._apply_filter()
        self._schedule_status()

    def _visible(self, entry):
        if self.query and self.query not in entry.get("archivo", "").lower():
            return False
        return self.filter == "todos" or entry.get("estado") == self.filter

    def _on_search(self, _e=None):
        q = self.search.get().strip().lower()
        if q != self.query:
            self.query = q
            self._apply_filter()

    def _apply_filter(self):
        entries = [self.rows[k] for k in sorted(self.rows, reverse=True)]
        for e in entries:
            if e.get("card") and e["card"].winfo_exists():
                e["card"].pack_forget()
        shown = 0
        for e in entries:
            if self._visible(e) and e.get("card") and e["card"].winfo_exists():
                e["card"].pack(fill="x", padx=0, pady=(0, 1))
                shown += 1
        self._update_empty(shown)

    def _update_empty(self, shown):
        if shown:
            self.empty_box.pack_forget()
            return
        if self.rows:
            self.empty_lbl.configure(text="Sin resultados")
            self.empty_sub.configure(text=f"Nada coincide con «{self.query}»." if self.query
                                     else "Prueba con otro filtro.")
            self.empty_btn.configure(text="Ver todos", command=self._reset_view)
        else:
            self.empty_lbl.configure(text="Aún no hay archivos")
            self.empty_sub.configure(text="Arrastra archivos aquí, elige uno con el botón,\n"
                                          "o activa la vigilancia y descarga algo.")
            self.empty_btn.configure(text="Elegir archivo", command=self.manual)
        if not self.empty_box.winfo_manager():
            self.empty_box.pack(fill="x", pady=(70, 20))

    def _reset_view(self):
        self.search.delete(0, "end")
        self.query = ""
        self.set_filter("todos")

    def _move_selection(self, step):
        if self.view != "files":
            return
        visible = [self.rows[k] for k in sorted(self.rows, reverse=True) if self._visible(self.rows[k])]
        if not visible:
            return
        if self.selected in visible:
            i = max(0, min(len(visible) - 1, visible.index(self.selected) + step))
        else:
            i = 0
        self._user_picked = True
        self._show_detail(visible[i])

    def _build_reports(self, parent):
        frame = ctk.CTkFrame(parent, fg_color=T.BG, corner_radius=0)
        head = ctk.CTkFrame(frame, fg_color="transparent")
        head.pack(fill="x", pady=(0, 12))
        col = ctk.CTkFrame(head, fg_color="transparent")
        col.pack(side="left")
        ctk.CTkLabel(col, text="Informes", font=(T.DISPLAY_FONT, 26, "bold"), text_color=T.TEXT).pack(anchor="w")
        ctk.CTkLabel(col, text="Evidencia lista para adjuntar o imprimir: veredicto, ingeniería inversa, "
                               "pruebas, MITRE ATT&CK e indicadores.",
                     font=T.F_BODY, text_color=T.TEXT_SECONDARY).pack(anchor="w", pady=(2, 0))
        ctk.CTkButton(head, text="Abrir carpeta", width=130, height=34, command=self._open_reports_dir,
                      **T.button_style("secondary")).pack(side="right", anchor="s")
        ctk.CTkButton(head, text="Borrar todos", width=120, height=34, command=self._clear_reports,
                      **T.button_style("tertiary")).pack(side="right", anchor="s", padx=(0, 8))
        panel = ctk.CTkFrame(frame, fg_color=T.SURFACE, corner_radius=T.RADIUS_PANEL)
        panel.pack(fill="both", expand=True)
        self.reports_box = ctk.CTkScrollableFrame(panel, fg_color="transparent")
        self.reports_box.pack(fill="both", expand=True, padx=8, pady=8)
        self.reports_empty = ctk.CTkLabel(
            self.reports_box,
            text="Aún no hay informes\n\nSelecciona un archivo en Archivos y pulsa «Generar informe».",
            font=(T.UI_FONT, 14), text_color=T.TEXT_SECONDARY, justify="center")
        self.reports_empty.pack(padx=16, pady=70)
        return frame

    def _open_reports_dir(self):
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        if hasattr(os, "startfile"):
            os.startfile(str(REPORTS_DIR))

    def _clear_reports(self):
        files = list(REPORTS_DIR.glob("*.html")) if REPORTS_DIR.exists() else []
        if files and messagebox.askyesno("Borrar todos los informes",
                                         f"Se borrarán {len(files)} informe(s). No se puede deshacer.",
                                         icon="warning", parent=self):
            for f in files:
                f.unlink(missing_ok=True)
            self._refresh_reports()

    def _delete_report(self, path):
        if messagebox.askyesno("Borrar informe", f"¿Borrar {path.name}?", parent=self):
            path.unlink(missing_ok=True)
            self._refresh_reports()

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
        files = sorted(REPORTS_DIR.glob("*.html"), key=lambda p: p.stat().st_mtime, reverse=True) \
            if REPORTS_DIR.exists() else []
        for f in files:
            row = ctk.CTkFrame(self.reports_box, fg_color=T.ELEVATED, corner_radius=T.RADIUS_MD)
            row.pack(fill="x", padx=2, pady=3)
            ctk.CTkLabel(row, text="", image=icon("reports", 16, T.PRIMARY), width=24).pack(
                side="left", padx=(14, 8), pady=12)
            col = ctk.CTkFrame(row, fg_color="transparent")
            col.pack(side="left", fill="x", expand=True)
            name = f.stem.split("_", 2)[-1] if f.stem[:8].isdigit() else f.stem
            ctk.CTkLabel(col, text=name, font=(T.UI_FONT, 13, "bold"), text_color=T.TEXT,
                         anchor="w").pack(anchor="w")
            stamp = time.strftime("%d/%m/%Y %H:%M", time.localtime(f.stat().st_mtime))
            ctk.CTkLabel(col, text=f"{stamp} · {f.stat().st_size / 1024:.1f} KB", font=(T.UI_FONT, 11),
                         text_color=T.TEXT_SECONDARY, anchor="w").pack(anchor="w")
            ctk.CTkButton(row, text="Borrar", width=80, height=30, command=lambda p=f: self._delete_report(p),
                          **T.button_style("tertiary")).pack(side="right", padx=(4, 12))
            ctk.CTkButton(row, text="Abrir", width=90, height=30,
                          command=lambda p=str(f): hasattr(os, "startfile") and os.startfile(p),
                          **T.button_style("primary")).pack(side="right", padx=4)
        self._reports_empty_state(not files)

    def _reports_empty_state(self, show):
        if show:
            self.reports_empty.pack(padx=16, pady=70)
        else:
            self.reports_empty.pack_forget()


    # ── ingeniería inversa en el detalle ──
    def _render_re(self, entry):
        box = self.re_box
        box.delete("1.0", "end")
        re = entry.get("re") or {}
        if not re:
            box.insert("end", "Este resultado es de una versión anterior: vuelve a analizar el archivo\n"
                              "para ver su ingeniería inversa.\n", "dim")
            return
        box.insert("end", "CÓMO SE DESMONTÓ (sin ejecutarlo)\n", "head")
        for i, step in enumerate(re.get("pasos") or [], 1):
            box.insert("end", f"  {i}. {step}\n")
        pe = re.get("pe")
        if pe:
            box.insert("end", "\nESTRUCTURA DEL EJECUTABLE\n", "head")
            box.insert("end", f"  {pe.get('arquitectura') or '?'} · {pe.get('tipo') or ''}"
                              f"{' · .NET' if pe.get('dotnet') else ''} · {pe.get('imports') or 0} funciones importadas\n")
            box.insert("end", f"  firma: {pe.get('firma') or 'sin firma'}\n", "dim")
            for sec in pe.get("secciones") or []:
                box.insert("end", f"  sección {sec}\n", "dim")
            if pe.get("entrada"):
                box.insert("end", "\nPUNTO DE ENTRADA (desensamblado)\n", "head")
                for ins in pe["entrada"]:
                    box.insert("end", f"  {ins}\n")
                if pe.get("entrada_nota"):
                    box.insert("end", f"  ⚠ {pe['entrada_nota']}\n", "bad")
        if re.get("capacidades"):
            box.insert("end", "\nCAPACIDADES DEDUCIDAS DE LAS CADENAS\n", "head")
            for c in re["capacidades"]:
                box.insert("end", f"  • {c}\n", "bad")
        if re.get("capa"):
            box.insert("end", f"\nQUÉ SABE HACER EL PROGRAMA (capa · {len(re['capa'])})\n", "head")
            for c in re["capa"]:
                box.insert("end", f"  • {c}\n")
        elif re.get("capa_omitido"):
            box.insert("end", f"\n  desensamblado completo omitido: {re['capa_omitido']}\n", "dim")
        for t in re.get("tallados") or []:
            box.insert("end", f"\nEJECUTABLE OCULTO EN 0x{t.get('offset', 0):x}\n", "bad")
            box.insert("end", f"  extraído ({t.get('origen')}) · {t.get('bytes', 0):,} bytes\n")
            for c in t.get("capacidades") or []:
                box.insert("end", f"  • {c}\n")
        if not (re.get("capacidades") or re.get("capa") or re.get("tallados")):
            box.insert("end", "\n  Ninguna capacidad peligrosa reconocida.\n", "ok")

    # ── cuarentena ──
    def quarantine_selected(self):
        if self.selected:
            self._isolate(self.selected, ask=True)

    def _isolate(self, entry, ask=True):
        if entry.get("cuarentena"):
            return
        ruta = entry.get("ruta")
        if ask and not messagebox.askyesno(
                "Mover a cuarentena",
                f"Sentinel moverá «{entry['archivo']}» a su cuarentena para que no se abra por error.\n\n"
                "Podrás restaurarlo o eliminarlo desde la sección Cuarentena.", parent=self):
            return
        try:
            quarantine.isolate(ruta, entry.get("estado", ""), entry.get("score", 0),
                               "; ".join(entry.get("razones") or [])[:200])
        except OSError as exc:
            self._tools_note("CUARENTENA · no se pudo mover", f"  {exc}\n")
            return
        entry["cuarentena"] = True
        if entry.get("card") and entry["card"].winfo_exists():
            self._fill_card(entry["card"], entry)
            if self.selected is entry:
                self._paint_card(entry["card"], T.ROW_SELECTED, _resolve_color(entry["estado"]))
        if self.selected is entry:
            self._set_trace_button(entry)
        self._schedule_save()
        self._refresh_quarantine()
        self._set_badge("quarantine", len(quarantine.items()), T.TEXT_DISABLED)

    def _build_quarantine(self, parent):
        frame = ctk.CTkFrame(parent, fg_color=T.BG, corner_radius=0)
        head = ctk.CTkFrame(frame, fg_color="transparent")
        head.pack(fill="x", pady=(0, 12))
        ctk.CTkLabel(head, text="Cuarentena", font=(T.DISPLAY_FONT, 26, "bold"), text_color=T.TEXT).pack(anchor="w")
        ctk.CTkLabel(head, text="Archivos apartados para que no se abran por error. No se ejecutan desde aquí: "
                                "puedes devolverlos a su sitio o eliminarlos para siempre.",
                     font=T.F_BODY, text_color=T.TEXT_SECONDARY, anchor="w").pack(anchor="w", pady=(2, 0))
        panel = ctk.CTkFrame(frame, fg_color=T.SURFACE, corner_radius=T.RADIUS_PANEL)
        panel.pack(fill="both", expand=True)
        self.q_box = ctk.CTkScrollableFrame(panel, fg_color="transparent")
        self.q_box.pack(fill="both", expand=True, padx=8, pady=8)
        self._refresh_quarantine()
        return frame

    def _refresh_quarantine(self):
        if not hasattr(self, "q_box"):
            return
        for w in self.q_box.winfo_children():
            w.destroy()
        items = quarantine.items()
        if not items:
            self._set_badge("quarantine", 0)
            ctk.CTkLabel(self.q_box, text="La cuarentena está vacía", font=(T.UI_FONT, 16, "bold"),
                         text_color=T.TEXT).pack(pady=(70, 6))
            ctk.CTkLabel(self.q_box, text="Selecciona un archivo peligroso y pulsa «Mover a cuarentena»,\n"
                                          "o activa la cuarentena automática en Ajustes.",
                         font=T.F_BODY, text_color=T.TEXT_SECONDARY, justify="center").pack()
            return
        for it in items:
            row = ctk.CTkFrame(self.q_box, fg_color=T.ELEVATED, corner_radius=T.RADIUS_MD)
            row.pack(fill="x", padx=2, pady=3)
            color = _resolve_color(it.get("estado", ""))
            ctk.CTkFrame(row, fg_color=color, width=4, height=1, corner_radius=2).pack(side="left", fill="y",
                                                                              padx=(8, 10), pady=10)
            col = ctk.CTkFrame(row, fg_color="transparent")
            col.pack(side="left", fill="x", expand=True, pady=8)
            ctk.CTkLabel(col, text=it["archivo"], font=(T.UI_FONT, 13, "bold"), text_color=T.TEXT,
                         anchor="w").pack(anchor="w")
            when = time.strftime("%d/%m %H:%M", time.localtime(it.get("ts", 0)))
            sub = f"{when} · desde {it['origen']}"
            if it.get("motivo"):
                sub += f"\n{it['motivo']}"
            ctk.CTkLabel(col, text=sub, font=(T.UI_FONT, 11), text_color=T.TEXT_SECONDARY, anchor="w",
                         justify="left").pack(anchor="w")
            ctk.CTkButton(row, text="Eliminar", width=96, height=30,
                          command=lambda q=it: self._q_delete(q), **T.button_style("destructive")).pack(
                side="right", padx=(4, 12))
            ctk.CTkButton(row, text="Restaurar", width=96, height=30,
                          command=lambda q=it: self._q_restore(q), **T.button_style("secondary")).pack(
                side="right", padx=4)
        self._set_badge("quarantine", len(items), T.TEXT_DISABLED)

    def _q_restore(self, item):
        if not messagebox.askyesno("Restaurar", f"¿Devolver «{item['archivo']}» a\n{item['origen']}?\n\n"
                                   "Solo hazlo si estás seguro de que es de fiar.", parent=self):
            return
        try:
            quarantine.restore(item["id"])
        except (OSError, KeyError) as exc:
            messagebox.showerror("Restaurar", str(exc), parent=self)
        for e in self.rows.values():
            if e.get("ruta") == item["origen"]:
                e["cuarentena"] = False
        self._refresh_quarantine()

    def _q_delete(self, item):
        if not messagebox.askyesno("Eliminar para siempre",
                                   f"«{item['archivo']}» se borrará definitivamente. No se puede deshacer.",
                                   icon="warning", parent=self):
            return
        quarantine.delete(item["id"])
        self._refresh_quarantine()

    # ── ajustes ──
    def _build_settings(self, parent):
        frame = ctk.CTkScrollableFrame(parent, fg_color=T.BG, corner_radius=0)
        ctk.CTkLabel(frame, text="Ajustes", font=(T.DISPLAY_FONT, 26, "bold"), text_color=T.TEXT).pack(
            anchor="w", pady=(0, 12))

        def group(title):
            box = ctk.CTkFrame(frame, fg_color=T.SURFACE, corner_radius=T.RADIUS_PANEL)
            box.pack(fill="x", pady=(0, 12))
            ctk.CTkLabel(box, text=title, font=(T.UI_FONT, 14, "bold"), text_color=T.TEXT).pack(
                anchor="w", padx=18, pady=(14, 4))
            return box

        def toggle(box, key, title, desc):
            row = ctk.CTkFrame(box, fg_color="transparent")
            row.pack(fill="x", padx=18, pady=(4, 10))
            var = ctk.BooleanVar(value=bool(self.prefs.get(key)))
            sw = ctk.CTkSwitch(row, text="", variable=var, width=46, progress_color=T.PRIMARY,
                               button_color=T.TEXT, button_hover_color=T.TEXT,
                               command=lambda: self._set_pref(key, var.get()))
            sw.pack(side="right")
            col = ctk.CTkFrame(row, fg_color="transparent")
            col.pack(side="left", fill="x", expand=True)
            ctk.CTkLabel(col, text=title, font=(T.UI_FONT, 13), text_color=T.TEXT, anchor="w").pack(anchor="w")
            ctk.CTkLabel(col, text=desc, font=(T.UI_FONT, 11), text_color=T.TEXT_SECONDARY, anchor="w",
                         justify="left").pack(anchor="w")

        def info(box, title, value, mono=False):
            row = ctk.CTkFrame(box, fg_color="transparent")
            row.pack(fill="x", padx=18, pady=(2, 10))
            ctk.CTkLabel(row, text=title, font=(T.UI_FONT, 13), text_color=T.TEXT, width=180,
                         anchor="w").pack(side="left")
            lbl = ctk.CTkLabel(row, text=value, font=T.F_MONO_SM if mono else (T.UI_FONT, 12),
                               text_color=T.TEXT_SECONDARY, anchor="w", justify="left")
            lbl.pack(side="left", fill="x", expand=True)
            return lbl

        prot = group("Protección")
        toggle(prot, "watch_on_start", "Vigilar Descargas al abrir Sentinel",
               "Empieza a revisar cada archivo nuevo en cuanto abres la aplicación.")
        toggle(prot, "auto_quarantine", "Cuarentena automática",
               "Los archivos con veredicto «Peligro» se apartan solos, sin preguntar.")
        info(prot, "Carpeta vigilada", str(WATCH_DIR), mono=True)

        online = group("Consulta online")
        vt = self._vt_state()
        info(online, "VirusTotal", "conectado: se consulta solo el hash, nunca se sube el archivo"
             if vt == "disponible" else "sin clave · añade VT_API_KEY al archivo .env para activarlo")

        data = group("Datos")
        row = ctk.CTkFrame(data, fg_color="transparent")
        row.pack(fill="x", padx=18, pady=(4, 14))
        ctk.CTkLabel(row, text="Vaciar la lista de archivos analizados", font=(T.UI_FONT, 13),
                     text_color=T.TEXT, anchor="w").pack(side="left")
        ctk.CTkButton(row, text="Vaciar lista", width=120, height=32, command=self.clear_list,
                      **T.button_style("secondary")).pack(side="right")

        about = group("Acerca de")
        info(about, "Versión", T.SENTINEL_VER)
        info(about, "Análisis", "local y estático: los archivos nunca se ejecutan")
        return frame

    def _set_pref(self, key, value):
        self.prefs[key] = bool(value)
        user_settings.save(self.prefs)

    def clear_list(self):
        if self.rows and not messagebox.askyesno(
                "Vaciar lista", "Se quitarán todos los archivos de la lista. Los archivos en sí no se tocan.",
                parent=self):
            return
        for e in list(self.rows.values()):
            if e.get("card") and e["card"].winfo_exists():
                e["card"].destroy()
        self.rows.clear()
        self.selected = None
        self._user_picked = False
        self.stats = {"total": 0, "alerta": 0, "pendiente": 0, "limpio": 0, "score_sum": 0}
        history.clear()
        self._set_detail_mode(False)
        self._update_empty(0)
        self._flash = None
        self._schedule_status()
        self.show_view("files")

    # ── menú contextual de una fila ──
    def _row_menu(self, event, entry):
        self._on_row_click(entry)
        m = tk.Menu(self, tearoff=0, bg=T.ELEVATED, fg=T.TEXT, activebackground=T.ELEVATED_HOVER,
                    activeforeground=T.TEXT, bd=0, font=(T.UI_FONT, 10))
        m.add_command(label="Generar informe", command=self.export_report)
        m.add_command(label="Volver a analizar", command=lambda: self._enqueue([entry["ruta"]]))
        m.add_command(label="Mostrar en la carpeta", command=lambda: self._reveal_file(entry))
        sha = (entry.get("info") or {}).get("sha256")
        if sha:
            m.add_command(label="Copiar SHA-256", command=lambda: (self.clipboard_clear(),
                                                                  self.clipboard_append(sha)))
        m.add_separator()
        if not entry.get("cuarentena"):
            m.add_command(label="Mover a cuarentena", command=lambda: self._isolate(entry))
        m.add_command(label="Quitar de la lista", command=lambda: self._remove_entry(entry))
        try:
            m.tk_popup(event.x_root, event.y_root)
        finally:
            m.grab_release()

    def _reveal_file(self, entry):
        ruta = entry.get("ruta") or ""
        if sys.platform == "win32" and os.path.exists(ruta):
            import subprocess
            subprocess.Popen(["explorer", "/select,", os.path.normpath(ruta)])
        elif hasattr(os, "startfile"):
            os.startfile(os.path.dirname(ruta) or ".")

    def _remove_entry(self, entry):
        key = entry.get("row")
        if key not in self.rows:
            return
        self.rows.pop(key)
        if entry.get("card") and entry["card"].winfo_exists():
            entry["card"].destroy()
        self._bump_stats(entry, removing=True)
        if self.selected is entry:
            self.selected = None
            self._set_detail_mode(False)
        self._update_empty(sum(1 for e in self.rows.values() if self._visible(e)))

    # ── arrastrar y soltar ──
    def _enable_drop(self):
        if TkinterDnD is None:
            return
        try:
            self.TkdndVersion = TkinterDnD._require(self)
            self.drop_target_register(DND_FILES)
            self.dnd_bind("<<DropEnter>>", self._drop_enter)
            self.dnd_bind("<<DropLeave>>", lambda _e: self._schedule_status())
            self.dnd_bind("<<Drop>>", self._on_drop)
        except Exception:  # noqa: BLE001 - sin tkdnd, se usa el botón
            pass

    def _drop_enter(self, event):
        self.show_view("files")
        self.status_dot.configure(text_color=T.PRIMARY)
        self.status_title.configure(text="Suelta para analizar")
        self.status_sub.configure(text="Cada archivo se revisa en local, sin ejecutarlo.")
        self.status_bar.configure(border_color=T.PRIMARY)
        return event.action

    def _on_drop(self, event):
        paths = []
        for p in self.tk.splitlist(event.data):
            if os.path.isdir(p):
                for root, _dirs, names in os.walk(p):
                    paths.extend(os.path.join(root, n) for n in names)
                    if len(paths) > 200:
                        break
            elif os.path.isfile(p):
                paths.append(p)
        self._enqueue(paths[:200])
        self._schedule_status()
        return event.action

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
        self.watch_btn.configure(text="Pausar", image=icon("pause", 13, T.TEXT), **self._btn("secondary"))
        self._schedule_status()

    def _stop_watch(self):
        if self.watcher:
            self.watcher.stop()
            self.watcher = None
        self.watching = False
        self.monitor_ready = False
        self.watch_btn.configure(text="Activar vigilancia", image=icon("play", 13, T.ON_PRIMARY),
                                 **self._btn("primary"))
        self._schedule_status()

    def _check_watcher(self):
        """Si el hilo de vigilancia muere, la interfaz no puede seguir diciendo «activa»."""
        if self.watching and self.watcher and not self.watcher.is_alive() \
                and time.time() - getattr(self, "_watch_restart", 0) > 5:
            self._watch_restart = time.time()
            self._stop_watch()
            self._start_watch()

    def _poll(self):
        self._check_watcher()
        try:
            while True:
                entry = self.queue.get_nowait()
                self._add_row(entry)
        except queue.Empty:
            pass
        self.after(GUI_POLL_MS, self._poll)

    # ── lista de archivos ──
    def _add_row(self, entry):
        existing = entry.get("row")
        if existing and existing in self.rows and entry.get("update"):
            self._update_row(existing, entry)
            return
        if entry.get("update"):
            return

        row = len(self.rows) and max(self.rows) + 1 or 1
        entry["row"] = row
        entry.setdefault("hora", time.strftime("%H:%M:%S"))
        entry.setdefault("ts", time.time())
        self.rows[row] = entry

        card = tk.Frame(self.table, bg=T.ELEVATED, bd=0, highlightthickness=1,
                        highlightbackground=T.ELEVATED, highlightcolor=T.ELEVATED, height=50)
        card.pack_propagate(False)
        entry["card"] = card
        self._fill_card(card, entry)
        if self._visible(entry):
            newest = next((e["card"] for e in reversed([self.rows[k] for k in sorted(self.rows)])
                           if e is not entry and self._visible(e) and e.get("card")
                           and e["card"].winfo_exists() and e["card"].winfo_manager()), None)
            if newest is not None:
                card.pack(fill="x", padx=0, pady=(0, 1), before=newest)
            else:
                card.pack(fill="x", padx=0, pady=(0, 1))
            self.empty_box.pack_forget()

        self._bump_stats(entry)
        if not self._loading:
            if entry.get("estado") == "alerta" and self.prefs.get("auto_quarantine"):
                self.after(10, lambda e=entry: self._isolate(e, ask=False))
            self._pulse_card(card)
            self._flash_entry(entry)
            # Si el usuario no ha elegido nada, se le enseña lo último que llegó.
            if not self._user_picked and self.view == "files":
                self._show_detail(entry)
        if self.view == "reports":
            self._refresh_reports()
        if len(self.rows) > _MAX_ROWS:
            self._drop_oldest()

    def _paint_card(self, card, bg, border=None):
        card.configure(bg=bg, highlightbackground=border or bg, highlightcolor=border or bg)
        stack = list(card.winfo_children())
        while stack:
            w = stack.pop()
            if getattr(w, "_row_bg", False):
                w.configure(bg=bg)
            stack.extend(w.winfo_children())

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

        bg = T.ELEVATED
        tk.Frame(card, bg=color, width=3, bd=0).pack(side="left", fill="y")
        label(card, text=self._when(entry)[-5:], font=(T.MONO_FONT, 9), fg=T.TEXT_DISABLED, bg=bg,
              width=6, anchor="w").pack(side="left", padx=(11, 4))
        verdict = label(card, text=T.STATE_TEXT.get(estado, estado.upper()), font=(T.MONO_FONT, 9, "bold"),
                        fg=color, bg=bg, width=11, anchor="e")
        verdict.pack(side="right", padx=(4, 14))
        score = int(entry.get("score", 0) or 0)
        meter = tk.Canvas(card, width=74, height=14, bg=bg, bd=0, highlightthickness=0)
        meter._row_bg = True
        meter.create_rectangle(0, 6, 50, 8, fill=T.BORDER, outline="")
        meter.create_rectangle(0, 6, max(2, 50 * score / 100), 8, fill=color, outline="")
        meter.create_text(74, 7, text=f"{score:>3}", fill=T.TEXT_SECONDARY, font=(T.MONO_FONT, 9), anchor="e")
        meter.pack(side="right", padx=4)
        names = tk.Frame(card, bg=bg, bd=0)
        names._row_bg = True
        names.pack(side="left", fill="x", expand=True, padx=(4, 8))
        top = tk.Frame(names, bg=bg, bd=0)
        top._row_bg = True
        top.pack(anchor="w", fill="x", pady=(9, 0))
        name = entry["archivo"] if len(entry["archivo"]) <= 34 else entry["archivo"][:33] + "…"
        label(top, text=name, font=(T.UI_FONT, 10, "bold"), fg=T.TEXT, bg=bg, anchor="w").pack(side="left")
        n = len([f for f in entry.get("findings", []) if confidence(f) != "baja"])
        size = (entry.get("info") or {}).get("size")
        sub = kind_label(entry['archivo'], entry.get('tipo')).lower() + (
            f" · {_size(size)}" if isinstance(size, int) else "") + (f" · {n} ind." if n else "")
        if entry.get("cuarentena"):
            sub += " · en cuarentena"
        label(names, text=sub, font=(T.MONO_FONT, 8), fg=T.TEXT_SECONDARY, bg=bg,
              anchor="w").pack(anchor="w")
        _bind_tree(card, "<Button-1>", lambda _e, e=entry: self._on_row_click(e))
        _bind_tree(card, "<Button-3>", lambda ev, e=entry: self._row_menu(ev, e))
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
                       lambda s=shade: card.winfo_exists() and (self.selected or {}).get("card") is not card and
                       self._paint_card(card, s))

    def _drop_oldest(self):
        oldest = min(self.rows)
        entry = self.rows.pop(oldest)
        card = entry.get("card")
        if card and card.winfo_exists():
            card.destroy()
        if self.selected is entry:
            self.selected = None
            self._set_detail_mode(False)
        self._bump_stats(entry, removing=True)

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
        if old.get("estado") == "consultando VT" and entry.get("estado") != "consultando VT":
            self._flash_entry(entry)
        if self.filter != "todos":
            self._apply_filter()

    def _bump_stats(self, entry, removing=False):
        delta = -1 if removing else 1
        self.stats["total"] += delta
        self.stats["score_sum"] += entry.get("score", 0) * delta
        estado = entry.get("estado", "")
        if estado in ("alerta", "pendiente", "limpio"):
            self.stats[estado] += delta
        self._refresh_stats()

    def _refresh_stats(self):
        self._schedule_status()
        self._schedule_save()

    def _schedule_save(self):
        if self._loading or self._save_job is not None:
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
    def _on_row_click(self, entry):
        self._user_picked = True
        self._show_detail(entry)

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
            self._scroll_into_view(card)
        self._set_detail_mode(True)

        title, reason, action = T.VERDICT_TEXT.get(estado, (estado, "", ""))
        errors = entry.get("errors") or []
        if estado == "pendiente" and errors and not [f for f in entry.get("findings", [])
                                                     if confidence(f) != "baja"]:
            title = "No se pudo revisar del todo"
            reason = errors[0][:140]
            action = "Trátalo como no verificado: ábrelo solo si confías en quien te lo envió."
        score = entry.get("score", 0)
        self.detail_pill.configure(text=f"[ {T.STATE_TEXT.get(estado, estado.upper())} ]", text_color=color)
        name = entry["archivo"]
        size = (entry.get("info") or {}).get("size")
        meta = f"{kind_label(name, entry.get('tipo')).upper()}" + (f" · {_size(size)}" if isinstance(size, int) else "")
        self.detail_name.configure(text=(name if len(name) <= 44 else name[:43] + "…") + f"   {meta}")
        for w in self.chips.winfo_children():
            w.destroy()
        motivos = entry.get("razones") or [] if estado != "limpio" else []
        for m in motivos[:3]:
            row = ctk.CTkFrame(self.chips, fg_color="transparent")
            row.pack(fill="x", pady=1)
            ctk.CTkLabel(row, text="▸", font=(T.MONO_FONT, 11, "bold"), text_color=color, width=14).pack(side="left")
            ctk.CTkLabel(row, text=m, font=(T.MONO_FONT, 11), text_color=T.TEXT, anchor="w").pack(
                side="left", padx=(4, 0))
        if motivos:
            self.chips.pack(fill="x", padx=20, pady=(12, 0), after=self.detail_action.master.master)
        else:
            self.chips.pack_forget()
        self.detail_reason.configure(text=reason)
        self.detail_action.configure(text=f"→ {action}" if action else "")
        self._count_up(score, color)
        self.risk_bar.set(score, color)
        self.detail_file.configure(text=entry.get("ruta", ""))
        self._fade_label(self.detail_verdict, title, color)
        self._set_trace_button(entry)
        self._render_why(entry)
        self.tabs.set("Por qué")

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
        self._render_re(entry)
        if self._flash is not None:
            self._schedule_status()

    def _count_up(self, target, color):
        """La puntuación sube de 0 a su valor: se ve el riesgo «medirse»."""
        job = getattr(self, "_count_job", None)
        if job is not None:
            self.after_cancel(job)
        t0 = time.perf_counter()

        def step():
            t = min(1.0, (time.perf_counter() - t0) / 0.45)
            self.risk_lbl.configure(text=str(round(target * _ease(t))),
                                    text_color=_mix(T.TEXT_SECONDARY, color, _ease(t)))
            self._count_job = self.after(_MOTION_MS, step) if t < 1 else None

        step()

    def _fade_label(self, label, text, color):
        """El veredicto entra fundiéndose desde el fondo: se nota que ha cambiado."""
        label.configure(text=text)
        job = getattr(label, "_fade_job", None)
        if job is not None:
            self.after_cancel(job)
        t0 = time.perf_counter()

        def step():
            t = min(1.0, (time.perf_counter() - t0) * 1000 / T.TRANSITION_MS)
            label.configure(text_color=_mix(T.SURFACE, color, _ease(t)))
            label._fade_job = self.after(_MOTION_MS, step) if t < 1 else None

        step()

    def _scroll_into_view(self, card):
        try:
            canvas = self.table._parent_canvas
            self.update_idletasks()
            total = self.table.winfo_height()
            if total <= 1:
                return
            top, bottom = card.winfo_y(), card.winfo_y() + card.winfo_height()
            view_top, view_bottom = (f * total for f in canvas.yview())
            if top < view_top:
                canvas.yview_moveto(top / total)
            elif bottom > view_bottom:
                canvas.yview_moveto((bottom - (view_bottom - view_top)) / total)
        except Exception:  # noqa: BLE001 - cosmético
            pass

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
            box = ctk.CTkFrame(self.why_box, fg_color=T.BG, corner_radius=2)
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
        card = ctk.CTkFrame(self.why_box, fg_color=T.BG, corner_radius=2)
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
                     fg_color=T.ELEVATED, corner_radius=2).pack(side="right")
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

    def _tools_note(self, title, body):
        self.tabs.set("Detalles técnicos")
        self.detail_box.insert("end", f"\n{title}\n", "head")
        self.detail_box.insert("end", body)
        self.detail_box.see("end")

    def _set_trace_button(self, entry):
        if not entry:
            for b in (self.trace_btn, self.report_btn, self.q_btn):
                b.configure(state="disabled", **T.disabled_button_style("secondary"))
            return
        self.report_btn.configure(state="normal", **T.button_style("secondary"))
        in_q = bool(entry.get("cuarentena"))
        if in_q:
            self.q_btn.configure(text="En cuarentena", state="disabled", **T.disabled_button_style("secondary"))
        elif entry.get("estado") == "alerta":
            self.q_btn.configure(text="Mover a cuarentena", state="normal", **T.button_style("destructive"))
        else:
            self.q_btn.configure(text="Mover a cuarentena", state="normal", **T.button_style("secondary"))
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
        self.report_btn.configure(text="Informe listo ✓")
        self.after(1800, lambda: self.report_btn.configure(text="Generar informe"))
        if hasattr(os, "startfile"):
            try:
                os.startfile(str(path))
            except OSError:
                pass
        if self.view == "reports":
            self._refresh_reports()


    # ── análisis manual en segundo plano ──
    def manual(self):
        paths = filedialog.askopenfilenames(initialdir=str(WATCH_DIR), title="Elige uno o varios archivos")
        if paths:
            self._enqueue(list(paths))

    def _enqueue(self, paths):
        paths = [p for p in paths if p and os.path.isfile(p)]
        if not paths:
            return
        self.show_view("files")
        self.jobs.extend(paths)
        self.job_total += len(paths)
        if not self.busy:
            self._next_job()

    def _next_job(self):
        if not self.jobs:
            self.busy = False
            self.job_total = 0
            self.pick_btn.configure(state="normal", text="Analizar archivos…")
            self._schedule_status()
            return
        path = self.jobs.pop(0)
        self.busy = True
        done = self.job_total - len(self.jobs)
        self.busy_name = Path(path).name + (f"  ({done} de {self.job_total})" if self.job_total > 1 else "")
        self.pick_btn.configure(state="disabled", text="Analizando…")
        self._schedule_status()
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
        entry.update(entry_extras(result))
        self.after(0, lambda: self._manual_done(entry))

    def _manual_done(self, entry):
        # Un archivo ya listado se actualiza en su sitio en vez de duplicarse.
        old = next((e for e in self.rows.values() if e.get("ruta") == entry["ruta"]), None)
        if old is not None:
            self._remove_entry(old)
        self._user_picked = True
        self._add_row(entry)
        self._show_detail(entry)
        self._next_job()


def run():
    app = SentinelApp()
    app.mainloop()


if __name__ == "__main__":
    run()
