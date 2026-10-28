import os
import queue
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import customtkinter as ctk
from tkinter import filedialog

from config import GUI_POLL_MS, PROJECT_DIR, REPORTS_DIR, WATCH_DIR

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
from ui import theme as T
from ui.scanstage import ScanStage
from ui.widgets import DropZone, ScoreGauge, ShieldPulse, ext_badge

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

_MOTION_MS = 16
_PULSE_STEPS = 10
_MAX_ROWS = 200
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
    VIEW_TITLES = {"monitor": "Inicio", "reports": "Informes", "config": "Motores"}

    def __init__(self):
        super().__init__()
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
        self.view = "monitor"
        self.monitor_ready = False
        self.busy = False
        self.stats = {"total": 0, "alerta": 0, "pendiente": 0, "limpio": 0, "score_sum": 0}

        self.withdraw()
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
        for key, icon, label in (("monitor", "◉", "Inicio"), ("reports", "▤", "Informes"),
                                 ("config", "⚙", "Motores")):
            self.nav_buttons[key] = self._nav_item(icon, label, lambda k=key: self.show_view(k))

        status = ctk.CTkFrame(self.sidebar, fg_color=T.ELEVATED, corner_radius=T.RADIUS_MD)
        status.pack(side="bottom", fill="x", padx=12, pady=14)
        ctk.CTkLabel(status, text="PROTECCIÓN", font=(T.UI_FONT, 10, "bold"),
                     text_color=T.TEXT_SECONDARY).pack(anchor="w", padx=12, pady=(10, 0))
        self.nav_dot = ctk.CTkLabel(status, text="●  desactivada", font=(T.UI_FONT, 13, "bold"),
                                    text_color=T.TEXT_SECONDARY)
        self.nav_dot.pack(anchor="w", padx=12, pady=(2, 10))

        main = ctk.CTkFrame(self, fg_color=T.BG, corner_radius=0)
        main.pack(side="left", fill="both", expand=True)

        self.views = {}
        for key, builder in (("monitor", self._build_monitor),
                             ("reports", self._build_reports),
                             ("config", self._build_config)):
            self.views[key] = builder(main)

        self.show_view("monitor")
        self.after(GUI_POLL_MS, self._poll)

    def _nav_item(self, icon, label, command):
        wrap = ctk.CTkFrame(self.sidebar, fg_color="transparent", height=42)
        wrap.pack(fill="x", padx=10, pady=2)
        wrap.pack_propagate(False)
        bar = ctk.CTkFrame(wrap, fg_color="transparent", width=3, corner_radius=2)
        bar.pack(side="left", fill="y", padx=(0, 8), pady=6)
        btn = ctk.CTkButton(wrap, text=f"{icon}   {label}", anchor="w", height=36, border_spacing=8,
                            fg_color="transparent", hover_color=T.ELEVATED,
                            text_color=T.TEXT_SECONDARY, font=(T.UI_FONT, 14),
                            corner_radius=T.RADIUS_SM, command=command)
        btn.pack(fill="x", side="left", expand=True)
        wrap.bar = bar
        wrap.btn = btn
        return wrap

    def show_view(self, key):
        self.view = key
        for k, frame in self.views.items():
            if k == key:
                frame.pack(fill="both", expand=True, padx=18, pady=16)
            else:
                frame.pack_forget()
        for k, wrap in self.nav_buttons.items():
            active = (k == key)
            wrap.bar.configure(fg_color=T.PRIMARY if active else "transparent")
            wrap.btn.configure(text_color=T.TEXT if active else T.TEXT_SECONDARY,
                               fg_color=T.ELEVATED if active else "transparent",
                               font=(T.UI_FONT, 14, "bold" if active else "normal"))
        if key == "reports":
            self._refresh_reports()

    # ── vista de inicio ──
    def _build_monitor(self, parent):
        frame = ctk.CTkFrame(parent, fg_color=T.BG, corner_radius=0)

        hero = ctk.CTkFrame(frame, fg_color="transparent")
        hero.pack(fill="x")
        hero.grid_columnconfigure(0, weight=5, uniform="hero")
        hero.grid_columnconfigure(1, weight=7, uniform="hero")

        prot = ctk.CTkFrame(hero, fg_color=T.SURFACE, corner_radius=14)
        prot.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        self.shield = ShieldPulse(prot, size=104, bg=T.SURFACE)
        self.shield.pack(side="left", padx=(14, 4), pady=10)
        pt = ctk.CTkFrame(prot, fg_color="transparent")
        pt.pack(side="left", fill="both", expand=True, padx=(4, 18), pady=16)
        self.prot_title = ctk.CTkLabel(pt, text="Protección desactivada", font=(T.UI_FONT, 19, "bold"),
                                       text_color=T.TEXT, anchor="w")
        self.prot_title.pack(anchor="w")
        self.prot_desc = ctk.CTkLabel(
            pt, text="Actívala y Sentinel revisará cada archivo que llegue a tu carpeta Descargas.",
            font=T.F_BODY, text_color=T.TEXT_SECONDARY, anchor="w", justify="left", wraplength=300)
        self.prot_desc.pack(anchor="w", pady=(4, 12))
        self.watch_btn = ctk.CTkButton(pt, text="Activar protección", width=190, height=40,
                                       command=self.toggle, **self._btn("primary", 14))
        self.watch_btn.pack(anchor="w")

        pick = ctk.CTkFrame(hero, fg_color=T.SURFACE, corner_radius=14)
        pick.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
        ctk.CTkLabel(pick, text="ANALIZAR A MANO", font=(T.UI_FONT, 10, "bold"),
                     text_color=T.TEXT_SECONDARY).pack(anchor="w", padx=18, pady=(14, 4))
        self.drop = DropZone(pick, command=self.manual, height=104, bg=T.SURFACE)
        self.drop.pack(fill="x", padx=14, pady=(0, 14))

        strip = ctk.CTkFrame(frame, fg_color="transparent")
        strip.pack(fill="x", pady=(14, 0))
        self.strip_cells = {}
        for i, (key, label, color, bg) in enumerate((
            ("total", "analizados", T.TEXT, T.SURFACE),
            ("alerta", "peligro", T.DANGER, T.DANGER_BG),
            ("pendiente", "revisar", T.WARNING, T.WARNING_BG),
            ("limpio", "seguros", T.SUCCESS, T.SUCCESS_BG),
        )):
            strip.grid_columnconfigure(i, weight=1, uniform="strip")
            cell = ctk.CTkFrame(strip, fg_color=bg, corner_radius=12)
            cell.grid(row=0, column=i, sticky="nsew", padx=(0 if i == 0 else 6, 0))
            val = ctk.CTkLabel(cell, text="0", font=(T.MONO_FONT, 26, "bold"), text_color=color)
            val.pack(side="left", padx=(18, 10), pady=10)
            ctk.CTkLabel(cell, text=label, font=(T.UI_FONT, 13), text_color=T.TEXT_SECONDARY).pack(
                side="left")
            self.strip_cells[key] = val

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

    def _poll(self):
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
        self.rows[row] = entry
        self.empty_box.pack_forget()

        card = ctk.CTkFrame(self.table, fg_color=T.ELEVATED, corner_radius=10, border_width=1,
                            border_color=T.ELEVATED, height=60)
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

    def _fill_card(self, card, entry):
        for w in card.winfo_children():
            w.destroy()
        estado = entry["estado"]
        color = _resolve_color(estado)
        ctk.CTkFrame(card, fg_color=color, width=5, height=1, corner_radius=3).pack(
            side="left", fill="y", padx=(6, 10), pady=10)
        ext, ext_color = ext_badge(entry["archivo"], entry.get("tipo"))
        ctk.CTkLabel(card, text=ext, width=48, height=32, font=(T.MONO_FONT, 11, "bold"),
                     text_color=ext_color, fg_color=T.BG, corner_radius=6).pack(side="left", pady=12)
        names = ctk.CTkFrame(card, fg_color="transparent", height=1)
        names.pack(side="left", fill="x", expand=True, padx=12, pady=4)
        name = entry["archivo"] if len(entry["archivo"]) <= 38 else entry["archivo"][:37] + "…"
        ctk.CTkLabel(names, text=name, font=(T.UI_FONT, 13, "bold"), text_color=T.TEXT,
                     anchor="w", height=22).pack(anchor="w")
        n = len([f for f in entry.get("findings", []) if confidence(f) != "baja"])
        sub = f"{entry.get('hora', '')} · {entry.get('tipo', '').lower()} · " + (
            f"{n} indicio{'s' if n != 1 else ''}" if n else "sin indicios")
        ctk.CTkLabel(names, text=sub, font=(T.UI_FONT, 11), text_color=T.TEXT_SECONDARY,
                     anchor="w", height=18).pack(anchor="w")
        ctk.CTkLabel(card, text=f" {T.STATE_TEXT.get(estado, estado.upper())} · {entry.get('score', 0)} ",
                     font=(T.UI_FONT, 11, "bold"), text_color=color,
                     fg_color=T.STATE_BG.get(estado, T.BG), corner_radius=6, height=26).pack(
            side="right", padx=12)
        _bind_tree(card, "<Button-1>", lambda _e, e=entry: self._show_detail(e))
        _bind_tree(card, "<Enter>", lambda _e, e=entry: self._hover(e, True))
        _bind_tree(card, "<Leave>", lambda _e, e=entry: self._hover(e, False))
        card.configure(cursor="hand2")

    def _hover(self, entry, on):
        card = entry.get("card")
        if not card or not card.winfo_exists() or self.selected is entry:
            return
        card.configure(fg_color=T.ROW_HOVER if on else T.ELEVATED)

    def _pulse_card(self, card):
        for i in range(_PULSE_STEPS, -1, -1):
            shade = _hex_rc(T.ELEVATED, int(22 * i / _PULSE_STEPS))
            self.after((_PULSE_STEPS - i) * _MOTION_MS * 2,
                       lambda s=shade: card.winfo_exists() and self.selected is None and
                       card.configure(fg_color=s))

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
        for key in ("total", "alerta", "pendiente", "limpio"):
            self.strip_cells[key].configure(text=str(self.stats[key]))

    # ── detalle ──
    def _show_detail(self, entry):
        previous = self.selected
        self.selected = entry
        if previous is not None and previous is not entry and previous.get("card") \
                and previous["card"].winfo_exists():
            previous["card"].configure(fg_color=T.ELEVATED, border_color=T.ELEVATED)
        card = entry.get("card")
        estado = entry["estado"]
        color = _resolve_color(estado)
        if card and card.winfo_exists():
            card.configure(fg_color=T.ROW_SELECTED, border_color=color)

        title, reason, action = T.VERDICT_TEXT.get(estado, (estado, "", ""))
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
            body = "  sin llamadas peligrosas observadas\n" if not events else "".join(
                f"  L{ev['line']:<4} {ev['evento']:<16} {ev['args']}\n" for ev in events)
            self._tools_note("TRAZA (intérprete instrumentado; aísla builtins, no el proceso)", body)
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
        tipo = classify(path)
        entry = {
            "hora": time.strftime("%H:%M:%S"),
            "archivo": Path(path).name,
            "ruta": path,
            "tipo": tipo,
            "estado": "pendiente",
            "score": 0,
            "findings": [],
            "engine": "",
            "online": False,
        }
        try:
            if tipo in ("CÓDIGO", "BINARIO"):
                result = analyze(path)
                entry["estado"] = result["estado"]
                entry["score"] = result.get("score", 0)
                entry["findings"] = result["findings"]
                entry["engine"] = result.get("engine", "")
            elif tipo == "IGNORAR":
                entry["estado"] = "limpio"
                entry["engine"] = "omitido (descarga a medias o archivo de Sentinel)"
        except Exception as exc:
            entry["engine"] = f"error: {exc}"
        self.after(0, lambda: self._manual_done(entry))

    def _manual_done(self, entry):
        self.busy = False
        self.drop.set_busy(False)
        if not self.watching:
            self.stage.set_active(False)
        self._add_row(entry)
        self._show_detail(entry)


def run():
    app = SentinelApp()
    app.mainloop()


if __name__ == "__main__":
    run()
