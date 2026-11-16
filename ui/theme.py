import tkinter.font as tkfont

BG = "#08090B"
SURFACE = "#0E1013"
ELEVATED = "#15181C"
BORDER = "#23272E"
ELEVATED_HOVER = "#1B1F24"
ROW_HOVER = "#13161A"
ROW_SELECTED = "#181C21"

PRIMARY = "#FFB224"
PRIMARY_HOVER = "#FFC457"
PRIMARY_ACTIVE = "#E09A10"
ON_PRIMARY = "#0A0A0A"

TEXT = "#ECEDEE"
TEXT_SECONDARY = "#8A9099"
TEXT_DISABLED = "#565C66"

SUCCESS = "#3DDC84"
SUCCESS_BG = "#0D1F15"
WARNING = "#FFB224"
WARNING_BG = "#261E0E"
DANGER = "#FF4D57"
DANGER_BG = "#2A0F13"
INFO = "#4CC2FF"
INFO_BG = "#0E202D"

RADIUS_SM = 2
RADIUS_MD = 2
RADIUS_PANEL = 0

TRANSITION_MS = 150

from config import VERSION as _VERSION

SENTINEL_VER = f"v{_VERSION}"


def _families():
    try:
        import tkinter as _tk
        root = _tk.Tk()
        root.withdraw()
        fams = set(tkfont.families(root))
        root.destroy()
        return fams
    except Exception:
        return set()


_FAMS = _families()

UI_FONT = "Segoe UI" if "Segoe UI" in _FAMS else ("Inter" if "Inter" in _FAMS else "Segoe UI")
# Bahnschrift (DIN industrial, incluida en Windows 10/11) da carácter a titulares y cifras.
DISPLAY_FONT = "Bahnschrift" if "Bahnschrift" in _FAMS else UI_FONT
MONO_FONT = ("JetBrains Mono" if "JetBrains Mono" in _FAMS
             else "Cascadia Mono" if "Cascadia Mono" in _FAMS
             else "Consolas")

F_TITLE = (UI_FONT, 22, "bold")
F_SECTION = (UI_FONT, 14, "bold")
F_BODY = (UI_FONT, 13)
F_NAV = (UI_FONT, 13)
F_LABEL = (UI_FONT, 10)
F_STAT = (MONO_FONT, 26, "bold")
F_MONO = (MONO_FONT, 12)
F_MONO_SM = (MONO_FONT, 11)
F_BTN = (UI_FONT, 13)
F_BTN_SM = (UI_FONT, 12)

STATE_COLORS = {
    "limpio": SUCCESS,
    "pendiente": WARNING,
    "alerta": DANGER,
    "consultando VT": INFO,
}

STATE_TEXT = {
    "alerta": "PELIGRO",
    "pendiente": "REVISAR",
    "limpio": "SEGURO",
    "consultando VT": "CONSULTANDO",
}

# Veredicto en lenguaje llano: título, qué encontramos y qué hacer.
VERDICT_TEXT = {
    "limpio": ("Parece seguro",
               "No encontramos nada que indique comportamiento malicioso.",
               "Puedes abrirlo con normalidad."),
    "pendiente": ("Revísalo antes de abrirlo",
                  "Hay señales sospechosas, pero ninguna prueba firme de malware.",
                  "Ábrelo solo si confías en quien te lo envió."),
    "alerta": ("No lo abras",
               "Encontramos pruebas claras de comportamiento malicioso.",
               "Bórralo o muévelo fuera de tu equipo. No lo ejecutes."),
    "consultando VT": ("Consultando VirusTotal",
                       "El análisis local terminó; falta la respuesta online.",
                       "Espera unos segundos."),
}

CONFIDENCE_TEXT = {"alta": "prueba fuerte", "media": "indicio", "baja": "señal débil"}
CONFIDENCE_COLORS = {"alta": DANGER, "media": WARNING, "baja": TEXT_SECONDARY}

STATE_BG = {"limpio": SUCCESS_BG, "pendiente": WARNING_BG, "alerta": DANGER_BG,
            "consultando VT": INFO_BG}

SEV_COLORS = {
    "bajo": INFO,
    "medio": WARNING,
    "alto": DANGER,
    "crítico": DANGER,
}


def button_style(kind="secondary"):
    if kind == "primary":
        return dict(fg_color=PRIMARY, hover_color=PRIMARY_HOVER, text_color=ON_PRIMARY,
                    corner_radius=RADIUS_SM, font=F_BTN)
    if kind == "tertiary":
        bg = SURFACE
        return dict(fg_color=bg, hover_color=BORDER, text_color=TEXT_SECONDARY,
                    corner_radius=RADIUS_SM, font=F_BTN)
    if kind == "destructive":
        return dict(fg_color=DANGER, hover_color="#FF6B73", text_color=ON_PRIMARY,
                    corner_radius=RADIUS_SM, font=F_BTN)
    return dict(fg_color=ELEVATED, hover_color=ELEVATED_HOVER, text_color=TEXT,
                border_width=1, border_color=BORDER, corner_radius=RADIUS_SM, font=F_BTN)


def disabled_button_style(kind="secondary"):
    d = dict(button_style(kind))
    d["fg_color"] = ELEVATED if kind != "primary" else PRIMARY_ACTIVE
    d["text_color"] = TEXT_DISABLED
    d["hover_color"] = d["fg_color"]
    return d


def state_badge(estado):
    color = STATE_COLORS.get(estado, TEXT_SECONDARY)
    bgs = {"limpio": SUCCESS_BG, "pendiente": WARNING_BG, "alerta": DANGER_BG,
           "consultando VT": INFO_BG}
    return color, bgs.get(estado, ELEVATED)
