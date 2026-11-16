"""Informe HTML de un análisis: autocontenido, imprimible y legible sin Sentinel.

Orden pensado para quien lo recibe: veredicto y qué hacer, por qué, qué hace el
archivo según la ingeniería inversa, las pruebas una a una y los datos técnicos.
"""
import html
from datetime import datetime
from pathlib import Path

from config import REPORTS_DIR, VERSION
from core import iocs as iocs_mod
from core.scoring import confidence

_E = html.escape

_STATE = {
    "alerta": ("PELIGRO", "No lo abras", "Encontramos pruebas claras de comportamiento malicioso.",
               "Bórralo o muévelo a la cuarentena. No lo ejecutes.", "#E5484D", "#FDECEC"),
    "pendiente": ("REVISAR", "Revísalo antes de abrirlo",
                  "Hay señales sospechosas, pero ninguna prueba firme de malware.",
                  "Ábrelo solo si confías en quien te lo envió.", "#C27C0E", "#FDF4E3"),
    "limpio": ("SEGURO", "Parece seguro", "No encontramos nada que indique comportamiento malicioso.",
               "Puedes abrirlo con normalidad.", "#1F9D63", "#E7F6EE"),
    "consultando VT": ("CONSULTANDO", "Consulta pendiente", "El análisis local terminó; faltaba VirusTotal.",
                       "Vuelve a generar el informe en unos segundos.", "#2F7FC1", "#E8F2FB"),
}
_CONF = {"alta": ("Prueba fuerte", "c-high"), "media": ("Indicio", "c-mid"), "baja": ("Señal débil", "c-low")}
_SEV_ORDER = {"crítico": 0, "alto": 1, "medio": 2, "bajo": 3}
_CONF_ORDER = {"alta": 0, "media": 1, "baja": 2}


def build(entry):
    estado = entry.get("estado", "pendiente")
    label, title, reason, action, color, tint = _STATE.get(estado, _STATE["pendiente"])
    findings = sorted(entry.get("findings", []),
                      key=lambda f: (_CONF_ORDER.get(confidence(f), 1), _SEV_ORDER.get(f.get("severidad"), 3)))
    iocs = entry.get("iocs")
    if iocs is None:
        try:
            iocs = iocs_mod.extract_file(entry["ruta"]) if entry.get("ruta") else []
        except OSError:
            iocs = []
    score = int(entry.get("score", 0) or 0)
    when = datetime.fromtimestamp(entry["ts"]).strftime("%d/%m/%Y %H:%M") if entry.get("ts") else "—"

    body = [
        f"<header class='top'><div class='brand'>Sentinel</div>"
        f"<div class='meta'>Informe de análisis · v{_E(VERSION)} · generado {datetime.now():%d/%m/%Y %H:%M}</div></header>",
        f"<section class='verdict' style='--c:{color};--t:{tint}'>"
        f"<div class='pill'>{label}</div>"
        f"<h1>{_E(title)}</h1><p class='file'>{_E(entry.get('archivo', '?'))}</p>"
        f"<p>{_E(reason)}</p><p class='action'>→ {_E(action)}</p>"
        f"<div class='risk'><span>Riesgo {score}/100</span><div class='bar'><i style='width:{max(score, 2)}%'></i></div></div>"
        "</section>",
        _reasons(entry, findings),
        _reverse(entry.get("re") or {}),
        _findings(findings),
        _mitre(findings),
        _iocs(iocs),
        _identity(entry, when),
        _errors(entry),
        "<footer>Análisis estático local: el archivo no se ejecutó. Sentinel ayuda a decidir; "
        "no sustituye a un antivirus de producción.</footer>",
    ]
    return _TEMPLATE.format(titulo=_E(entry.get("archivo", "informe")), body="\n".join(b for b in body if b))


def write(entry):
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    stem = Path(entry.get("archivo", "informe")).stem
    out = REPORTS_DIR / f"{stamp}_{stem}.html"
    out.write_text(build(entry), encoding="utf-8")
    return out


def _section(title, inner, sub=""):
    sub = f"<span class='sub'>{_E(sub)}</span>" if sub else ""
    return f"<section><h2>{_E(title)}{sub}</h2>{inner}</section>"


def _reasons(entry, findings):
    reasons = entry.get("razones") or [f.get("regla", "") for f in findings if confidence(f) != "baja"][:3]
    if not reasons:
        return ""
    items = "".join(f"<li>{_E(r)}</li>" for r in reasons)
    return _section("Por qué este veredicto", f"<ol class='reasons'>{items}</ol>")


def _reverse(re):
    parts = []
    if re.get("pasos"):
        parts.append("<ol class='steps'>" + "".join(f"<li>{_E(p)}</li>" for p in re["pasos"]) + "</ol>")
    if re.get("capacidades"):
        parts.append("<h3>Capacidades deducidas de las cadenas</h3><ul class='tags'>"
                     + "".join(f"<li>{_E(c)}</li>" for c in re["capacidades"]) + "</ul>")
    pe = re.get("pe")
    if pe:
        rows = [("Arquitectura", f"{pe.get('arquitectura') or '?'} · {pe.get('tipo') or ''}"
                 + (" · .NET" if pe.get("dotnet") else "")),
                ("Funciones importadas", pe.get("imports")),
                ("Firma digital", pe.get("firma") or "sin firma")]
        parts.append("<h3>Estructura del ejecutable</h3>" + _kv(rows))
        if pe.get("secciones"):
            parts.append("<ul class='tags mono'>" + "".join(f"<li>{_E(s)}</li>" for s in pe["secciones"]) + "</ul>")
        if pe.get("entrada"):
            note = f"<p class='note'>{_E(pe['entrada_nota'])}</p>" if pe.get("entrada_nota") else ""
            parts.append("<h3>Primeras instrucciones (desensamblado del punto de entrada)</h3>"
                         f"<pre>{_E(chr(10).join(pe['entrada']))}</pre>{note}")
    if re.get("capa"):
        parts.append(f"<h3>Qué sabe hacer el programa (capa · {len(re['capa'])} capacidades)</h3>"
                     "<ul class='tags'>" + "".join(f"<li>{_E(c)}</li>" for c in re["capa"]) + "</ul>")
    elif re.get("capa_omitido"):
        parts.append(f"<p class='note'>Desensamblado completo omitido: {_E(re['capa_omitido'])}.</p>")
    for t in re.get("tallados") or []:
        caps = ", ".join(t.get("capacidades") or []) or "sin capacidades reconocidas"
        parts.append(f"<div class='carved'><b>Ejecutable oculto en 0x{t.get('offset', 0):x}</b> "
                     f"({_E(str(t.get('origen')))}, {t.get('bytes', 0):,} bytes) · {_E(caps)}</div>")
    if not parts:
        return ""
    return _section("Ingeniería inversa", "".join(parts), "el archivo se desmonta sin ejecutarlo")


def _findings(findings):
    if not findings:
        return _section("Pruebas", "<p class='ok'>Ningún motor encontró nada que señalar.</p>")
    rows = []
    for f in findings:
        name, cls = _CONF.get(confidence(f), _CONF["media"])
        line = f"línea {f['line']} · " if f.get("line") else ""
        mitre = (f"<span class='mitre'>{_E(f['mitre_id'])} · {_E(f.get('mitre_name') or '')}</span>"
                 if f.get("mitre_id") else "")
        motor = f"<span class='motor'>{_E(f['motor'].replace('_', ' '))}</span>" if f.get("motor") else ""
        att = f"<div class='note'>{_E(f['atenuado'])}</div>" if f.get("atenuado") else ""
        rows.append(
            f"<tr><td><span class='conf {cls}'>{name}</span></td>"
            f"<td><b>{_E(f.get('regla', ''))}</b>{motor}<div class='det'>{line}{_E(str(f.get('detalle', '')))}</div>"
            f"{mitre}{att}</td><td class='sev'>{_E(f.get('severidad', ''))}</td></tr>")
    strong = sum(1 for f in findings if confidence(f) == "alta")
    return _section("Pruebas", "<table><thead><tr><th>Peso</th><th>Hallazgo</th><th>Severidad</th></tr></thead>"
                    f"<tbody>{''.join(rows)}</tbody></table>",
                    f"{len(findings)} hallazgos · {strong} pruebas fuertes")


def _mitre(findings):
    seen = {}
    for f in findings:
        if f.get("mitre_id") and confidence(f) != "baja":
            seen.setdefault(f["mitre_id"], f.get("mitre_name", ""))
    if not seen:
        return ""
    rows = "".join(f"<tr><td class='mono'>{_E(k)}</td><td>{_E(v)}</td></tr>" for k, v in sorted(seen.items()))
    return _section("Técnicas MITRE ATT&CK", f"<table><tbody>{rows}</tbody></table>")


def _iocs(iocs):
    if not iocs:
        return ""
    rows = "".join(f"<tr><td class='mono'>{_E(i['tipo'])}</td><td class='mono'>{_E(str(i['valor']))}</td></tr>"
                   for i in iocs[:200])
    counts = " · ".join(f"{n} {t}" for t, n in sorted(iocs_mod.summarize(iocs).items()))
    return _section("Indicadores de compromiso", f"<table><tbody>{rows}</tbody></table>", counts)


def _identity(entry, when):
    info = entry.get("info") or {}
    size = info.get("size")
    rows = [("Nombre", entry.get("archivo")), ("Ruta", entry.get("ruta")),
            ("Analizado", when), ("Tipo", (entry.get("tipo") or "").lower()),
            ("Tamaño", f"{size:,} bytes" if isinstance(size, int) else None),
            ("Formato real", ", ".join(info.get("magic") or []) or None),
            ("Entropía", info.get("entropy")),
            ("SHA-256", info.get("sha256")), ("MD5", info.get("md5")),
            ("Motores", (entry.get("engine") or "").replace("multi:", "").replace("+", " · ").replace("_", " "))]
    return _section("Identidad del archivo", _kv(rows, mono_keys={"Ruta", "SHA-256", "MD5"}))


def _errors(entry):
    errs = entry.get("errors") or []
    if not errs:
        return ""
    return _section("Avisos del análisis", "<ul>" + "".join(f"<li>{_E(e)}</li>" for e in errs) + "</ul>")


def _kv(rows, mono_keys=()):
    out = "".join(f"<tr><th>{_E(k)}</th><td class='{'mono' if k in mono_keys else ''}'>{_E(str(v))}</td></tr>"
                  for k, v in rows if v not in (None, ""))
    return f"<table class='kv'><tbody>{out}</tbody></table>"


_TEMPLATE = """<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sentinel · {titulo}</title>
<style>
:root {{ --ink:#16181D; --muted:#5E6472; --line:#E3E5EA; --bg:#F6F7F9; }}
* {{ box-sizing:border-box; }}
body {{ margin:0; background:var(--bg); color:var(--ink);
       font:15px/1.55 "Segoe UI", Inter, system-ui, sans-serif; }}
main {{ max-width:880px; margin:32px auto; background:#fff; border:1px solid var(--line);
       border-radius:12px; padding:36px 44px; }}
.top {{ display:flex; justify-content:space-between; align-items:baseline;
        border-bottom:1px solid var(--line); padding-bottom:14px; margin-bottom:24px; }}
.brand {{ font-weight:700; font-size:18px; letter-spacing:.2px; }}
.meta, .sub, .note, .motor {{ color:var(--muted); font-size:12.5px; }}
.verdict {{ background:var(--t); border-left:5px solid var(--c); border-radius:10px; padding:22px 26px; }}
.verdict h1 {{ color:var(--c); margin:8px 0 2px; font-size:30px; }}
.verdict p {{ margin:4px 0; }}
.verdict .file {{ font-weight:600; font-size:16px; word-break:break-all; }}
.verdict .action {{ font-weight:700; }}
.pill {{ display:inline-block; background:var(--c); color:#fff; font-weight:700; font-size:12px;
         padding:3px 10px; border-radius:6px; letter-spacing:.6px; }}
.risk {{ display:flex; align-items:center; gap:14px; margin-top:14px; font:600 13px Consolas, monospace; color:var(--c); }}
.bar {{ flex:1; height:8px; background:#fff; border-radius:4px; overflow:hidden; }}
.bar i {{ display:block; height:100%; background:var(--c); }}
section {{ margin-top:30px; }}
h2 {{ font-size:17px; margin:0 0 10px; display:flex; gap:12px; align-items:baseline; }}
h3 {{ font-size:14px; margin:18px 0 6px; }}
table {{ width:100%; border-collapse:collapse; font-size:14px; }}
th, td {{ text-align:left; vertical-align:top; padding:9px 10px; border-bottom:1px solid var(--line); }}
thead th {{ font-size:12px; color:var(--muted); text-transform:uppercase; letter-spacing:.5px; }}
.kv th {{ width:170px; color:var(--muted); font-weight:500; }}
.mono, pre {{ font-family:Consolas, "Cascadia Mono", monospace; font-size:12.5px; word-break:break-all; }}
pre {{ background:#101215; color:#E8E6DF; padding:14px 16px; border-radius:8px; overflow:auto; }}
.det {{ color:var(--muted); font-family:Consolas, monospace; font-size:12.5px; margin-top:3px; word-break:break-word; }}
.mitre {{ display:inline-block; margin-top:4px; font-size:12px; color:#3B5BA9; }}
.motor {{ margin-left:8px; }}
.conf {{ font-size:11.5px; font-weight:700; padding:3px 8px; border-radius:5px; white-space:nowrap; }}
.c-high {{ background:#FDECEC; color:#C62A30; }} .c-mid {{ background:#FDF4E3; color:#A3670A; }}
.c-low {{ background:#EEF0F3; color:#5E6472; }}
.sev {{ color:var(--muted); font-size:13px; }}
.reasons li, .steps li {{ margin:4px 0; }}
.tags {{ list-style:none; padding:0; display:flex; flex-wrap:wrap; gap:6px; }}
.tags li {{ background:var(--bg); border:1px solid var(--line); border-radius:6px; padding:3px 9px; font-size:13px; }}
.carved {{ background:#FDECEC; border-radius:8px; padding:10px 14px; margin-top:10px; font-size:13.5px; }}
.ok {{ color:#1F9D63; font-weight:600; }}
footer {{ margin-top:36px; padding-top:14px; border-top:1px solid var(--line); color:var(--muted); font-size:12.5px; }}
@media print {{ body {{ background:#fff; }} main {{ border:0; margin:0; padding:0; max-width:none; }}
               section {{ break-inside:avoid; }} }}
</style>
</head>
<body><main>
{body}
</main></body>
</html>
"""
