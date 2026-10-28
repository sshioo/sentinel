import html
from datetime import datetime
from pathlib import Path

from config import REPORTS_DIR
from core import iocs as iocs_mod

_SEV_CLASS = {
    "bajo": "sev-info",
    "medio": "sev-warn",
    "alto": "sev-danger",
    "crítico": "sev-critical",
}


def build(entry):
    archivo = entry.get("archivo", "?")
    ruta = entry.get("ruta", "")
    score = entry.get("score", 0)
    estado = entry.get("estado", "?")
    engine = entry.get("engine", "")
    findings = entry.get("findings", [])

    iocs = entry.get("iocs")
    if iocs is None:
        try:
            iocs = iocs_mod.extract_file(ruta) if ruta else []
        except OSError:
            iocs = []

    return _TEMPLATE.format(
        titulo=html.escape(archivo),
        archivo=html.escape(archivo),
        ruta=html.escape(str(ruta)),
        score=score,
        estado=html.escape(estado),
        score_color=_score_color(score, estado),
        engine=html.escape(engine),
        generado=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        findings_html=_findings_html(findings),
        iocs_html=_iocs_html(iocs),
        iocs_resumen=html.escape(_iocs_summary(iocs)),
        meta_html=_meta_html(entry),
        ai_html=_ai_html(entry),
    )


def write(entry):
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    stem = Path(entry.get("archivo", "informe")).stem
    out = REPORTS_DIR / f"{stamp}_{stem}.html"
    out.write_text(build(entry), encoding="utf-8")
    return out


def _score_color(score, estado):
    if estado == "alerta" or score >= 25:
        return "#FF626C"
    if score > 0 or estado == "pendiente":
        return "#E8A33D"
    return "#4CCB91"


def _findings_html(findings):
    if not findings:
        return "<p class='ok'>Sin coincidencias.</p>"
    rows = []
    for f in findings:
        sev = f.get("severidad", "bajo")
        sev_class = _SEV_CLASS.get(sev, "sev-info")
        line = f.get("line", 0)
        line_txt = f"L{line}" if line else "—"
        mitre = f.get("mitre_id", "")
        mitre_name = f.get("mitre_name", "")
        mitre_html = (
            f"<span class='mitre'>{html.escape(mitre)} {html.escape(mitre_name)}</span>"
            if mitre else ""
        )
        rows.append(
            "<tr>"
            f"<td class='mono'>{line_txt}</td>"
            f"<td><span class='sev {sev_class}'>{html.escape(sev)}</span></td>"
            f"<td>{html.escape(f.get('regla', ''))}{mitre_html}"
            f"<span class='mono'> · confianza {html.escape(str(f.get('confianza', 'media')))}</span><br>"
            f"<span class='detalle'>{html.escape(str(f.get('detalle', '')))}</span></td>"
            "</tr>"
        )
    return (
        "<table><thead><tr><th scope='col'>Línea</th><th scope='col'>Severidad</th><th scope='col'>Hallazgo</th></tr></thead>"
        "<tbody>" + "".join(rows) + "</tbody></table>"
    )


def _iocs_html(iocs):
    if not iocs:
        return "<p class='ok'>Sin IOCs extraídos.</p>"
    rows = [
        f"<tr><td class='mono'>{html.escape(i['tipo'])}</td>"
        f"<td class='mono'>{html.escape(str(i['valor']))}</td>"
        f"<td class='mono'>L{i.get('line', 0)}</td></tr>"
        for i in iocs
    ]
    return (
        "<table><thead><tr><th scope='col'>Tipo</th><th scope='col'>Valor</th><th scope='col'>Línea</th></tr></thead>"
        "<tbody>" + "".join(rows) + "</tbody></table>"
    )


def _iocs_summary(iocs):
    if not iocs:
        return "0 IOCs"
    counts = iocs_mod.summarize(iocs)
    return " · ".join(f"{n} {t}" for t, n in sorted(counts.items()))


def _ai_html(entry):
    text = entry.get("ai_text")
    if not text:
        return ""
    meta = entry.get("ai_meta") or {}
    origen = "caché" if meta.get("cached") else "nuevo"
    proveedor = html.escape(f"{meta.get('provider', '')} {meta.get('model', '')}".strip())
    cuerpo = html.escape(text).replace("\n", "<br>")
    return (
        f"<h2>Análisis asistido · IA · {proveedor or 'modelo'} · {origen}</h2>"
        f"<div class='ai'>{cuerpo}</div>"
    )


def _meta_html(entry):
    parts = []
    sha = entry.get("sha256")
    if not sha and isinstance(entry.get("meta"), dict):
        sha = entry["meta"].get("binary", {}).get("sha256")
    if sha:
        parts.append(f"<div class='mono'>SHA256: {html.escape(sha)}</div>")
    events = entry.get("trace_events")
    if events:
        parts.append(f"<div class='mono'>Eventos trazados: {len(events)}</div>")
    return "".join(parts)


_TEMPLATE = """<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sentinel — Informe {titulo}</title>
<style>
  :root {{
    --bg:#0E0F12; --surface:#15171C; --elevated:#1C1F26; --border:#2B2E36;
    --primary:#E8A33D; --text:#F4F1E8; --text-2:#9296A2; --text-3:#7D828F;
    --sans:"Inter","Segoe UI",system-ui,sans-serif;
    --mono:"JetBrains Mono","Cascadia Mono",Consolas,monospace;
  }}
  * {{ box-sizing:border-box; }}
  body {{ font-family:var(--sans); background:var(--bg); color:var(--text);
          margin:0; padding:28px 16px; line-height:1.6; }}
  .card {{ max-width:980px; margin:0 auto; background:var(--surface);
           border:1px solid var(--border); border-radius:12px; overflow:hidden; }}
  .top {{ display:flex; align-items:center; gap:12px; padding:16px 28px;
          border-bottom:1px solid var(--border); background:var(--elevated); }}
  .top .eye {{ width:18px; height:18px; border:2px solid var(--primary); border-radius:50%;
               display:inline-block; position:relative; flex:none; }}
  .top .eye::after {{ content:""; position:absolute; inset:3px; border-radius:50%;
                      background:var(--primary); }}
  .top b {{ font-size:13px; letter-spacing:.08em; }}
  .top small {{ color:var(--text-3); font-family:var(--mono); font-size:10px;
                letter-spacing:.12em; text-transform:uppercase; }}
  .body {{ padding:28px 32px 32px; }}
  h1 {{ font-size:20px; margin:0 0 4px; letter-spacing:-.01em; }}
  h2 {{ font-family:var(--mono); font-size:11px; font-weight:500; letter-spacing:.14em;
        text-transform:uppercase; color:var(--text-2); margin:30px 0 12px;
        padding-bottom:8px; border-bottom:1px solid var(--border); }}
  .ruta {{ color:var(--text-2); font-family:var(--mono); font-size:12px;
           word-break:break-all; }}
  .score {{ display:inline-block; font-family:var(--mono); font-size:30px; font-weight:700;
            padding:8px 16px; border:1px solid currentColor; border-radius:8px;
            margin-right:12px; }}
  .estado {{ font-family:var(--mono); font-size:12px; font-weight:700;
             letter-spacing:.12em; text-transform:uppercase; }}
  .meta {{ color:var(--text-3); font-family:var(--mono); font-size:11px; margin-top:12px; }}
  .meta .mono {{ margin-top:4px; word-break:break-all; }}
  table {{ width:100%; border-collapse:collapse; font-size:13px; }}
  th {{ text-align:left; font-family:var(--mono); font-weight:500; font-size:10px;
        letter-spacing:.1em; text-transform:uppercase; color:var(--text-3);
        padding:8px; border-bottom:1px solid var(--border); }}
  td {{ padding:10px 8px; border-bottom:1px solid var(--border); vertical-align:top; }}
  tr:last-child td {{ border-bottom:0; }}
  .mono {{ font-family:var(--mono); font-size:12px; color:var(--text-2); }}
  .sev {{ font-family:var(--mono); font-weight:500; padding:2px 8px; border-radius:4px;
          font-size:10px; letter-spacing:.06em; text-transform:uppercase; white-space:nowrap; }}
  .sev-info {{ color:#69B9F5; background:#172735; }}
  .sev-warn {{ color:#E8A33D; background:#302719; }}
  .sev-danger {{ color:#FF626C; background:#321B20; }}
  .sev-critical {{ color:#17130D; background:#FF626C; }}
  .mitre {{ color:#69B9F5; font-family:var(--mono); font-size:10px; margin-left:8px;
            letter-spacing:.04em; }}
  .detalle {{ color:var(--text-3); font-family:var(--mono); font-size:12px; }}
  .ai {{ border-left:2px solid var(--primary); background:var(--elevated);
         padding:14px 16px; border-radius:0 8px 8px 0; font-size:13px;
         color:var(--text); line-height:1.75; }}
  .ok {{ color:#4CCB91; font-family:var(--mono); font-size:12px; }}
  footer {{ text-align:center; color:var(--text-3); font-family:var(--mono);
            font-size:10px; letter-spacing:.08em; padding:16px; border-top:1px solid var(--border); }}
</style>
</head>
<body>
  <div class="card">
    <div class="top">
      <span class="eye" aria-hidden="true"></span>
      <b>SENTINEL</b><small>informe de análisis</small>
    </div>
    <div class="body">
      <h1>{archivo}</h1>
      <div class="ruta">{ruta}</div>
      <h2>Veredicto</h2>
      <div class="score" style="color:{score_color}">{score}/100</div>
      <span class="estado" style="color:{score_color}">{estado}</span>
      <div class="meta">motor: {engine} · generado: {generado}{meta_html}</div>
      <h2>Hallazgos</h2>
      {findings_html}
      <h2>Indicadores de compromiso · {iocs_resumen}</h2>
      {iocs_html}
      {ai_html}
    </div>
    <footer>GENERADO POR SENTINEL · CONSOLA DE ANÁLISIS DE MALWARE</footer>
  </div>
</body>
</html>
"""
