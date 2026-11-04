import sys
import threading
import time
from collections import OrderedDict
from datetime import datetime
from pathlib import Path

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from config import POLL_INTERVAL_S, STABLE_MAX_RETRIES, STABLE_WINDOW_S, WATCH_DIR
from core.analyzer import analyze
from core.dispatcher import classify

_DONE_LIMIT = 2000
_LOCKED_RETRIES = 150  # ~30 s de archivo bloqueado antes de rendirse


class _Handler(FileSystemEventHandler):
    def __init__(self, out_queue, online=True):
        self.queue = out_queue
        self.online = online
        self.pending = {}
        self.done = OrderedDict()
        self.lock = threading.Lock()

    def on_created(self, event):
        if not event.is_directory:
            self._schedule(event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self._schedule(event.dest_path)

    def on_modified(self, event):
        if not event.is_directory:
            self._schedule(event.src_path)

    def _schedule(self, path):
        with self.lock:
            self.pending.setdefault(path, {"size": -1, "since": time.time(), "empties": 0,
                                           "locked": 0})

    def drain(self):
        """Avanza cada archivo pendiente sin bloquear: ninguno retiene a los demás."""
        with self.lock:
            ready = list(self.pending.items())
        for path, state in ready:
            try:
                self._step(path, state)
            except Exception as exc:  # noqa: BLE001 - un archivo no puede detener la vigilancia
                self._fail(path, exc)

    def _drop(self, path):
        with self.lock:
            self.pending.pop(path, None)

    def _step(self, path, state):
        try:
            stat = Path(path).stat()
        except FileNotFoundError:
            self._drop(path)  # temporal que el navegador renombró o borró
            return
        except OSError:
            state["locked"] += 1
            if state["locked"] > _LOCKED_RETRIES:
                self._drop(path)
            return

        now = time.time()
        if stat.st_size != state["size"]:
            state["size"], state["since"] = stat.st_size, now
            return
        if now - state["since"] < STABLE_WINDOW_S:
            return
        if stat.st_size <= 0:
            state["empties"] += 1
            if state["empties"] <= STABLE_MAX_RETRIES:
                state["since"] = now
                return
        signature = (stat.st_size, stat.st_mtime_ns)
        if self.done.get(path) == signature:
            self._drop(path)  # mismo contenido ya analizado
            return
        self._finalize(path)
        self.done[path] = signature
        while len(self.done) > _DONE_LIMIT:
            self.done.popitem(last=False)

    def _entry(self, path, tipo):
        return {
            "hora": datetime.now().strftime("%H:%M:%S"),
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

    def _fail(self, path, exc):
        self._drop(path)
        entry = self._entry(path, classify(path))
        entry["engine"] = "error"
        entry["errors"] = [f"análisis interrumpido ({type(exc).__name__}): {str(exc)[:120]}"]
        self.queue.put(entry)

    def _finalize(self, path):
        self._drop(path)
        tipo = classify(path)
        if tipo == "IGNORAR":
            return

        entry = self._entry(path, tipo)
        result = analyze(path, online=False)
        entry["estado"] = result["estado"]
        entry["score"] = result.get("score", 0)
        entry["findings"] = result["findings"]
        entry["engine"] = result.get("engine", "")
        if result.get("errors"):
            entry["errors"] = result["errors"]

        self.queue.put(entry)

        if self.online and tipo == "BINARIO":
            self._enqueue_online(path, entry)

    def _enqueue_online(self, path, base_entry):
        from engines import virustotal

        if not virustotal.has_api_key():
            return

        entry = dict(base_entry)
        entry["estado"] = "consultando VT"
        entry["update"] = True
        self.queue.put(entry)

        threading.Thread(
            target=self._run_online,
            args=(path, base_entry),
            daemon=True,
        ).start()

    def _run_online(self, path, base_entry):
        from engines import virustotal

        try:
            result = virustotal.scan(path=path)
        except Exception as exc:  # noqa: BLE001
            result = {"findings": [], "error": str(exc), "engine": "virustotal"}

        update = dict(base_entry)
        update["update"] = True
        findings = base_entry["findings"] + result.get("findings", [])
        update["findings"] = findings
        if result.get("findings"):
            from core.scoring import estado_from_score, weighted_score
            score = weighted_score(findings)
            update["score"] = score
            update["estado"] = estado_from_score(score, findings)
        else:
            update["estado"] = base_entry["estado"]
        if result.get("engine"):
            update["engine"] = (base_entry.get("engine", "") + "+virustotal").strip("+")
        if result.get("error"):
            update["errors"] = list(base_entry.get("errors", [])) + [f"virustotal: {result['error']}"]
        self.queue.put(update)


class Watcher(threading.Thread):
    def __init__(self, out_queue, watch_dir=WATCH_DIR, online=True):
        super().__init__(daemon=True)
        self.queue = out_queue
        self.watch_dir = Path(watch_dir)
        self.handler = _Handler(out_queue, online=online)
        self.observer = Observer()
        self._prepared = False
        self._halt = threading.Event()
        self.last_error = None

    def prepare(self):
        self.watch_dir.mkdir(parents=True, exist_ok=True)
        self.observer.schedule(self.handler, str(self.watch_dir), recursive=True)
        self._prepared = True

    def run(self):
        if not self._prepared:
            self.prepare()
        self.observer.start()
        try:
            while not self._halt.is_set():
                try:
                    self.handler.drain()
                except BaseException as exc:  # noqa: BLE001 - la vigilancia no se apaga sola
                    self.last_error = f"{type(exc).__name__}: {exc}"
                    print(f"[sentinel] error en el vigilante: {self.last_error}", file=sys.stderr)
                self._halt.wait(POLL_INTERVAL_S)
        finally:
            self.observer.stop()
        self.observer.join()

    def stop(self):
        self._halt.set()
        self.observer.stop()
