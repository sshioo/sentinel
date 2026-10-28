import queue
import threading
import time
from datetime import datetime
from pathlib import Path

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from config import POLL_INTERVAL_S, STABLE_MAX_RETRIES, STABLE_WINDOW_S, WATCH_DIR
from core.analyzer import analyze
from core.dispatcher import classify


class _Handler(FileSystemEventHandler):
    def __init__(self, out_queue, online=True):
        self.queue = out_queue
        self.online = online
        self.pending = {}
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
            self.pending[path] = self.pending.get(path, 0)

    def drain(self):
        with self.lock:
            ready = list(self.pending.items())
        for path, retries in ready:
            self._emit(path, retries)

    def _emit(self, path, retries):
        status = _stability(path)
        if status == "unstable":
            with self.lock:
                self.pending[path] = retries
            return
        if status == "empty":
            if retries < STABLE_MAX_RETRIES:
                with self.lock:
                    self.pending[path] = retries + 1
                return
            self._finalize(path, retries + 1)
            return
        self._finalize(path, retries)

    def _finalize(self, path, retries):
        with self.lock:
            self.pending.pop(path, None)

        tipo = classify(path)
        if tipo == "IGNORAR":
            return

        entry = {
            "hora": datetime.now().strftime("%H:%M:%S"),
            "archivo": Path(path).name,
            "ruta": path,
            "tipo": tipo,
            "estado": "pendiente",
            "score": 0,
            "findings": [],
            "engine": "",
            "online": False,
        }
        if tipo in ("CÓDIGO", "BINARIO"):
            result = analyze(path, online=False)
            entry["estado"] = result["estado"]
            entry["score"] = result.get("score", 0)
            entry["findings"] = result["findings"]
            entry["engine"] = result.get("engine", "")

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
        except Exception as exc:
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
        self.queue.put(update)


def _stability(path, window=STABLE_WINDOW_S, interval=POLL_INTERVAL_S):
    last = -1.0
    stable_since = None
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            size = Path(path).stat().st_size
        except OSError:
            return "unstable"
        now = time.time()
        if size != last:
            last = size
            stable_since = now
        elif now - stable_since >= window:
            if last <= 0:
                return "empty"
            return "stable"
        time.sleep(interval)
    return "empty" if last <= 0 else "unstable"


def _stable(path, window=STABLE_WINDOW_S, interval=POLL_INTERVAL_S):
    return _stability(path, window, interval) == "stable"


class Watcher(threading.Thread):
    def __init__(self, out_queue, watch_dir=WATCH_DIR, online=True):
        super().__init__(daemon=True)
        self.queue = out_queue
        self.watch_dir = Path(watch_dir)
        self.handler = _Handler(out_queue, online=online)
        self.observer = Observer()
        self._prepared = False
        self._halt = threading.Event()

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
                self.handler.drain()
                self._halt.wait(POLL_INTERVAL_S)
        finally:
            self.observer.stop()
        self.observer.join()

    def stop(self):
        self._halt.set()
        self.observer.stop()
