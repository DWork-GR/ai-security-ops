import threading

from app.config import SCAN_WORKER_ENABLED, SCAN_WORKER_POLL_INTERVAL_SEC
from app.database.db import SessionLocal
from app.services.scan_job_service import execute_next_queued_scan_job

_worker_lock = threading.Lock()
_worker_stop_event = threading.Event()
_worker_thread: threading.Thread | None = None


def _worker_loop():
    poll_sec = max(0.5, float(SCAN_WORKER_POLL_INTERVAL_SEC))
    while not _worker_stop_event.is_set():
        try:
            with SessionLocal() as db:
                processed = execute_next_queued_scan_job(db)
            wait_sec = 0.15 if processed else poll_sec
            _worker_stop_event.wait(wait_sec)
        except Exception:
            _worker_stop_event.wait(poll_sec)


def start_scan_worker():
    global _worker_thread
    if not SCAN_WORKER_ENABLED:
        return

    with _worker_lock:
        if _worker_thread and _worker_thread.is_alive():
            return
        _worker_stop_event.clear()
        _worker_thread = threading.Thread(
            target=_worker_loop,
            name="scan-job-worker",
            daemon=True,
        )
        _worker_thread.start()


def stop_scan_worker():
    global _worker_thread
    with _worker_lock:
        _worker_stop_event.set()
        if _worker_thread and _worker_thread.is_alive():
            _worker_thread.join(timeout=2.0)
        _worker_thread = None
