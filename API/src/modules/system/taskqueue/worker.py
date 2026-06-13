"""
taskqueue/worker.py
───────────────────
RQ worker entry point with Flask application context pre-loaded.

Usage:
    python -m src.modules.system.taskqueue.worker

The worker creates a Flask app instance, pushes an application context
so that database sessions, config, and all Flask extensions are available
to every executed job. It then listens on the configured Redis queues.

Separate process from the API server: if the API crashes, running
tasks survive; if a task crashes, the API stays healthy.
"""

from __future__ import annotations

import logging
import os
import signal
import sys
import threading
import uuid

logging.getLogger("rq").setLevel(logging.WARNING)
logging.getLogger("rq.scheduler").setLevel(logging.WARNING)

import redis as redis_lib
from rq import Queue, SimpleWorker

import src.modules.system.config_reading as CR

from .queue import TaskQueue

_workers = []
_workers_lock = threading.Lock()


class _ThreadSafeWorker(SimpleWorker):
    """SimpleWorker that skips signal handler installation in non-main threads."""

    def _install_signal_handlers(self):
        pass


def _worker_thread(queues, worker_num):
    from run import create_app
    app = create_app(start_scheduler=False)
    with app.app_context():
        worker_name = f"worker-{worker_num}-{uuid.uuid4().hex[:8]}"
        worker = _ThreadSafeWorker(queues, name=worker_name)
        with _workers_lock:
            _workers.append(worker)
        try:
            worker.work(with_scheduler=False)
        finally:
            with _workers_lock:
                if worker in _workers:
                    _workers.remove(worker)


def _make_redis_connection():
    redis_cfg = CR.get_redis_config()
    return redis_lib.Redis(
        host=redis_cfg["host"],
        port=redis_cfg["port"],
        db=redis_cfg["db"],
        password=redis_cfg["password"] or None,
    )


def _make_queues(connection=None):
    conn = connection or _make_redis_connection()
    return [
        Queue(name, connection=conn)
        for name in TaskQueue.QUEUE_NAMES
    ]


def _stop_workers():
    logging.info("Stopping all workers...")
    with _workers_lock:
        for worker in list(_workers):
            try:
                worker.request_stop(signal.SIGTERM, None)
            except Exception as exc:
                logging.warning("Failed to stop worker %s: %s", worker.name, exc)


def _signal_handler(signum, frame):
    sig_name = signal.Signals(signum).name if hasattr(signal, 'Signals') else str(signum)
    print(f"\n[WORKER] {sig_name} received, forcing shutdown...", flush=True)
    logging.info("%s received, forcing shutdown...", sig_name)
    _stop_workers()
    os._exit(0)


def start_worker() -> None:
    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)
    if hasattr(signal, 'SIGBREAK'):
        signal.signal(signal.SIGBREAK, _signal_handler)
    taskqueue_cfg = CR.get_taskqueue_config()
    max_workers = int(taskqueue_cfg.get("max_workers", 4))

    if max_workers == 1:
        try:
            _worker_thread(_make_queues(), 1)
        except KeyboardInterrupt:
            logging.info("KeyboardInterrupt received")
            _stop_workers()
        return

    threads = []
    for i in range(max_workers):
        conn = _make_redis_connection()
        t = threading.Thread(
            target=_worker_thread,
            args=(_make_queues(conn), i + 1),
            daemon=True,
        )
        t.start()
        threads.append(t)
        logging.info("Worker %d started", i + 1)

    try:
        while any(t.is_alive() for t in threads):
            for t in threads:
                t.join(timeout=0.5)
    except KeyboardInterrupt:
        logging.info("KeyboardInterrupt received, stopping workers...")
        _stop_workers()
        os._exit(0)


if __name__ == "__main__":
    start_worker()
