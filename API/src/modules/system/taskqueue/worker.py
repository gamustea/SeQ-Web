"""
taskqueue/worker.py
───────────────────
RQ worker entry point with Flask application context pre-loaded.

Usage:
    python -m src.modules.system.taskqueue.worker

The worker creates a Flask app instance, pushes an application context
so that database sessions, config, and all Flask extensions are available
to every executed job. It then listens on the configured Redis queues.

Modelo de ejecución: **hilos + RQ SimpleWorker** (sin ``fork``). Es la única
estrategia que funciona de forma idéntica en Windows y Linux: ``fork`` no
existe en Windows y el worker clásico de RQ depende de él. Cada hilo crea su
propia app Flask y empuja un contexto de aplicación. No cambiar a un modelo
basado en ``fork`` sin romper el soporte Windows.

Separate process from the API server: if the API crashes, running
tasks survive; if a task crashes, the API stays healthy.
"""

from __future__ import annotations

import logging
import os
import signal
import threading
import uuid

logging.getLogger("rq").setLevel(logging.WARNING)
logging.getLogger("rq.scheduler").setLevel(logging.WARNING)

from rq import Queue, SimpleWorker

import src.modules.system.config_reading as CR

from .connection import RedisConnectionFactory
from .registry import QueueRegistry

_workers = []
_workers_lock = threading.Lock()


class _ThreadSafeWorker(SimpleWorker):
    """SimpleWorker that skips signal handler installation in non-main threads."""

    def _install_signal_handlers(self):
        pass


def _make_queues(connection=None):
    """Construye las colas a partir del registro. Debe llamarse después de
    ``create_app`` para que los módulos hayan registrado sus categorías."""
    conn = connection or RedisConnectionFactory.raw()
    return [Queue(name, connection=conn) for name in QueueRegistry.names()]


def _worker_thread(worker_num):
    from run import create_app
    # create_app importa todos los módulos (blueprints), lo que dispara el
    # registro de categorías en QueueRegistry antes de construir las colas.
    app = create_app(start_scheduler=False)
    with app.app_context():
        queues = _make_queues()
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


def _install_signal_handlers() -> None:
    """Instala manejadores multiplataforma. ``SIGBREAK`` solo existe en
    Windows; ``SIGINT``/``SIGTERM`` están en ambos. Se usa ``os._exit(0)`` en
    el handler porque los workers corren en hilos daemon y queremos una salida
    inmediata y determinista en cualquier SO."""
    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)
    if hasattr(signal, 'SIGBREAK'):
        signal.signal(signal.SIGBREAK, _signal_handler)


def start_worker() -> None:
    _install_signal_handlers()
    taskqueue_cfg = CR.get_taskqueue_config()
    max_workers = int(taskqueue_cfg.get("max_workers", 4))

    if max_workers == 1:
        try:
            _worker_thread(1)
        except KeyboardInterrupt:
            logging.info("KeyboardInterrupt received")
            _stop_workers()
        return

    threads = []
    for i in range(max_workers):
        t = threading.Thread(
            target=_worker_thread,
            args=(i + 1,),
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
