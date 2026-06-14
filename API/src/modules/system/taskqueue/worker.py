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
from .queue import QueueRegistry

_workers = []
_workers_lock = threading.Lock()


class _ThreadSafeWorker(SimpleWorker):
    """SimpleWorker that skips signal handler installation in non-main threads."""

    def _install_signal_handlers(self):
        pass


def _worker_thread(worker_num: int):
    """Hilo de trabajo independiente que escucha y ejecuta jobs de una o más colas.

    **Inicialización** (paso a paso):
        1. create_app(start_scheduler=False) → crea instancia Flask
           - Importa todos los módulos (blueprints, managers)
           - Cada módulo hace QueueRegistry.register("categoría")
        2. app.app_context() → empuja contexto Flask para que DB sessions funcionen
        3. QueueRegistry.names() → obtiene todas las colas registradas
           Ej: ["default", "sentinel.scan", "sentinel.report", "aegis.generate", "iris.analyze"]
        4. Crea RQ Queue para cada nombre (conexión a Redis)
        5. Crea RQ Worker y lo registra en _workers (para poder pararlo después)
        6. worker.work() → loop infinito que:
           - Escucha TODAS las colas en paralelo (FIFO)
           - Cuando hay un job, lo saca
           - Ejecuta func(args, kwargs) en el contexto Flask
           - Registra resultado/error en Redis (callbacks de RQ)
           - Vuelve a esperar

    **Aislamiento**: Cada worker corre en su propio thread con su propia
    app Flask y contexto. Si uno se cuelga, los otros siguen funcionando.

    **Proceso vs Thread**: RQ clásico usa fork() (procesos). Aquí usamos
    threads para funcionar en Windows (fork no existe). Cada thread tiene
    su propia app Flask, por lo que DB sessions no se interfieren.

    **Error handling**: Si el job crashea, RQ lo atrapa, registra el error,
    y el worker sigue escuchando. La tarea no se reintenta automáticamente
    (comportamiento configurable de RQ).
    """
    from run import create_app
    # create_app importa todos los módulos (blueprints), lo que dispara el
    # registro de categorías en QueueRegistry antes de construir las colas.
    app = create_app(start_scheduler=False)
    with app.app_context():
        conn = RedisConnectionFactory.raw()
        queues = [Queue(name, connection=conn) for name in QueueRegistry.names()]
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

def start_worker() -> None:
    """Entry point para iniciar los workers.

    **Responsabilidad**: Arrancar N workers (configurables) como threads,
    cada uno escuchando las colas registradas en QueueRegistry. Manejar
    señales (SIGINT, SIGTERM, SIGBREAK en Windows) para shutdown limpio.

    **Configuración**:
        - max_workers: int (config) → número de threads
        - Si max_workers == 1: single-threaded (simpler debugging)
        - Si max_workers > 1: multi-threaded, cada uno con su contexto Flask

    **Uso**: python -m src.modules.system.taskqueue.worker

    **Flujo**:
        1. Lee config max_workers
        2. Si max_workers == 1: corre _worker_thread(1) bloqueante
        3. Si max_workers > 1: inicia N threads, cada uno en _worker_thread(i)
        4. Instala signal handlers para SIGINT, SIGTERM, SIGBREAK (Windows)
        5. Espera a que los threads terminen (Ctrl+C los mata limpiamente)

    **Shutdown limpio**: _stop_workers() llama request_stop() en cada worker,
    que envía SIGTERM al worker RQ. Los jobs en progreso reciben SIGTERM y
    pueden hacer cleanup si quieren (context managers como job_context limpian
    señales de cancelación automáticamente).

    **Separación API/Workers**: Este proceso es independiente de run.py (API).
    - Si un worker crashea, la API sigue respondiendo
    - Si la API crashea, los workers siguen procesando tareas
    - El estado está en Redis (persiste entre reinicios)
    """

    def _signal_handler(signum, frame):
        sig_name = signal.Signals(signum).name if hasattr(signal, 'Signals') else str(signum)
        print(f"\n[WORKER] {sig_name} received, forcing shutdown...", flush=True)
        logging.info("%s received, forcing shutdown...", sig_name)
        _stop_workers()
        os._exit(0)

    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)
    if hasattr(signal, 'SIGBREAK'):
        signal.signal(signal.SIGBREAK, _signal_handler)

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
