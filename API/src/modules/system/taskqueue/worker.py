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

from rq import Connection, Queue, Worker

import src.modules.system.config_reading as CR


def start_worker() -> None:
    redis_cfg = CR.get_redis_config()
    redis_kwargs = {
        "host": redis_cfg["host"],
        "port": redis_cfg["port"],
        "db": redis_cfg["db"],
    }
    if redis_cfg["password"]:
        redis_kwargs["password"] = redis_cfg["password"]

    queues = [
        Queue("sentinel.scan", connection=redis_kwargs),
        Queue("sentinel.report", connection=redis_kwargs),
        Queue("aegis.generate", connection=redis_kwargs),
        Queue("iris.analyze", connection=redis_kwargs),
        Queue("default", connection=redis_kwargs),
    ]

    from run import create_app
    app = create_app(start_scheduler=False)
    app.app_context().push()

    with Connection(**redis_kwargs):
        worker = Worker(queues, connection=redis_kwargs)
        worker.work(with_scheduler=True)


if __name__ == "__main__":
    start_worker()
