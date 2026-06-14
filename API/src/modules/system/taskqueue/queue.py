"""
taskqueue/queue.py
──────────────────
Cola de tareas respaldada por RQ + Redis.

``TaskQueue`` es una **fachada** delgada que orquesta colaboradores con una
única responsabilidad cada uno (SRP):

- ``ExternalIdStore``   mapa external_id -> job_id.
- ``CancellationStore`` señales de cancelación cooperativa.
- ``HistoryStore``      historial de tareas terminadas (snapshots).
- ``ProgressStore``     progreso almacenado en ``job.meta``.
- ``QueueRegistry``     categorías/colas registrables por módulo (OCP).
- ``RedisConnectionFactory`` única fuente de conexiones Redis.

Frente a SeQueue (la cola en memoria anterior), persiste el estado en Redis
(sobrevive a reinicios), los workers corren en procesos separados y el
historial recoge tareas completadas, fallidas y canceladas vía callbacks de
RQ.
"""

from __future__ import annotations

import logging
import threading
from datetime import datetime, timezone
from typing import Callable, ClassVar, Dict, List, Optional

import redis as redis_lib
import rq
from rq import Worker
from rq.job import Callback, Job
from rq.registry import StartedJobRegistry

from src.modules.system.logging import SecOpsLogger

import src.modules.system.config_reading as CR

from .connection import RedisConnectionFactory
from .registry import DEFAULT_QUEUE, QueueRegistry
from .stores import (
    CancellationStore,
    ExternalIdStore,
    HistoryStore,
    ProgressStore,
)
from .task import Task, TaskStatus

_DEFAULT_TIMEOUT = 600


# =============================================================================
# CALLBACKS DE RQ (se ejecutan en el worker al terminar el job)
# =============================================================================

def _record_terminal(job: Job, status: TaskStatus, error: Optional[str] = None) -> None:
    """Registra el snapshot de un job terminado en el historial.

    Se ejecuta dentro del worker (con contexto Flask activo), por lo que la
    configuración y Redis están disponibles.
    """
    try:
        tq = TaskQueue.get_instance()
        data = Task.from_rq_job(job).to_dict()
        data["status"] = str(status)
        if error and not data.get("error"):
            data["error"] = error
        if not data.get("finishedAt"):
            data["finishedAt"] = datetime.now(timezone.utc).isoformat()

        tq._history.record(data)
        tq._external.remove_by_job_id(job.id)
    except Exception:  # noqa: BLE001 - un fallo de historial no debe tumbar el job
        logging.getLogger("TaskQueue").warning(
            "No se pudo registrar el historial del job %s",
            getattr(job, "id", "?"), exc_info=True,
        )


def _on_job_success(job, connection, result, *args, **kwargs):  # noqa: ANN001
    _record_terminal(job, TaskStatus.COMPLETED)


def _on_job_failure(job, connection, exc_type, exc_value, traceback, *args, **kwargs):  # noqa: ANN001
    error = None
    if exc_type is not None:
        error = f"{getattr(exc_type, '__name__', exc_type)}: {exc_value}"
    _record_terminal(job, TaskStatus.FAILED, error=error)


# =============================================================================
# FACHADA
# =============================================================================

class TaskQueue:
    """Singleton fachada de la cola de tareas (RQ + Redis)."""

    _instance: ClassVar[Optional[TaskQueue]] = None
    _instance_lock = threading.Lock()

    def __init__(self) -> None:
        taskqueue_cfg = CR.get_taskqueue_config()

        self._redis = RedisConnectionFactory.raw()
        self._decoded = RedisConnectionFactory.decoded()

        self._external = ExternalIdStore(self._decoded)
        self._cancel = CancellationStore(self._decoded)
        self._history = HistoryStore(
            self._decoded,
            int(taskqueue_cfg.get("history_max_items", 200)),
            int(taskqueue_cfg.get("history_ttl_seconds", 3600)),
        )

        self._queue_cache: Dict[str, rq.Queue] = {}
        self.logger = SecOpsLogger("TaskQueue").get_logger()

    # =========================================================================
    # SINGLETON
    # =========================================================================

    @classmethod
    def get_instance(cls) -> TaskQueue:
        with cls._instance_lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    @classmethod
    def _reset_instance(cls) -> None:
        with cls._instance_lock:
            cls._instance = None

    # =========================================================================
    # PUBLIC API
    # =========================================================================

    def submit(
        self,
        func: Callable,
        *,
        name: str = "",
        category: str = "",
        args: tuple = (),
        kwargs: Optional[dict] = None,
        external_id: Optional[str] = None,
        timeout: int = _DEFAULT_TIMEOUT,
    ) -> Task:
        queue = self._queue_for(category)

        job_id = name if name else None
        if job_id:
            existing = self._try_fetch_job(job_id)
            if existing is not None:
                status = existing.get_status(refresh=True)
                if status in ("queued", "scheduled", "started"):
                    self.logger.warning(
                        "Task %s already exists with status %s, cancelling old job",
                        job_id, status,
                    )
                    self.cancel(job_id)
                else:
                    try:
                        existing.delete()
                    except Exception:
                        pass

        try:
            job = queue.enqueue(
                func,
                args=args,
                kwargs=kwargs or {},
                job_id=job_id,
                job_timeout=timeout,
                on_success=Callback(_on_job_success),
                on_failure=Callback(_on_job_failure),
                meta={
                    "category": category,
                    "external_id": external_id,
                    "progress": 0,
                },
            )
        except ValueError as exc:
            self.logger.error("Failed to submit task %s: %s", name, exc)
            raise

        if external_id:
            self._external.set(external_id, job.id)

        self.logger.debug(
            "Task %s submitted [category=%s, external=%s]",
            job.id, category, external_id,
        )
        return Task.from_rq_job(job, category=category, external_id=external_id)

    def cancel(self, task_id: str) -> bool:
        job = self._try_fetch_job(task_id)
        if job is None:
            self.logger.warning("Task %s not found for cancellation", task_id)
            return False

        status = job.get_status(refresh=True)
        if status is None:
            return False

        if status in ("queued", "scheduled"):
            snapshot = Task.from_rq_job(job).to_dict()
            snapshot["status"] = str(TaskStatus.CANCELLED)
            snapshot["finishedAt"] = datetime.now(timezone.utc).isoformat()
            try:
                job.cancel()
                job.delete()
            except Exception:
                pass
            self._cancel.clear(task_id)
            self._external.remove_by_job_id(task_id)
            self._history.record(snapshot)
            self.logger.info("Task %s cancelled (was pending)", task_id)
            return True

        if status == "started":
            self._cancel.signal(task_id)
            self.logger.info("Task %s cancel signal sent (is running)", task_id)
            return True

        self.logger.warning("Task %s cannot be cancelled (status=%s)", task_id, status)
        return False

    def cancel_all(self) -> None:
        self.logger.info("TaskQueue cancel_all")

        for queue_name in QueueRegistry.names():
            queue = self._queue_for(queue_name)
            for job_id in queue.get_job_ids():
                self.cancel(job_id)

            started = StartedJobRegistry(name=queue_name, connection=self._redis)
            for job_id in started.get_job_ids():
                self.logger.info("Sending cancel signal to running job %s", job_id)
                self._cancel.signal(job_id)

    def is_cancelled(self, task_id: str) -> bool:
        return self._cancel.is_cancelled(task_id)

    def clear_cancel_signal(self, task_id: str) -> None:
        self._cancel.clear(task_id)

    def get_task(self, task_id: str) -> Optional[Task]:
        job = self._try_fetch_job(task_id)
        if job is None:
            return None
        return Task.from_rq_job(job)

    def get_task_by_external_id(
        self, external_id: str, category: Optional[str] = None
    ) -> Optional[Task]:
        job_id = self._external.get(external_id)
        if job_id is None:
            self.logger.debug("get_task_by_external_id: no job_id for external_id=%s", external_id)
            return None
        task = self.get_task(job_id)
        if task is None:
            self.logger.debug(
                "get_task_by_external_id: task not found for job_id=%s (external_id=%s)",
                job_id, external_id,
            )
            return None
        if category is not None and task.category != category:
            self.logger.debug(
                "get_task_by_external_id: category mismatch (expected=%s, actual=%s)",
                category, task.category,
            )
            return None
        return task

    def get_running(self, category: Optional[str] = None) -> List[dict]:
        all_job_ids = []
        for queue_name in QueueRegistry.names():
            started = StartedJobRegistry(name=queue_name, connection=self._redis)
            all_job_ids.extend(started.get_job_ids())
        tasks = self._jobs_to_tasks(all_job_ids, category)
        return sorted(tasks, key=lambda t: t.get("createdAt") or "")

    def get_pending(self, category: Optional[str] = None) -> List[dict]:
        all_pending_ids = []
        for queue_name in QueueRegistry.names():
            queue = self._queue_for(queue_name)
            started_ids = set(
                StartedJobRegistry(name=queue_name, connection=self._redis).get_job_ids()
            )
            job_ids = queue.get_job_ids()
            pending_ids = [j for j in job_ids if j not in started_ids]
            all_pending_ids.extend(pending_ids)
        tasks = self._jobs_to_tasks(all_pending_ids, category)
        return sorted(tasks, key=lambda t: t.get("createdAt") or "")

    def get_history(self, category: Optional[str] = None) -> List[dict]:
        tasks = self._history.list(category)
        return sorted(
            tasks,
            key=lambda t: t.get("finishedAt") or t.get("startedAt") or t.get("createdAt") or "",
            reverse=True,
        )

    def get_status(self) -> dict:
        running_count = 0
        pending_count = 0
        try:
            for queue_name in QueueRegistry.names():
                queue = self._queue_for(queue_name)
                started = StartedJobRegistry(name=queue_name, connection=self._redis)
                running_count += started.count
                pending_count += queue.count
        except Exception as exc:
            self.logger.warning("Error reading queue status from Redis: %s", exc)
            running_count = 0
            pending_count = 0

        return {
            "maxWorkers":    CR.get_taskqueue_config().get("max_workers", 4),
            "aliveWorkers":  self._count_alive_workers(),
            "runningCount":  running_count,
            "pendingCount":  pending_count,
            "historyCount":  self._history.count(),
        }

    def update_progress(self, task_id: str, progress: int) -> None:
        if not (0 <= progress <= 100):
            return
        job = self._try_fetch_job(task_id)
        if job is None:
            return
        ProgressStore.write(job, progress)

    # =========================================================================
    # REDIS ACCESS
    # =========================================================================

    @property
    def redis(self) -> redis_lib.Redis:
        return self._redis

    # =========================================================================
    # INTERNAL
    # =========================================================================

    def _queue_for(self, category: str) -> rq.Queue:
        """Resuelve la cola de una categoría (cae a ``default`` si no está
        registrada) y la cachea."""
        name = category if QueueRegistry.is_registered(category) else DEFAULT_QUEUE
        queue = self._queue_cache.get(name)
        if queue is None:
            queue = rq.Queue(name=name, connection=self._redis, default_timeout=_DEFAULT_TIMEOUT)
            self._queue_cache[name] = queue
        return queue

    def _count_alive_workers(self) -> int:
        """Número real de workers vivos registrados en Redis."""
        try:
            return Worker.count(connection=self._redis)
        except Exception as exc:
            self.logger.debug("No se pudo contar workers vivos: %s", exc)
            return -1

    def _try_fetch_job(self, task_id: str) -> Optional[Job]:
        try:
            return rq.job.Job.fetch(task_id, connection=self._redis)
        except rq.exceptions.NoSuchJobError:
            self.logger.debug("_try_fetch_job: job %s not found in Redis", task_id)
            return None
        except Exception as exc:
            self.logger.warning("_try_fetch_job: unexpected error for %s: %s", task_id, exc)
            return None

    def _jobs_to_tasks(self, job_ids: List[str], category: Optional[str] = None) -> List[dict]:
        tasks = []
        for jid in job_ids:
            job = self._try_fetch_job(jid)
            if job is None:
                continue
            data = Task.from_rq_job(job).to_dict()
            if category is not None and data.get("category") != category:
                continue
            tasks.append(data)
        return tasks
