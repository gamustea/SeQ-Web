"""
taskqueue/queue.py
──────────────────
RQ-backed task queue with Redis persistence.

TaskQueue replaces SeQueue as the central background task system:
- Persists job state in Redis (survives crashes/restarts)
- Workers run in separate processes (isolated from the API)
- External ID mapping stored in Redis hashes
- Cancellation via Redis keys checked cooperatively by workers
- History stored as Redis sorted set with TTL
"""

from __future__ import annotations

import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable, ClassVar, Dict, List, Optional

import redis as redis_lib
import rq
from rq.job import Job
from rq.registry import StartedJobRegistry

from src.modules.system.logging import SecOpsLogger

import src.modules.system.config_reading as CR

from .task import Task, TaskStatus


class TaskQueue:
    """Singleton task queue backed by RQ + Redis."""

    _instance: ClassVar[Optional[TaskQueue]] = None
    _instance_lock = threading.Lock()

    QUEUE_NAMES = [
        "sentinel.scan",
        "sentinel.report",
        "aegis.generate",
        "iris.analyze",
        "default",
    ]

    def __init__(self) -> None:
        redis_cfg = CR.get_redis_config()
        taskqueue_cfg = CR.get_taskqueue_config()

        redis_kwargs = {
            "host": redis_cfg["host"],
            "port": redis_cfg["port"],
            "db": redis_cfg["db"],
            "password": redis_cfg["password"],
        }
        self._redis = redis_lib.Redis(**redis_kwargs, decode_responses=False)
        self._redis_decoded = redis_lib.Redis(**redis_kwargs, decode_responses=True)
        self._queues: Dict[str, rq.Queue] = {
            name: rq.Queue(name=name, connection=self._redis, default_timeout=600)
            for name in self.QUEUE_NAMES
        }
        self._queue = self._queues["default"]
        self._history_max = int(taskqueue_cfg.get("history_max_items", 200))
        self._history_ttl = int(taskqueue_cfg.get("history_ttl_seconds", 3600))

        self.logger = SecOpsLogger("TaskQueue").get_logger()

        self._external_id_hash = "taskqueue:external_ids"
        self._cancel_prefix = "taskqueue:cancel:"
        self._history_key = "taskqueue:history"

        self._migrate_history_key()

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
        timeout: int = 600,
    ) -> Task:
        queue_name = category if category in self._queues else "default"
        queue = self._queues[queue_name]

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
            self._redis_decoded.hset(self._external_id_hash, external_id, job.id)

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
            try:
                job.cancel()
                job.delete()
            except Exception:
                pass
            self._redis_decoded.delete(self._cancel_prefix + task_id)
            self._remove_external_id_by_job_id(task_id)
            self._add_to_history(task_id, TaskStatus.CANCELLED)
            self.logger.info("Task %s cancelled (was pending)", task_id)
            return True

        if status == "started":
            self._redis_decoded.set(self._cancel_prefix + task_id, "1", ex=3600)
            self.logger.info("Task %s cancel signal sent (is running)", task_id)
            return True

        self.logger.warning("Task %s cannot be cancelled (status=%s)", task_id, status)
        return False

    def cancel_all(self) -> None:
        self.logger.info("TaskQueue cancel_all")

        for queue_name, queue in self._queues.items():
            for job_id in queue.get_job_ids():
                self.cancel(job_id)

            started = StartedJobRegistry(name=queue_name, connection=self._redis)
            for job_id in started.get_job_ids():
                self.logger.info("Sending cancel signal to running job %s", job_id)
                self._redis_decoded.set(self._cancel_prefix + job_id, "1", ex=3600)

    def is_cancelled(self, task_id: str) -> bool:
        return bool(self._redis_decoded.exists(self._cancel_prefix + task_id))

    def clear_cancel_signal(self, task_id: str) -> None:
        self._redis_decoded.delete(self._cancel_prefix + task_id)

    def get_task(self, task_id: str) -> Optional[Task]:
        job = self._try_fetch_job(task_id)
        if job is None:
            return None
        return Task.from_rq_job(job)

    def get_task_by_external_id(
        self, external_id: str, category: Optional[str] = None
    ) -> Optional[Task]:
        job_id = self._redis_decoded.hget(self._external_id_hash, external_id)
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
        for queue_name in self._queues:
            started = StartedJobRegistry(name=queue_name, connection=self._redis)
            all_job_ids.extend(started.get_job_ids())
        tasks = self._jobs_to_tasks(all_job_ids, category)
        return sorted(tasks, key=lambda t: t.get("createdAt") or "")

    def get_pending(self, category: Optional[str] = None) -> List[dict]:
        all_pending_ids = []
        for queue_name, queue in self._queues.items():
            started_ids = set(
                StartedJobRegistry(name=queue_name, connection=self._redis).get_job_ids()
            )
            job_ids = queue.get_job_ids()
            pending_ids = [j for j in job_ids if j not in started_ids]
            all_pending_ids.extend(pending_ids)
        tasks = self._jobs_to_tasks(all_pending_ids, category)
        return sorted(tasks, key=lambda t: t.get("createdAt") or "")

    def get_history(self, category: Optional[str] = None) -> List[dict]:
        items = self._redis_decoded.zrevrange(self._history_key, 0, -1)
        tasks = []
        for task_id in items:
            t = self.get_task(task_id)
            if t is None:
                continue
            data = t.to_dict()
            if category is not None and data.get("category") != category:
                continue
            tasks.append(data)

        return sorted(
            tasks,
            key=lambda t: t.get("finishedAt") or t.get("startedAt") or t.get("createdAt") or "",
            reverse=True,
        )

    def get_status(self) -> dict:
        try:
            running_count = 0
            pending_count = 0
            for queue_name, queue in self._queues.items():
                started = StartedJobRegistry(name=queue_name, connection=self._redis)
                running_count += started.count
                pending_count += queue.count
        except Exception as exc:
            self.logger.warning("Error reading queue status from Redis: %s", exc)
            running_count = 0
            pending_count = 0

        history_count = self._redis_decoded.zcard(self._history_key)

        return {
            "maxWorkers":    CR.get_taskqueue_config().get("max_workers", 4),
            "aliveWorkers":  -1,
            "runningCount":  running_count,
            "pendingCount":  pending_count,
            "historyCount":  history_count,
        }

    def update_progress(self, task_id: str, progress: int) -> None:
        if not (0 <= progress <= 100):
            return
        job = self._try_fetch_job(task_id)
        if job is None:
            return
        job.meta["progress"] = progress
        job.save_meta()

    # =========================================================================
    # REDIS ACCESS
    # =========================================================================

    @property
    def redis(self) -> redis_lib.Redis:
        return self._redis

    # =========================================================================
    # INTERNAL
    # =========================================================================

    def _try_fetch_job(self, task_id: str) -> Optional[Job]:
        try:
            return rq.job.Job.fetch(task_id, connection=self._redis)
        except rq.exceptions.NoSuchJobError:
            self.logger.debug("_try_fetch_job: job %s not found in Redis", task_id)
            return None
        except Exception as exc:
            self.logger.warning("_try_fetch_job: unexpected error for %s: %s", task_id, exc)
            return None

    def _migrate_history_key(self) -> None:
        key_type = self._redis_decoded.type(self._history_key)
        if key_type == "hash":
            self.logger.info("Migrating history key from Hash to Sorted Set")
            self._redis_decoded.delete(self._history_key)
            self._redis_decoded.delete(f"{self._history_key}:status")

    def _jobs_to_tasks(self, job_ids: List[str], category: Optional[str] = None) -> List[dict]:
        tasks = []
        for jid in job_ids:
            job = self._try_fetch_job(jid)
            if job is None:
                continue
            t = Task.from_rq_job(job)
            data = t.to_dict()
            if category is not None and data.get("category") != category:
                continue
            tasks.append(data)
        return tasks

    def _remove_external_id_by_job_id(self, job_id: str) -> None:
        cursor = 0
        while True:
            cursor, items = self._redis_decoded.hscan(self._external_id_hash, cursor=cursor)
            for key, val in items.items():
                if val == job_id:
                    self._redis_decoded.hdel(self._external_id_hash, key)
                    return
            if cursor == 0:
                break

    def _add_to_history(self, task_id: str, status: TaskStatus) -> None:
        score = time.time()
        self._redis_decoded.zadd(self._history_key, {task_id: score})
        self._redis_decoded.hset(f"{self._history_key}:status", task_id, status.value)

        if self._history_ttl > 0:
            self._redis_decoded.expire(self._history_key, self._history_ttl)
            self._redis_decoded.expire(f"{self._history_key}:status", self._history_ttl)

        if self._history_max > 0 and self._redis_decoded.zcard(self._history_key) > self._history_max:
            self._trim_history()

    def _trim_history(self) -> None:
        total = self._redis_decoded.zcard(self._history_key)
        excess = total - self._history_max
        if excess <= 0:
            return

        to_remove = self._redis_decoded.zrange(self._history_key, 0, excess - 1)
        if not to_remove:
            return

        pipe = self._redis_decoded.pipeline()
        for task_id in to_remove:
            pipe.zrem(self._history_key, task_id)
            pipe.hdel(f"{self._history_key}:status", task_id)
        pipe.execute()
