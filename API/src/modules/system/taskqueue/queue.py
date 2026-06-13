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

import logging
import os
import threading
from datetime import datetime, timezone
from typing import Any, Callable, ClassVar, Dict, List, Optional

import redis as redis_lib
import rq
from rq.job import Job
from rq.registry import FinishedJobRegistry, StartedJobRegistry

from src.modules.system.logging import SecOpsLogger

import src.modules.system.config_reading as CR

from .task import Task, TaskStatus


class TaskQueue:
    """Singleton task queue backed by RQ + Redis."""

    _instance: ClassVar[Optional[TaskQueue]] = None
    _instance_lock = threading.Lock()

    def __init__(self) -> None:
        redis_cfg = CR.get_redis_config()
        taskqueue_cfg = CR.get_taskqueue_config()

        self._redis = redis_lib.Redis(
            host=redis_cfg["host"],
            port=redis_cfg["port"],
            db=redis_cfg["db"],
            password=redis_cfg["password"],
            decode_responses=True,
        )
        self._queue = rq.Queue(
            name="default",
            connection=self._redis,
            default_timeout=600,
        )
        self._history_max = int(taskqueue_cfg.get("history_max_items", 200))
        self._history_ttl = int(taskqueue_cfg.get("history_ttl_seconds", 3600))

        self.logger = SecOpsLogger("TaskQueue").get_logger()

        self._pending_namespace = "taskqueue:pending"
        self._running_namespace = "taskqueue:running"
        self._external_id_hash = "taskqueue:external_ids"
        self._cancel_prefix = "taskqueue:cancel:"
        self._history_key = "taskqueue:history"

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
        job = self._queue.enqueue(
            func,
            args=args,
            kwargs=kwargs or {},
            job_id=name or None,
            job_timeout=timeout,
            meta={
                "category": category,
                "external_id": external_id,
                "progress": 0,
            },
        )

        if external_id:
            self._redis.hset(self._external_id_hash, external_id, job.id)

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
            self._redis.delete(self._cancel_prefix + task_id)
            self._remove_external_id_by_job_id(task_id)
            self._add_to_history(task_id, TaskStatus.CANCELLED)
            self.logger.info("Task %s cancelled (was pending)", task_id)
            return True

        if status == "started":
            self._redis.set(self._cancel_prefix + task_id, "1", ex=3600)
            self.logger.info("Task %s cancel signal sent (is running)", task_id)
            return True

        self.logger.warning("Task %s cannot be cancelled (status=%s)", task_id, status)
        return False

    def cancel_all(self) -> None:
        self.logger.info("TaskQueue cancel_all")

        for job_id in self._queue.job_ids:
            self.cancel(job_id)

        started = StartedJobRegistry(name=self._queue.name, connection=self._redis)
        for job_id in started.get_job_ids():
            self.logger.info("Sending cancel signal to running job %s", job_id)
            self._redis.set(self._cancel_prefix + job_id, "1", ex=3600)

    def is_cancelled(self, task_id: str) -> bool:
        return bool(self._redis.exists(self._cancel_prefix + task_id))

    def clear_cancel_signal(self, task_id: str) -> None:
        self._redis.delete(self._cancel_prefix + task_id)

    def get_task(self, task_id: str) -> Optional[Task]:
        job = self._try_fetch_job(task_id)
        if job is None:
            return None
        return Task.from_rq_job(job)

    def get_task_by_external_id(
        self, external_id: str, category: Optional[str] = None
    ) -> Optional[Task]:
        job_id = self._redis.hget(self._external_id_hash, external_id)
        if job_id is None:
            return None
        task = self.get_task(job_id)
        if task is None:
            return None
        if category is not None and task.category != category:
            return None
        return task

    def get_running(self, category: Optional[str] = None) -> List[dict]:
        started = StartedJobRegistry(name=self._queue.name, connection=self._redis)
        jobs = started.get_job_ids()
        tasks = self._jobs_to_tasks(jobs, category)
        return sorted(tasks, key=lambda t: t.get("createdAt") or "")

    def get_pending(self, category: Optional[str] = None) -> List[dict]:
        job_ids = self._queue.get_job_ids()
        started_ids = set(
            StartedJobRegistry(name=self._queue.name, connection=self._redis).get_job_ids()
        )
        pending_ids = [j for j in job_ids if j not in started_ids]
        tasks = self._jobs_to_tasks(pending_ids, category)
        return sorted(tasks, key=lambda t: t.get("createdAt") or "")

    def get_history(self, category: Optional[str] = None) -> List[dict]:
        items = self._redis.hgetall(self._history_key)
        tasks = []
        for task_id, status in items.items():
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
            started = StartedJobRegistry(name=self._queue.name, connection=self._redis)
            running_count = started.count
            pending_count = self._queue.count
        except Exception as exc:
            self.logger.warning("Error reading queue status from Redis: %s", exc)
            running_count = 0
            pending_count = 0

        history_count = self._redis.hlen(self._history_key)

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
        except (rq.exceptions.NoSuchJobError, Exception):
            return None

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
            cursor, items = self._redis.hscan(self._external_id_hash, cursor=cursor)
            for key, val in items.items():
                if val == job_id:
                    self._redis.hdel(self._external_id_hash, key)
                    self._cancel_prefix
                    return
            if cursor == 0:
                break

    def _add_to_history(self, task_id: str, status: TaskStatus) -> None:
        self._redis.hset(self._history_key, task_id, status.value)
        if self._history_max > 0 and self._redis.hlen(self._history_key) > self._history_max:
            self._trim_history()

    def _trim_history(self) -> None:
        all_items = self._redis.hgetall(self._history_key)
        excess = len(all_items) - self._history_max
        if excess <= 0:
            return

        to_remove = list(all_items.keys())[:excess]
        pipe = self._redis.pipeline()
        for task_id in to_remove:
            pipe.hdel(self._history_key, task_id)
        pipe.execute()
