"""
sequeue/queue.py
────────────────
Generic, thread‑safe FIFO task queue with configurable max concurrency.

SeQueue is a singleton that manages background task execution:
- Tasks are submitted wrapped in SeQueueTask instances.
- A fixed pool of worker threads pulls tasks from a FIFO Queue.
- Concurrency is limited by the pool size (read from config).
- Completed / failed / cancelled tasks are kept in a bounded history.
- The domain layer stays decoupled via callbacks (on_complete,
  on_error, on_cancel) and an opaque external_id field.
"""

from __future__ import annotations

import collections
import logging
import os
import queue
import threading
import time
import uuid
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

import src.modules.system.config_reading as CR
from src.modules.system.logging import SecOpsLogger

from .task import SeQueueTask, SeQueueTaskStatus


class SeQueue:

    _instance: Optional[SeQueue] = None
    _instance_lock = threading.Lock()

    def __init__(self, max_workers: Optional[int] = None) -> None:
        cfg = CR.get_sequeue_config()
        self._max_workers = max_workers if max_workers is not None else int(
            cfg.get("max_workers", 4)
        )
        self._history_max = int(cfg.get("history_max_items", 100))
        self._history_ttl = float(cfg.get("history_ttl_seconds", 3600))

        self._queue: queue.Queue[SeQueueTask] = queue.Queue()
        self._pending: Dict[uuid.UUID, SeQueueTask] = {}
        self._running: Dict[uuid.UUID, SeQueueTask] = {}
        self._history: collections.OrderedDict[uuid.UUID, SeQueueTask] = (
            collections.OrderedDict()
        )
        self._external_id_map: Dict[str, uuid.UUID] = {}

        self._lock = threading.RLock()
        self._shutdown_event = threading.Event()
        self._workers: List[threading.Thread] = []

        self.logger = SecOpsLogger("SeQueue").get_logger()

    # =========================================================================
    # SINGLETON
    # =========================================================================

    @classmethod
    def get_instance(cls) -> SeQueue:
        with cls._instance_lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    @classmethod
    def _reset_instance(cls) -> None:
        """Reset the singleton instance (useful for testing)."""
        with cls._instance_lock:
            cls._instance = None

    # =========================================================================
    # LIFECYCLE
    # =========================================================================

    def start(self) -> None:
        self._shutdown_event.clear()

        with self._lock:
            # If already started, check if workers are alive and just return
            alive = [w for w in self._workers if w.is_alive()]
            if alive:
                self.logger.info("SeQueue already started with %d workers", len(alive))
                return
            self._workers.clear()

            for i in range(self._max_workers):
                t = threading.Thread(
                    target=self._worker_loop,
                    daemon=True,
                    name=f"SeQueue-worker-{i}",
                )
                t.start()
                self._workers.append(t)

        self.logger.info("SeQueue started with %d workers", self._max_workers)

    def shutdown(self, timeout: int = 30) -> None:
        self.logger.info("SeQueue shutting down...")

        with self._lock:
            # Cancel pending
            for task in list(self._pending.values()):
                task.status = SeQueueTaskStatus.CANCELLED
                task.finished_at = datetime.now()
                self._add_to_history(task)
            self._pending.clear()

            # Cancel running – call domain cancel callbacks
            for task in list(self._running.values()):
                if task.on_cancel:
                    try:
                        task.on_cancel()
                    except Exception as exc:
                        self.logger.warning(
                            "Error in on_cancel for task %s: %s", task.id, exc
                        )
                task.status = SeQueueTaskStatus.CANCELLED
                task.finished_at = datetime.now()
                self._add_to_history(task)
                if task.id in self._running:
                    del self._running[task.id]

            # Clean external_id_map
            self._external_id_map.clear()

        self._shutdown_event.set()

        # Unblock workers
        for _ in self._workers:
            self._queue.put(None)  # type: ignore[arg-type]

        deadline = time.monotonic() + timeout
        for worker in list(self._workers):
            remaining = max(0.0, deadline - time.monotonic())
            worker.join(timeout=remaining)

        self._workers.clear()
        self.logger.info("SeQueue shut down complete")

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
        on_complete: Optional[Callable[[SeQueueTask], None]] = None,
        on_error: Optional[Callable[[SeQueueTask, Exception], None]] = None,
        on_cancel: Optional[Callable[[], None]] = None,
    ) -> SeQueueTask:

        task = SeQueueTask(
            name=name or f"task-{uuid.uuid4().hex[:8]}",
            category=category,
            external_id=external_id,
            on_complete=on_complete,
            on_error=on_error,
            on_cancel=on_cancel,
        )
        task._callable = func
        task._args = args
        task._kwargs = kwargs or {}

        with self._lock:
            self._pending[task.id] = task
            if external_id is not None:
                self._external_id_map[external_id] = task.id
            self._queue.put(task)

        self.logger.debug(
            "Task %s submitted [category=%s, external=%s]",
            task.id, task.category, task.external_id,
        )
        return task

    def cancel(self, task_id: uuid.UUID) -> bool:
        with self._lock:
            # Check pending first (fast path – just mark cancelled)
            task = self._pending.get(task_id)
            if task is not None:
                task.status = SeQueueTaskStatus.CANCELLED
                task.finished_at = datetime.now()
                self._add_to_history(task)
                self._remove_pending(task)
                self._remove_external_id(task)
                self.logger.info("Task %s cancelled (was pending)", task_id)
                return True

            # Check running
            task = self._running.get(task_id)
            if task is not None:
                if task.on_cancel:
                    try:
                        task.on_cancel()
                    except Exception as exc:
                        self.logger.warning(
                            "Error in on_cancel for task %s: %s", task_id, exc
                        )
                task.status = SeQueueTaskStatus.CANCELLED
                task.finished_at = datetime.now()
                self._add_to_history(task)
                del self._running[task_id]
                self._remove_external_id(task)
                self.logger.info("Task %s cancelled (was running)", task_id)
                return True

        self.logger.warning("Task %s not found for cancellation", task_id)
        return False

    def get_task(self, task_id: uuid.UUID) -> Optional[SeQueueTask]:
        with self._lock:
            return (
                self._pending.get(task_id)
                or self._running.get(task_id)
                or self._history.get(task_id)
            )

    def get_task_by_external_id(
        self, external_id: str, category: Optional[str] = None
    ) -> Optional[SeQueueTask]:
        with self._lock:
            task_id = self._external_id_map.get(external_id)
            if task_id is None:
                return None
            task = (
                self._pending.get(task_id)
                or self._running.get(task_id)
            )
            if task is None:
                return None
            if category is not None and task.category != category:
                return None
            return task

    def get_running(self, category: Optional[str] = None) -> List[SeQueueTask]:
        with self._lock:
            tasks = list(self._running.values())
        if category is not None:
            tasks = [t for t in tasks if t.category == category]
        return sorted(tasks, key=lambda t: t.created_at or datetime.min)

    def get_pending(self, category: Optional[str] = None) -> List[SeQueueTask]:
        with self._lock:
            tasks = list(self._pending.values())
        if category is not None:
            tasks = [t for t in tasks if t.category == category]
        return sorted(tasks, key=lambda t: t.created_at or datetime.min)

    def get_history(self, category: Optional[str] = None) -> List[SeQueueTask]:
        with self._lock:
            tasks = list(self._history.values())
        if category is not None:
            tasks = [t for t in tasks if t.category == category]
        return sorted(
            tasks, key=lambda t: t.finished_at or datetime.min, reverse=True
        )

    def get_status(self) -> dict:
        with self._lock:
            alive = sum(1 for w in self._workers if w.is_alive())
            return {
                "maxWorkers":    self._max_workers,
                "aliveWorkers":  alive,
                "runningCount":  len(self._running),
                "pendingCount":  len(self._pending),
                "historyCount":  len(self._history),
            }

    def resize(self, max_workers: int) -> None:
        if max_workers < 1:
            raise ValueError("max_workers must be >= 1")

        with self._lock:
            old = self._max_workers
            self._max_workers = max_workers

            if max_workers > old:
                for i in range(old, max_workers):
                    t = threading.Thread(
                        target=self._worker_loop,
                        daemon=True,
                        name=f"SeQueue-worker-{i}",
                    )
                    t.start()
                    self._workers.append(t)
                self.logger.info(
                    "SeQueue scaled up: %d → %d workers", old, max_workers
                )

            elif max_workers < old:
                to_remove = old - max_workers
                for _ in range(to_remove):
                    self._queue.put(None)  # type: ignore[arg-type]
                self.logger.info(
                    "SeQueue scaled down: %d → %d workers", old, max_workers
                )

    # =========================================================================
    # INTERNAL
    # =========================================================================

    def _worker_loop(self) -> None:
        """Main loop for each worker thread. Blocks on the FIFO queue."""
        while not self._shutdown_event.is_set():
            try:
                task = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue

            # Sentinel for scale-down
            if task is None:  # type: ignore
                self._queue.task_done()
                self._detach_worker()
                return

            try:
                self._execute_task(task)  # type: ignore
            finally:
                self._queue.task_done()

    def _execute_task(self, task: SeQueueTask) -> None:
        """Execute a single task, handling status transitions."""
        with self._lock:
            # Was cancelled while pending?
            if task.status == SeQueueTaskStatus.CANCELLED:
                self._add_to_history(task)
                self._remove_pending(task)
                self._remove_external_id(task)
                return

            self._remove_pending(task)
            task.status = SeQueueTaskStatus.RUNNING
            task.started_at = datetime.now()
            self._running[task.id] = task

        try:
            if task._callable is None:
                raise RuntimeError("Task has no callable set")

            result = task._callable(*task._args, **task._kwargs)

            with self._lock:
                # If cancel() already processed this task, skip overwriting status
                if task.id not in self._running:
                    return
                task.status = SeQueueTaskStatus.COMPLETED
                task.finished_at = datetime.now()
                task.progress = 100
                task.result = result
                self._add_to_history(task)
                self._remove_running(task)
                self._remove_external_id(task)

            if task.on_complete:
                try:
                    task.on_complete(task)
                except Exception as exc:
                    self.logger.warning(
                        "on_complete callback failed for task %s: %s", task.id, exc
                    )

        except Exception as exc:
            self.logger.error("Task %s failed: %s", task.id, exc)

            with self._lock:
                # If cancel() already processed this task, skip overwriting status
                if task.id not in self._running:
                    return
                task.status = SeQueueTaskStatus.FAILED
                task.finished_at = datetime.now()
                task.error = str(exc)
                self._add_to_history(task)
                self._remove_running(task)
                self._remove_external_id(task)

            if task.on_error:
                try:
                    task.on_error(task, exc)
                except Exception as cb_exc:
                    self.logger.warning(
                        "on_error callback failed for task %s: %s", task.id, cb_exc
                    )

    def _remove_pending(self, task: SeQueueTask) -> None:
        """Remove from pending dict only (assumes lock held).
        Does NOT remove the external_id mapping — that stays until the
        task reaches a terminal state so that domain-layer lookups
        (e.g. cancel_scan) can still find running tasks."""
        self._pending.pop(task.id, None)

    def _remove_running(self, task: SeQueueTask) -> None:
        """Remove from running dict (assumes lock held)."""
        self._running.pop(task.id, None)

    def _remove_external_id(self, task: SeQueueTask) -> None:
        """Clean up the external-id → task-id mapping."""
        if task.external_id and self._external_id_map.get(task.external_id) == task.id:
            del self._external_id_map[task.external_id]

    def _add_to_history(self, task: SeQueueTask) -> None:
        """Insert into bounded history (assumes lock held)."""
        if task.id in self._history:
            del self._history[task.id]
        self._history[task.id] = task
        self._history.move_to_end(task.id)

        # Enforce size limit
        while len(self._history) > self._history_max:
            self._history.popitem(last=False)

        # Enforce TTL
        cutoff = datetime.now().timestamp() - self._history_ttl
        stale = [
            tid for tid, t in self._history.items()
            if t.finished_at and t.finished_at.timestamp() < cutoff
        ]
        for tid in stale:
            del self._history[tid]

    def _detach_worker(self) -> None:
        """Remove current thread from worker list (called by exiting workers)."""
        current = threading.current_thread()
        with self._lock:
            self._workers = [w for w in self._workers if w is not current]

    # =========================================================================
    # TASK PROGRESS (called from executing code)
    # =========================================================================

    def update_progress(self, task_id: uuid.UUID, progress: int) -> None:
        with self._lock:
            task = self._running.get(task_id)
            if task is not None and 0 <= progress <= 100:
                task.progress = progress
