"""
taskqueue/__init__.py
────────────────────
Public API for the RQ-backed background task queue system.
"""

from .interfaces import ITaskQueue
from .job_context import JobHandle, job_context
from .queue import TaskQueue
from .registry import DEFAULT_QUEUE, QueueRegistry
from .task import Task, TaskStatus
from .tracking import TaskTrackingMixin

__all__ = [
    "ITaskQueue",
    "JobHandle",
    "job_context",
    "Task",
    "TaskQueue",
    "TaskStatus",
    "TaskTrackingMixin",
    "QueueRegistry",
    "DEFAULT_QUEUE",
]
