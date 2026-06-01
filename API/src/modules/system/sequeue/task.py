"""
sequeue/task.py
───────────────
SeQueueTask wrapper and status enum for the SeQueue system.

SeQueueTask wraps any callable submitted to SeQueue, tracking its
lifecycle status, progress, and providing hooks for completion,
error handling, and cancellation.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Optional


class SeQueueTaskStatus(Enum):
    """Lifecycle states for a SeQueue task."""
    PENDING   = "pending"
    RUNNING   = "running"
    COMPLETED = "completed"
    FAILED    = "failed"
    CANCELLED = "cancelled"

    def __str__(self) -> str:
        return self.value


@dataclass
class SeQueueTask:

    id: uuid.UUID = field(default_factory=uuid.uuid4)
    name: str = ""
    category: str = ""
    external_id: Optional[str] = None

    status: SeQueueTaskStatus = SeQueueTaskStatus.PENDING
    progress: int = 0
    created_at: datetime = field(default_factory=datetime.now)
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    result: Optional[Any] = None
    error: Optional[str] = None

    # ── internal (not serialised) ──────────────────────────────────────

    _callable: Optional[Callable] = field(default=None, repr=False, compare=False)
    _args: tuple = field(default_factory=tuple, repr=False, compare=False)
    _kwargs: dict = field(default_factory=dict, repr=False, compare=False)

    on_complete: Optional[Callable[[SeQueueTask], None]] = field(
        default=None, repr=False, compare=False
    )
    on_error: Optional[Callable[[SeQueueTask, Exception], None]] = field(
        default=None, repr=False, compare=False
    )
    on_cancel: Optional[Callable[[], None]] = field(
        default=None, repr=False, compare=False
    )

    def to_dict(self) -> dict:
        return {
            "id":          str(self.id),
            "name":        self.name,
            "category":    self.category,
            "externalId":  self.external_id,
            "status":      str(self.status),
            "progress":    self.progress,
            "createdAt":   self.created_at.isoformat() if self.created_at else None,
            "startedAt":   self.started_at.isoformat() if self.started_at else None,
            "finishedAt":  self.finished_at.isoformat() if self.finished_at else None,
            "error":       self.error,
        }
