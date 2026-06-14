"""
taskqueue/interfaces.py
───────────────────────
Contrato del sistema de tareas (Dependency Inversion Principle).

Los managers dependen de ``ITaskQueue`` en lugar del singleton concreto
``TaskQueue``. Esto permite inyectar una implementación falsa en los tests
(sin Redis ni RQ) y desacopla la lógica de dominio de la infraestructura.
"""

from __future__ import annotations

from typing import Callable, Optional, Protocol, runtime_checkable

from .task import Task


@runtime_checkable
class ITaskQueue(Protocol):
    """Superficie pública de la cola de tareas usada por los managers."""

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
    ) -> Task: ...

    def cancel(self, task_id: str) -> bool: ...

    def get_task(self, task_id: str) -> Optional[Task]: ...

    def get_task_by_external_id(
        self, external_id: str, category: Optional[str] = None
    ) -> Optional[Task]: ...

    def update_progress(self, task_id: str, progress: int) -> None: ...

    def is_cancelled(self, task_id: str) -> bool: ...

    def clear_cancel_signal(self, task_id: str) -> None: ...
