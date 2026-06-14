"""
taskqueue/tracking.py
─────────────────────
Mixin reutilizable para los managers que respaldan una entidad de dominio
con una tarea en segundo plano (DRY).

Antes, iris y sentinel repetían el mismo patrón "buscar la tarea por
external_id y, si existe, leer estado/progreso". Este mixin lo centraliza y
fija en un único lugar el formato del ``external_id`` y la categoría de cola.

La subclase debe:
- exponer ``self._tq`` (una ``ITaskQueue``), y
- definir ``EXTERNAL_ID_PREFIX`` y ``TASK_CATEGORY``.
"""

from __future__ import annotations

from typing import Optional

from .interfaces import ITaskQueue
from .task import Task


class TaskTrackingMixin:
    """Acceso uniforme al estado/progreso de la tarea de una entidad."""

    EXTERNAL_ID_PREFIX: str = ""
    TASK_CATEGORY: Optional[str] = None

    _tq: ITaskQueue

    def external_id_for(self, entity_id) -> str:
        """Construye el ``external_id`` canónico de la entidad."""
        return f"{self.EXTERNAL_ID_PREFIX}{entity_id}"

    def find_task(self, entity_id) -> Optional[Task]:
        return self._tq.get_task_by_external_id(
            self.external_id_for(entity_id), self.TASK_CATEGORY
        )

    def task_status_of(self, entity_id) -> Optional[str]:
        task = self.find_task(entity_id)
        return str(task.status) if task else None

    def task_progress_of(self, entity_id) -> Optional[int]:
        task = self.find_task(entity_id)
        return task.progress if task else None
