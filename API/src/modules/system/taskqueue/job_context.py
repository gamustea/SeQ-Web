"""
taskqueue/job_context.py
────────────────────────
Helper compartido para las funciones ejecutadas dentro del worker (DRY).

Antes, cada módulo (sentinel, aegis, iris) reimplementaba sus propios
``_cancel_check`` / ``_clear_cancel`` / ``_update_progress`` sobre
``get_current_job()``. ``job_context`` centraliza ese patrón y garantiza que
la señal de cancelación se limpie siempre al terminar, aunque el job falle::

    def execute_iris_analysis(analysis_id, raw_headers):
        with job_context() as job:
            IrisManager().._run_analysis(analysis_id, raw_headers)

    def execute_nmap_scan(scan_id, host, ports, timeout):
        with job_context() as job:
            task = NmapScanTask(..., progress_callback=job.progress)
            NmapScanManager()._execute_scan(scan_id, task, cancel_check=job.cancelled)
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator, Optional

from rq import get_current_job

from .queue import TaskQueue
from .stores import ProgressStore


class JobHandle:
    """Vista del job RQ en ejecución: progreso y cancelación cooperativa."""

    def __init__(self, job) -> None:
        self._job = job

    @property
    def id(self) -> Optional[str]:
        return self._job.id if self._job else None

    def progress(self, pct: int) -> None:
        """Actualiza el progreso (0-100) del job actual."""
        if self._job is not None and 0 <= pct <= 100:
            ProgressStore.write(self._job, pct)

    def cancelled(self) -> bool:
        """Indica si se ha solicitado la cancelación de este job."""
        if self._job is None:
            return False
        return TaskQueue.get_instance().is_cancelled(self._job.id)

    def clear_cancel(self) -> None:
        """Limpia la señal de cancelación asociada a este job."""
        if self._job is not None:
            TaskQueue.get_instance().clear_cancel_signal(self._job.id)


@contextmanager
def job_context() -> Iterator[JobHandle]:
    """Context manager que expone el job actual y limpia la señal de
    cancelación al salir (éxito o error)."""
    handle = JobHandle(get_current_job())
    try:
        yield handle
    finally:
        handle.clear_cancel()
