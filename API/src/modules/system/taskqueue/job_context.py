"""
taskqueue/job_context.py
────────────────────────
Helper para funciones ejecutadas en workers (DRY + garantías de cleanup).

**Propósito**:
    Los workers (en procesos/threads separados) necesitan:
    1. Actualizar progreso → report("Escanneando 30%", ...)
    2. Revisar si fue solicitada cancelación → if job.cancelled(): break
    3. Limpiar la bandera de cancelación al terminar

Antes, cada módulo (sentinel, aegis, iris) reimplementaba esto:
    - get_current_job() manualmente
    - Queries a TaskQueue para is_cancelled()
    - Manejo manual de cleanup (y olvidaba en caminos de error)

**job_context() centraliza**:
    - JobHandle: vista del RQ Job actual (segura fuera del worker)
    - Métodos: progress(pct), cancelled(), clear_cancel()
    - Context manager: garantiza cleanup (finally clause) aunque falle

**Uso en entry points de workers**::

    # Entrada del worker desde RQ (staticmethod en manager)
    @staticmethod
    def execute_nmap_scan(scan_id, host, ports, timeout):
        with job_context() as job:
            # job = JobHandle (safe outside worker, no-op si no está en RQ)
            task = NmapScanTask(
                target_host=host,
                target_ports=ports,
                timeout=timeout,
                progress_callback=job.progress  # ← llamar para actualizar progreso
            )
            NmapScanManager()._execute_scan(
                scan_id,
                task,
                cancel_check=job.cancelled  # ← pasar para revisar cancelación
            )
            # Al salir del with: job.clear_cancel() limpia la bandera

**JobHandle**: adaptador defensivo
    - Si el RQ get_current_job() retorna None (no estamos en un worker),
      los métodos no-op gracefully (no crashean)
    - Permite que la función sea testeable sin RQ
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator, Optional

from rq import get_current_job

from .queue import TaskQueue
from .stores import ProgressStore


class JobHandle:
    """Vista defensiva del RQ Job en ejecución: progreso + cancelación cooperativa.

    **Por qué 'defensiva'**: Si no estamos en un worker RQ (ej: tests, CLI),
    get_current_job() retorna None. En lugar de crashear, JobHandle no-ops
    gracefully (progress/cancelled/clear_cancel hacen nothing).

    **Uso típico**::
        with job_context() as job:
            for item in items:
                if job.cancelled():
                    break
                process(item)
                job.progress(100 * i // len(items))
    """

    def __init__(self, job) -> None:
        self._job = job

    @property
    def id(self) -> Optional[str]:
        """ID del RQ Job actual, o None si no estamos en un worker."""
        return self._job.id if self._job else None

    def progress(self, pct: int) -> None:
        """Actualiza el progreso del job actual (0-100).

        Se almacena en job.meta["progress"] en Redis.
        El API la consulta vía TaskQueue.get_task_by_external_id() y responde
        al cliente con {"status": "running", "progress": 35, ...}

        No-op si no estamos en un worker (self._job is None).

        Args:
            pct: 0-100. Fuera de rango = ignored.
        """
        if self._job is not None and 0 <= pct <= 100:
            ProgressStore.write(self._job, pct)

    def cancelled(self) -> bool:
        """Consulta si se solicitó cancelación cooperativa de este job.

        El manager/API hace TaskQueue.cancel(job_id) → señal cooperativa.
        El worker chequea job.cancelled() periódicamente y sale si es True.

        Retorna False si no estamos en un worker (seguro, no crashea).

        Típicamente usado en loops::
            while trabajo_pendiente:
                if job.cancelled():
                    break
                hacer_trabajo()
        """
        if self._job is None:
            return False
        return TaskQueue.get_instance().is_cancelled(self._job.id)

    def clear_cancel(self) -> None:
        """Limpia la bandera de cancelación al terminar el job.

        Previene que señales viejas interfieran con futuros reintentos.
        El context manager job_context() lo llama automáticamente en finally.

        No-op si no estamos en un worker.
        """
        if self._job is not None:
            TaskQueue.get_instance().clear_cancel_signal(self._job.id)


@contextmanager
def job_context() -> Iterator[JobHandle]:
    """Context manager para función ejecutada en un worker RQ.

    **Garantías**:
        1. Expone JobHandle: progreso + cancelación + limpieza automática
        2. Limpia la señal de cancelación al salir (finally → always runs)
        3. Safe fuera de RQ: si no hay job, todo es no-op

    **Uso obligatorio en entry points de workers**::

        @staticmethod
        def execute_my_scan(scan_id, target_host, ...):
            with job_context() as job:
                # job.progress(), job.cancelled(), etc.
                manager = MyManager()
                manager._run_internal(..., cancel_check=job.cancelled)
                # Al salir: job.clear_cancel() ejecuta automáticamente

    **Control de flujo**:
        - try: yield el JobHandle al usuario (quien lo usa en el with)
        - finally: clear_cancel() **siempre** ejecuta (éxito, excepción, todo)
        - No atrapa excepciones (dejar que RQ las maneje)
    """
    handle = JobHandle(get_current_job())
    try:
        yield handle
    finally:
        handle.clear_cancel()
