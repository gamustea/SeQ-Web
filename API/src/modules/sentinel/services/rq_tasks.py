"""
sentinel/services/rq_tasks.py
──────────────────────────────
Standalone module-level functions submitted to the RQ task queue.

These functions are designed to be serialized by pickle and executed
within RQ worker processes. They reconstruct the necessary objects,
execute scan/report logic, and update Redis metadata (progress,
cancellation). Flask application context is pushed by the worker
at startup, so DB sessions work transparently.
"""

from __future__ import annotations

from rq import get_current_job

from src.modules.system.taskqueue import TaskQueue


def _update_progress(progress: int) -> None:
    job = get_current_job()
    if job:
        job.meta["progress"] = progress
        job.save_meta()


def _cancel_check() -> bool:
    job = get_current_job()
    if job:
        return TaskQueue.get_instance().is_cancelled(job.id)
    return False


def _clear_cancel() -> None:
    job = get_current_job()
    if job:
        TaskQueue.get_instance().clear_cancel_signal(job.id)


def execute_nmap_scan(
    scan_id: int,
    target_host: str,
    target_ports: str,
    timeout: int,
) -> None:
    from src.modules.sentinel.services.tasks import NmapScanTask
    from src.modules.sentinel.managers import NmapScanManager

    task = NmapScanTask(
        target_host=target_host,
        target_ports=target_ports,
        timeout=timeout,
        progress_callback=_update_progress,
    )
    manager = NmapScanManager(user=None)
    manager._execute_scan(scan_id, task, cancel_check=_cancel_check)
    _clear_cancel()


def execute_nikto_scan(
    scan_id: int,
    target_domain: str,
    timeout: int,
) -> None:
    from src.modules.sentinel.services.tasks import NiktoScanTask
    from src.modules.sentinel.managers import NiktoScanManager

    task = NiktoScanTask(
        target_domain=target_domain,
        timeout=timeout,
        progress_callback=_update_progress,
    )
    manager = NiktoScanManager(user=None)
    manager._execute_scan(scan_id, task, cancel_check=_cancel_check)
    _clear_cancel()


def execute_openvas_scan(
    scan_id: int,
    target: str,
    scan_config_id: str,
    skip_normalize: bool,
) -> None:
    from src.modules.sentinel.services.tasks import OpenVASTask
    from src.modules.sentinel.managers import OpenVASScanManager
    from src.modules.system.config_reading import get_openvas_environment

    environ = get_openvas_environment()

    task = OpenVASTask(
        target=target,
        hostname=environ["hostname"],
        port=environ["port"],
        username=environ["username"],
        password=environ["password"],
        scan_config=scan_config_id,
        progress_callback=_update_progress,
    )
    manager = OpenVASScanManager(user=None)
    manager._execute_scan(scan_id, task, skip_normalize, cancel_check=_cancel_check)
    _clear_cancel()


def execute_report_generation(
    doc_id: int,
    scan_id: int,
    ai_report: bool,
) -> None:
    from src.modules.sentinel.managers import SentinelReportManager

    manager = SentinelReportManager(user=None)
    manager._generate_pdf_async(doc_id, scan_id, ai_report)
