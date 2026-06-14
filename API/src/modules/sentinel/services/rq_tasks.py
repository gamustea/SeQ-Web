"""
sentinel/services/rq_tasks.py
─────────────────────────────
Standalone module-level functions submitted to the RQ task queue.

These functions are simple entry points that delegate to managers.
The managers internally handle job_context() for progress and cancellation support.
El contexto de aplicación Flask es empujado por el worker al arrancar, así que las
sesiones de BD funcionan de forma transparente.
"""

from __future__ import annotations

import logging

_logger = logging.getLogger(__name__)


def execute_nmap_scan(
    scan_id: int,
    target_host: str,
    target_ports: str,
    timeout: int,
) -> None:
    """Execute Nmap scan. Already wrapped with job_context in the manager."""
    try:
        from src.modules.sentinel.managers import NmapScanManager

        manager = NmapScanManager()
        manager.execute_nmap_scan_internal(scan_id, target_host, target_ports, timeout)
    except Exception as exc:
        _logger.error("Nmap scan %d failed: %s", scan_id, exc, exc_info=True)
        raise


def execute_nikto_scan(
    scan_id: int,
    target_domain: str,
    timeout: int,
) -> None:
    """Execute Nikto scan. Already wrapped with job_context in the manager."""
    try:
        from src.modules.sentinel.managers import NiktoScanManager

        manager = NiktoScanManager()
        manager.execute_nikto_scan_internal(scan_id, target_domain, timeout)
    except Exception as exc:
        _logger.error("Nikto scan %d failed: %s", scan_id, exc, exc_info=True)
        raise


def execute_openvas_scan(
    scan_id: int,
    target: str,
    scan_config_id: str,
    skip_normalize: bool,
) -> None:
    """Execute OpenVAS scan. Already wrapped with job_context in the manager."""
    try:
        from src.modules.sentinel.managers import OpenVASScanManager

        manager = OpenVASScanManager()
        manager.execute_openvas_scan_internal(scan_id, target, scan_config_id, skip_normalize)
    except Exception as exc:
        _logger.error("OpenVAS scan %d failed: %s", scan_id, exc, exc_info=True)
        raise


def execute_report_generation(
    doc_id: int,
    scan_id: int,
    ai_report: bool,
) -> None:
    """Generate PDF report."""
    try:
        from src.modules.sentinel.managers import SentinelReportManager

        manager = SentinelReportManager()
        manager._generate_pdf_async(doc_id, scan_id, ai_report)
    except Exception as exc:
        _logger.error("Report generation for doc %d failed: %s", doc_id, exc, exc_info=True)
        raise
