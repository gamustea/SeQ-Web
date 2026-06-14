"""
iris/services/rq_tasks.py
──────────────────────────
Standalone module-level function for Iris email header analysis submitted to RQ.

This function is a simple entry point that delegates to IrisManager._run_analysis(),
which internally handles job_context() for progress and cancellation.
"""

import logging

_logger = logging.getLogger(__name__)


def execute_iris_analysis(analysis_id: int, raw_headers: str) -> None:
    """Execute iris analysis. Already wrapped with job_context in the manager."""
    try:
        from src.modules.iris.managers import IrisManager

        manager = IrisManager()
        manager._run_analysis(analysis_id, raw_headers)
    except Exception as exc:
        _logger.error("Iris analysis %d failed: %s", analysis_id, exc, exc_info=True)
        raise
