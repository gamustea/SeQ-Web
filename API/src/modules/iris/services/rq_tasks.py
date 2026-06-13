"""
iris/services/rq_tasks.py
──────────────────────────
Standalone module-level function for Iris email header analysis submitted to RQ.
"""

import logging

from src.modules.system.taskqueue import TaskQueue

_logger = logging.getLogger(__name__)


def execute_iris_analysis(analysis_id: int, raw_headers: str) -> None:
    try:
        from src.modules.iris.managers import IrisManager

        manager = IrisManager()
        manager._run_analysis(analysis_id, raw_headers)
    except Exception as exc:
        _logger.error("Iris analysis %d failed: %s", analysis_id, exc, exc_info=True)
        raise
    finally:
        from rq import get_current_job
        job = get_current_job()
        if job:
            TaskQueue.get_instance().clear_cancel_signal(job.id)
