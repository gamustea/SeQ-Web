"""
aegis/services/rq_tasks.py
───────────────────────────
Standalone module-level function for Aegis document generation submitted to RQ.

This function is a simple entry point that delegates to AegisManager._run_generation_workflow(),
which internally handles job_context() for graceful execution in or out of RQ.
"""

import logging

_logger = logging.getLogger(__name__)


def execute_aegis_generation(
    document_id: int,
    topic_id: int,
    tweaks: dict,
    user_id: int,
) -> None:
    """Execute Aegis generation workflow. Already wrapped with job_context in the manager."""
    try:
        from src.modules.users.managers import UserManager
        from src.modules.aegis.managers import AegisManager

        user_mgr = UserManager()
        user = user_mgr.get_user_by_id(user_id)
        if not user:
            raise ValueError(f"User {user_id} not found")

        manager = AegisManager(user)
        manager._run_generation_workflow(document_id, topic_id, tweaks)
    except Exception as exc:
        _logger.error("Aegis generation for doc %d failed: %s", document_id, exc, exc_info=True)
        raise
