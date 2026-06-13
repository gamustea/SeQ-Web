"""
aegis/services/rq_tasks.py
───────────────────────────
Standalone module-level function for Aegis document generation submitted to RQ.
"""


def execute_aegis_generation(
    document_id: int,
    topic_id: int,
    tweaks: dict,
    user_id: int,
) -> None:
    from src.modules.users.managers import UserManager
    from src.modules.aegis.managers import AegisManager

    user_mgr = UserManager()
    user = user_mgr.get_user_by_id(user_id)
    if not user:
        raise ValueError(f"User {user_id} not found")

    manager = AegisManager(user)
    manager._run_generation_workflow(document_id, topic_id, tweaks)
