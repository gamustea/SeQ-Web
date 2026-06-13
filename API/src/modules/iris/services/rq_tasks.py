"""
iris/services/rq_tasks.py
──────────────────────────
Standalone module-level function for Iris email header analysis submitted to RQ.
"""


def execute_iris_analysis(analysis_id: int, raw_headers: str) -> None:
    from src.modules.iris.managers import IrisManager

    manager = IrisManager()
    manager._run_analysis(analysis_id, raw_headers)
