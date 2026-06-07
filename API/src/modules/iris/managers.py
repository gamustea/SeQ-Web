"""
IrisManager — orchestrates email header analysis via SeQueue background tasks.

Coordinates the analysis lifecycle:
1. Creates an IrisAnalysis record in the database.
2. Submits an analysis task to SeQueue (category: "iris.analyze").
3. The background task runs all registered rules, aggregates scores,
   determines a verdict, and persists results.
4. Provides status queries and cancellation support.
"""

from __future__ import annotations

import threading

from datetime import datetime
from typing import Any, Dict, List, Optional

import src.modules.system.config_reading as CR
from src.modules.infrastructure import UnitOfWork
from src.modules.infrastructure.session import get_db_session
from src.modules.system.logging import SecOpsLogger
from src.modules.system.sequeue import SeQueue

from .exceptions import (
    IrisAnalysisNotFoundError,
    IrisAnalysisNotReadyError,
    IrisExecutionError,
    IrisInvalidStateError,
)
from .model import IrisAnalysis, IrisRuleResult
from .repositories import IrisAnalysisRepository, IrisRuleResultRepository
from .rules import iris_rules, RuleResult
from .services import parse_raw_headers


_CANCELLABLE_STATES = frozenset({"pending", "running"})


class IrisManager:
    """Orchestrates the lifecycle of an Iris email-header analysis.

    Typical usage::

        manager = IrisManager()
        analysis_id = manager.analyze(raw_headers, user_id)   # submit
        status = manager.get_analysis_status(analysis_id)      # poll
        report = manager.get_analysis_results(analysis_id)     # finished
    """

    def __init__(self) -> None:
        self.logger = SecOpsLogger("IrisManager").get_logger()

    # =========================================================================
    # PUBLIC API
    # =========================================================================

    def analyze(self, raw_headers: str, user_id: int) -> int:
        """Submit raw email headers for background analysis.

        Creates an IrisAnalysis record in ``pending`` state and enqueues
        a SeQueue task (category ``"iris.analyze"``) that runs every
        registered rule, aggregates scores, and persists the results.

        Args:
            raw_headers: Full email header block as plain text.
            user_id:     Primary key of the requesting user.

        Returns:
            The new IrisAnalysis primary key (``analysis_id``).  The
            caller should store this to later poll status or fetch the
            full report.
        """
        analysis_id = self._create_analysis_record(raw_headers, user_id)
        self.logger.info(f"Iris analysis {analysis_id} created for user {user_id}")

        cancel_event = threading.Event()
        thread_mgr = IrisManager()

        SeQueue.get_instance().submit(
            func=thread_mgr._run_analysis,
            args=(analysis_id, raw_headers),
            name=f"IrisAnalysis-{analysis_id}",
            category="iris.analyze",
            external_id=f"iris-analysis:{analysis_id}",
            on_cancel=cancel_event.set,
        )

        return analysis_id

    def get_analysis(self, analysis_id: int) -> Optional[IrisAnalysis]:
        """Fetch the analysis ORM object by its primary key.

        Returns None (rather than raising) when the analysis does not
        exist, which lets callers distinguish "not found" from
        "not ready".
        """
        session = get_db_session()
        return IrisAnalysisRepository(session=session).get_by_id(analysis_id)

    def get_analysis_status(self, analysis_id: int) -> Optional[str]:
        """Return the current lifecycle status string of an analysis.

        Checks the in-memory SeQueue task first (fast path for running
        tasks) and falls back to the database record.  Returns None
        if the analysis ID is unknown.
        """
        sequeue = SeQueue.get_instance()
        sq_task = sequeue.get_task_by_external_id(
            f"iris-analysis:{analysis_id}", category="iris.analyze"
        )
        if sq_task:
            return str(sq_task.status)

        analysis = self.get_analysis(analysis_id)
        if analysis:
            return analysis.status
        return None

    def get_analysis_progress(self, analysis_id: int) -> Optional[int]:
        """Return the progress percentage (0‑100) of a running analysis.

        Only meaningful for analyses in ``running`` state — returns None
        if no SeQueue task is active (e.g. finished or pending).
        """
        sequeue = SeQueue.get_instance()
        sq_task = sequeue.get_task_by_external_id(
            f"iris-analysis:{analysis_id}", category="iris.analyze"
        )
        if sq_task:
            return sq_task.progress
        return None

    def get_analysis_results(self, analysis_id: int) -> Dict[str, Any]:
        """Return the full analysis report for a finished analysis.

        The report includes the original headers, per-rule results,
        the total score, the textual verdict, and a flat list of
        actionable recommendations.

        Args:
            analysis_id: Primary key of the finished analysis.

        Returns:
            A dict with keys: analysisId, status, rawHeaders, totalScore,
            verdict, startedAt, finishedAt, user, rules, recommendations.

        Raises:
            IrisAnalysisNotFoundError: If *analysis_id* does not exist.
            IrisAnalysisNotReadyError: If the analysis is not yet
                ``finished`` (callers should poll ``/status`` first).
        """
        session = get_db_session()
        analysis = IrisAnalysisRepository(session=session).get_by_id(analysis_id)
        if not analysis:
            raise IrisAnalysisNotFoundError(analysis_id)

        if analysis.status != "finished":
            raise IrisAnalysisNotReadyError(analysis_id, analysis.status)

        rules_repo = IrisRuleResultRepository(session=session)
        rules = rules_repo.get_by_analysis(analysis_id)

        rules_data = [
            {
                "ruleName": r.rule_name,
                "category": r.category,
                "score": r.score,
                "verdict": r.verdict,
                "details": r.details,
                "recommendation": r.recommendation,
            }
            for r in rules
        ]

        recommendations = [
            r["recommendation"] for r in rules_data
            if r["recommendation"] is not None
        ]

        from src.modules.users import UserManager
        user = UserManager().get_user_by_id(analysis.user_id)
        username = user.username if user else "unknown"

        return {
            "analysisId": analysis.id,
            "status": analysis.status,
            "rawHeaders": analysis.raw_headers,
            "totalScore": analysis.total_score,
            "verdict": analysis.verdict,
            "startedAt": analysis.started_at.isoformat() if analysis.started_at else None,
            "finishedAt": analysis.finished_at.isoformat() if analysis.finished_at else None,
            "user": username,
            "rules": rules_data,
            "recommendations": recommendations,
        }

    def cancel_analysis(self, analysis_id: int, user_id: int) -> bool:
        """Cancel a running or pending analysis.

        Signals the SeQueue task to stop and marks the database record
        as ``cancelled``.

        Args:
            analysis_id: Primary key of the analysis to cancel.
            user_id:     Owner ID (must match the record's owner).

        Returns:
            True if the cancellation was successful.

        Raises:
            IrisAnalysisNotFoundError: If the analysis does not exist
                or does not belong to this user.
            IrisInvalidStateError: If the analysis is not in a
                cancellable state (``pending`` or ``running``).
        """
        analysis = self.assert_analysis_ownership(analysis_id, user_id)

        if analysis.status not in _CANCELLABLE_STATES:
            raise IrisInvalidStateError(
                f"Analysis {analysis_id} cannot be cancelled in state: {analysis.status}"
            )

        sequeue = SeQueue.get_instance()
        sq_task = sequeue.get_task_by_external_id(
            f"iris-analysis:{analysis_id}", category="iris.analyze"
        )
        if not sq_task:
            self.logger.warning(f"No active task found for analysis {analysis_id}")
            return False

        cancelled = sequeue.cancel(sq_task.id)
        if cancelled:
            with UnitOfWork() as uow:
                repo = IrisAnalysisRepository(uow)
                fresh = repo.get_by_id(analysis_id)
                if fresh:
                    fresh.status = "cancelled"
                    fresh.finished_at = datetime.now()
                    repo.update(fresh)
            self.logger.info(f"Analysis {analysis_id} cancelled by user {user_id}")
        return cancelled

    def delete_analysis(self, analysis_id: int) -> bool:
        """Permanently delete an analysis and its rule results.

        Cancels the analysis first if it is still running.

        Args:
            analysis_id: Primary key of the analysis to delete.

        Returns:
            True if the record was deleted.

        Raises:
            IrisAnalysisNotFoundError: If the analysis does not exist.
        """
        analysis = self.get_analysis(analysis_id)
        if not analysis:
            raise IrisAnalysisNotFoundError(analysis_id)

        if analysis.status in _CANCELLABLE_STATES:
            sequeue = SeQueue.get_instance()
            sq_task = sequeue.get_task_by_external_id(
                f"iris-analysis:{analysis_id}", category="iris.analyze"
            )
            if sq_task:
                sequeue.cancel(sq_task.id)

        with UnitOfWork() as uow:
            repo = IrisAnalysisRepository(uow)
            fresh = repo.get_by_id(analysis_id)
            if fresh:
                repo.delete(fresh)
                self.logger.info(f"Analysis {analysis_id} deleted")
                return True
        return False

    def get_analyses_for_user(self, user_id: int, page: int = 1, per_page: int = 10):
        """Return a paginated, formatted list of analyses for a user.

        Args:
            user_id:  Owner of the analyses.
            page:     1‑based page number.
            per_page: Items per page.

        Returns:
            Tuple of (formatted_results: list[dict], total_count: int).
        """
        session = get_db_session()
        items, total = IrisAnalysisRepository(session=session).get_by_user_paginated(
            user_id, page, per_page
        )
        results = [
            {
                "analysisId": a.id,
                "status": a.status,
                "totalScore": a.total_score,
                "verdict": a.verdict,
                "startedAt": a.started_at.isoformat() if a.started_at else None, # type: ignore
                "finishedAt": a.finished_at.isoformat() if a.finished_at else None, # type: ignore
            }
            for a in items
        ]
        return results, total

    @classmethod
    def assert_analysis_ownership(cls, analysis_id: int, user_id: int) -> IrisAnalysis:
        """Verify that an analysis belongs to a given user.

        Raises IrisAnalysisNotFoundError when the analysis does not
        exist or the ownership check fails (same error for both cases
        to prevent ID enumeration).
        """
        session = get_db_session()
        analysis = IrisAnalysisRepository(session=session).get_by_id(analysis_id)
        if not analysis or analysis.user_id != user_id:
            raise IrisAnalysisNotFoundError(analysis_id)
        return analysis

    # =========================================================================
    # INTERNAL
    # =========================================================================

    def _create_analysis_record(self, raw_headers: str, user_id: int) -> int:
        """Persist a new IrisAnalysis row in ``pending`` state."""
        analysis = IrisAnalysis(
            raw_headers=raw_headers,
            user_id=user_id,
            status="pending",
        )
        with UnitOfWork() as uow:
            repo = IrisAnalysisRepository(uow)
            repo.save(analysis)
        return analysis.id # type: ignore

    def _run_analysis(self, analysis_id: int, raw_headers: str) -> None:
        """Background task: execute all rules and persist results.

        This is the function submitted to SeQueue.  It:
        1. Marks the analysis as ``running``.
        2. Parses the raw header text.
        3. Iterates over every registered rule, collects RuleResults.
        4. Updates the SeQueue task progress after each rule.
        5. Computes the total score and verdict.
        6. Persists the final state (``finished`` + score + verdict).

        If cancellation is detected between rule executions, the task
        exits early without saving results.
        """
        self.logger.info(f"Starting analysis {analysis_id}")

        try:
            with UnitOfWork() as uow:
                repo = IrisAnalysisRepository(uow)
                fresh = repo.get_by_id(analysis_id)
                if fresh:
                    fresh.status = "running" # type: ignore
                    fresh.started_at = datetime.now() # type: ignore
                    repo.update(fresh)
        except Exception as e:
            self.logger.error(f"Failed to mark analysis {analysis_id} as running: {e}")
            self._fail_analysis(analysis_id)
            return

        headers = parse_raw_headers(raw_headers)
        rules = iris_rules.get_rules()
        total_rules = len(rules)
        results: List[RuleResult] = []
        sequeue = SeQueue.get_instance()

        for idx, rule in enumerate(rules):
            if self._is_cancelled(analysis_id):
                self.logger.info(f"Analysis {analysis_id} was cancelled")
                return

            try:
                result = rule["func"](headers)
            except Exception as e:
                self.logger.error(f"Rule '{rule['name']}' failed for analysis {analysis_id}: {e}")
                result = RuleResult(
                    score=0, verdict="error",
                    details={"error": str(e)},
                    recommendation=f"La regla '{rule['name']}' falló durante la ejecución.",
                )

            self._persist_rule_result(analysis_id, rule, result, idx)
            results.append(result)

            progress = int(((idx + 1) / total_rules) * 100)
            sq_task = sequeue.get_task_by_external_id(
                f"iris-analysis:{analysis_id}", category="iris.analyze"
            )
            if sq_task:
                sequeue.update_progress(sq_task.id, progress)

        total_score = sum(r.score for r in results)
        verdict = self._determine_verdict(total_score)

        try:
            with UnitOfWork() as uow:
                repo = IrisAnalysisRepository(uow)
                fresh = repo.get_by_id(analysis_id)
                if fresh:
                    fresh.status = "finished" # type: ignore
                    fresh.total_score = total_score # type: ignore
                    fresh.verdict = verdict # type: ignore
                    fresh.finished_at = datetime.now() # type: ignore
                    repo.update(fresh)
        except Exception as e:
            self.logger.error(f"Failed to finalise analysis {analysis_id}: {e}")
            self._fail_analysis(analysis_id)
            return

        self.logger.info(f"Analysis {analysis_id} completed: score={total_score}, verdict={verdict}")

    def _persist_rule_result(self, analysis_id: int, rule_def: dict,
                              result: RuleResult, position: int) -> None:
        """Save a single rule's outcome to the IrisRuleResult table.

        Failures are logged but do not interrupt the analysis — the
        rule is treated as a neutral (zero-score) result.
        """
        try:
            with UnitOfWork() as uow:
                repo = IrisRuleResultRepository(uow)
                rr = IrisRuleResult(
                    analysis_id=analysis_id,
                    rule_name=rule_def["name"],
                    category=rule_def["category"],
                    score=result.score,
                    verdict=result.verdict,
                    details=result.details,
                    recommendation=result.recommendation,
                    position=position,
                )
                repo.save(rr)
        except Exception as e:
            self.logger.error(f"Failed to persist rule result for analysis {analysis_id}: {e}")

    def _determine_verdict(self, total_score: float) -> str:
        """Map a numeric total score to a textual verdict.

        Thresholds come from ``SecOpsConfig.json``:
            - ``iris.legitimate_threshold`` (default 30)
            - ``iris.suspicious_threshold``  (default -10)
        """
        legitimate = CR.get_iris_legitimate_threshold()
        suspicious = CR.get_iris_suspicious_threshold()

        if total_score >= legitimate:
            return "Legitimate"
        if total_score >= suspicious:
            return "Suspicious"
        return "Phishing"

    def _fail_analysis(self, analysis_id: int) -> None:
        """Mark an analysis as ``failed`` with a finished timestamp."""
        try:
            with UnitOfWork() as uow:
                repo = IrisAnalysisRepository(uow)
                fresh = repo.get_by_id(analysis_id)
                if fresh:
                    fresh.status = "failed" # type: ignore
                    fresh.finished_at = datetime.now() # type: ignore
                    repo.update(fresh)
        except Exception as e:
            self.logger.error(f"Failed to mark analysis {analysis_id} as failed: {e}")

    def _is_cancelled(self, analysis_id: int) -> bool:
        """Check whether the analysis has been cancelled since we started.

        Reads from both the SeQueue in-memory state and the database;
        returns True if either indicates ``cancelled``.
        """
        sequeue = SeQueue.get_instance()
        sq_task = sequeue.get_task_by_external_id(
            f"iris-analysis:{analysis_id}", category="iris.analyze"
        )
        if sq_task and sq_task.status.value == "cancelled":
            return True
        try:
            with UnitOfWork() as uow:
                repo = IrisAnalysisRepository(uow)
                analysis = repo.get_by_id(analysis_id)
                if analysis and analysis.status == "cancelled":
                    return True
        except Exception:
            pass
        return False # type: ignore
