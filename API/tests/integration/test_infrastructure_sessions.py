"""
Integration tests for session/transaction resilience against the real engine.

These exercise the data-access layer's recovery behaviour using the SQLite
engine wired up by ``conftest`` (shared by both ``unit_of_work`` and
``shared._managers``):

- A poisoned thread-scoped session is recovered after the job-boundary
  ``close_all()`` — the core background-resilience guarantee.
- ``UnitOfWork`` rolls back and re-raises on commit failure, and recreates a
  usable session when a rollback itself fails.
- ``BaseManager`` shares the request session (deferring commit to teardown) in
  a request context, but owns and commits its own session in the background.
"""

from __future__ import annotations

from unittest import mock

import pytest
import sqlalchemy as sa
from sqlalchemy.exc import SQLAlchemyError

from src.modules.infrastructure import unit_of_work
from src.modules.infrastructure.unit_of_work import UnitOfWork, close_all, get_session
from src.modules.infrastructure.session import get_db_session
from src.modules.shared import BaseManager

pytestmark = pytest.mark.integration


# ---------------------------------------------------------------------------
# Core fix: a poisoned scoped session is recovered at the job boundary
# ---------------------------------------------------------------------------

def test_close_all_yields_fresh_session_between_jobs(_initialized_db):
    """The job-boundary cleanup (what worker/scheduler now run in ``finally``)
    must hand the next job a brand-new session.

    ``scoped_session`` is keyed by thread and worker threads are long-lived, so
    without ``close_all()`` the very same ``Session`` object is reused across
    jobs — and with it any residual transaction/identity-map state. This test
    pins the mechanism that prevents that leak."""
    s1 = get_session()

    # Without cleanup the scoped factory hands back the *same* object: that is
    # exactly the leak path between sequential jobs on one worker thread.
    assert get_session() is s1

    # A job runs some work (and may even fail) on s1.
    with pytest.raises(Exception):
        s1.execute(sa.text("SELECT * FROM table_that_does_not_exist_xyz"))

    # Job boundary cleanup removes the session from the scoped registry.
    close_all()

    # The next job on this thread now gets a fresh, working session.
    s2 = get_session()
    assert s2 is not s1
    assert s2.execute(sa.text("SELECT 1")).scalar() == 1
    close_all()


# ---------------------------------------------------------------------------
# UnitOfWork transaction failure handling
# ---------------------------------------------------------------------------

def test_commit_failure_rolls_back_and_reraises(_initialized_db):
    uow = UnitOfWork()
    try:
        with mock.patch.object(uow.session, "commit", side_effect=SQLAlchemyError("boom")), \
             mock.patch.object(uow.session, "rollback") as rollback:
            with pytest.raises(SQLAlchemyError):
                uow.commit()
            rollback.assert_called_once()
    finally:
        close_all()


def test_rollback_failure_recreates_usable_session(_initialized_db):
    uow = UnitOfWork()
    try:
        with mock.patch.object(uow.session, "rollback", side_effect=Exception("rollback boom")):
            with pytest.raises(RuntimeError):
                uow.rollback()

        # After a failed rollback the UoW must still expose a usable session.
        assert uow.session is not None
        assert uow.session.execute(sa.text("SELECT 1")).scalar() == 1
    finally:
        close_all()


# ---------------------------------------------------------------------------
# BaseManager ownership / commit-deferral semantics
# ---------------------------------------------------------------------------

def test_basemanager_shares_request_session_and_defers_commit(app):
    with app.test_request_context():
        session = get_db_session()  # mirrors init_request_session
        manager = BaseManager()

        assert manager._owns_session is False
        assert manager.session is session

        with mock.patch.object(session, "commit") as commit, \
             mock.patch.object(session, "flush") as flush:
            manager._persist()
            commit.assert_not_called()  # commit deferred to teardown
            flush.assert_called_once()


def test_basemanager_owns_and_commits_in_background(app):
    # Application context but no request context → background semantics.
    with app.app_context():
        manager = BaseManager()
        try:
            assert manager._owns_session is True
            with mock.patch.object(manager.session, "commit") as commit:
                manager._persist()
                commit.assert_called_once()
        finally:
            manager.close_session()
