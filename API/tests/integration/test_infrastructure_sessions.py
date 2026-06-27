"""
Integration tests for session/transaction resilience against the real engine.

These exercise the data-access layer's recovery behaviour using the SQLite
engine wired up by ``conftest`` (shared by both ``unit_of_work`` and
``shared._managers``):

- A poisoned thread-scoped session is recovered after the job-boundary
  ``close_all()`` — the core background-resilience guarantee.
- ``UnitOfWork`` rolls back and re-raises on commit failure, and re-raises on a
  failed rollback (recovery is the job boundary's ``close_all()``, since the
  UoW no longer owns the session).
- ``UnitOfWork`` is a no-op on exit inside a request (teardown commits, the
  session stays alive for lazy loading) and commits/rolls back its own block in
  a background context.
"""

from __future__ import annotations

from unittest import mock

import pytest
import sqlalchemy as sa
from sqlalchemy.exc import SQLAlchemyError

from src.modules.infrastructure import unit_of_work
from src.modules.infrastructure.unit_of_work import UnitOfWork, close_all, get_session
from src.modules.infrastructure.session import get_db_session

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


def test_rollback_failure_reraises_and_boundary_recovers(_initialized_db):
    """A failed rollback re-raises as RuntimeError. UnitOfWork no longer owns
    the session, so it does not recreate one — recovery is the job boundary's
    ``close_all()``, which hands the next job a fresh, usable session."""
    uow = UnitOfWork()
    try:
        with mock.patch.object(uow.session, "rollback", side_effect=Exception("rollback boom")):
            with pytest.raises(RuntimeError):
                uow.rollback()

        # The job-boundary cleanup recovers the thread-local session.
        close_all()
        assert get_session().execute(sa.text("SELECT 1")).scalar() == 1
    finally:
        close_all()


def test_unitofwork_manages_transaction_in_background(_initialized_db):
    """Outside a request, the UoW block owns commit/rollback (the boundary
    workers and the scheduler rely on)."""
    uow = UnitOfWork()
    try:
        assert uow._manage is True

        with mock.patch.object(uow.session, "commit") as commit:
            with uow:
                pass
            commit.assert_called_once()

        with mock.patch.object(uow.session, "rollback") as rollback:
            with pytest.raises(ValueError):
                with uow:
                    raise ValueError("boom")
            rollback.assert_called_once()
    finally:
        close_all()


def test_unitofwork_defers_to_teardown_in_request(app):
    """Inside a request, the UoW shares the request session and is a no-op on
    exit: commit/rollback is deferred to ``teardown_request`` and the session
    stays alive (lazy loading) for the rest of the request."""
    with app.test_request_context():
        session = get_db_session()  # mirrors init_request_session
        with mock.patch.object(session, "commit") as commit:
            with UnitOfWork() as uow:
                assert uow.session is session
                assert uow._manage is False
            # Exiting the block is a no-op in a request — teardown commits later.
            commit.assert_not_called()

        # Session is still usable after the block — not closed by the UoW.
        assert session.execute(sa.text("SELECT 1")).scalar() == 1
