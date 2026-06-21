"""
Unit of Work pattern for database session lifecycle management.

This module encapsulates a single database session and its transaction,
providing commit, rollback, and close operations with full error handling.

It is designed to be used as a context manager, ensuring the session is
always properly closed even in the presence of exceptions.

Classes:
    UnitOfWork: Manages a single session's lifecycle and transaction boundary.

Usage:
    # As a context manager (recommended):
    with UnitOfWork() as uow:
        repo = ScanRepository(uow)
        repo.save(scan)
        # Commits automatically on __exit__ if no exception was raised.

    # Manual control:
    uow = UnitOfWork()
    try:
        repo = ScanRepository(uow)
        repo.save(scan)
        uow.commit()
    except Exception:
        uow.rollback()
        raise
    finally:
        uow.close()
"""

from __future__ import annotations

import logging
from typing import Optional

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


import time
import urllib.parse

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import scoped_session, sessionmaker


ENGINE: Optional[Engine] = None
SESSION_FACTORY: Optional[scoped_session] = None


def initialize(database_url: Optional[str] = None) -> Engine:
    """
    Initialize the SQLAlchemy engine and session factory (idempotent).

    Creates a singleton engine with connection pooling configuration and a
    scoped session factory for thread-safe session management. Safe to call
    multiple times — subsequent calls are no-ops if already initialized.

    Args:
        database_url:   Optional database URL. If not provided, credentials
                        are read from the config_reading module (CR).

    Returns:
        The active SQLAlchemy engine instance.
    """
    global ENGINE, SESSION_FACTORY

    if ENGINE is not None:
        return ENGINE

    t0 = time.perf_counter()

    if database_url is None:
        from src.modules.system import config_reading as CR
        db_creds = CR.get_db_credentials()
        database_url = (
            f"{db_creds['dialect']}://"
            f"{db_creds['username']}:{urllib.parse.quote(db_creds['password'])}"
            f"@{db_creds['host']}:{db_creds['port']}/{db_creds['dbname']}"
        )

    from src.modules.system import config_reading as CR
    isolation_level = CR.get_db_isolation_level()

    ENGINE = create_engine(
        database_url,
        pool_pre_ping=True,
        pool_recycle=3600,
        echo=False,
        isolation_level=isolation_level,
    )

    SESSION_FACTORY = scoped_session(
        sessionmaker(
            bind=ENGINE,
            expire_on_commit=False,
            autoflush=True,
            autocommit=False,
        )
    )

    elapsed = time.perf_counter() - t0
    # Logger not injected here intentionally — this is infrastructure-level code.
    # Callers can log the elapsed time if needed.
    _ = elapsed

    return ENGINE


def get_session() -> Session:
    """
    Return a new (or existing scoped) session from the factory.

    Calls initialize() automatically if the factory has not been set up yet.

    Returns:
        A SQLAlchemy Session bound to the current thread/scope.
    """
    global SESSION_FACTORY

    if SESSION_FACTORY is None:
        initialize()

    return SESSION_FACTORY()


def warmup() -> None:
    """
    Pre-warm the connection pool by executing a trivial query.

    Ensures the first real database operation does not pay the cost of
    establishing a new connection. Safe to call at application startup.
    """
    global SESSION_FACTORY

    if SESSION_FACTORY is None:
        initialize()

    session = SESSION_FACTORY()
    session.execute(text("SELECT 1"))
    session.close()
    SESSION_FACTORY.remove()


def close_all() -> None:
    """
    Remove all active sessions from the scoped session factory.

    Useful during application shutdown or between tests to ensure no
    sessions are left open.
    """
    global SESSION_FACTORY

    if SESSION_FACTORY is not None:
        SESSION_FACTORY.remove()


class UnitOfWork:
    """
    Manages the lifecycle of a single SQLAlchemy session.

    Wraps one session and exposes commit / rollback / close operations
    with consistent error handling. Supports use as a context manager,
    committing on clean exit and rolling back on exception.

    Attributes:
        session:        The underlying SQLAlchemy session.
        _owns_session:  True if this UoW created the session (and must close it).

    Example:
    >>> with UnitOfWork() as uow:
    ...     scan_repo = ScanRepository(uow)
    ...     scan_repo.save(NmapScan(target="10.0.0.1", user_id=1))
    """

    def __init__(self, session: Optional[Session] = None) -> None:
        """
        Initialize the Unit of Work with an optional existing session.

        In a Flask request context, reuses ``g.db_session`` (if present)
        so that reads and writes share the same request-scoped session.
        In background threads, creates and owns its own session.

        Args:
            session: Optional existing SQLAlchemy session. If not provided,
                     behaviour depends on the runtime context.
        """
        if session is not None:
            self.session = session
            self._owns_session = False
        else:
            self.session = get_session()
            self._owns_session = True

        # If we're in a Flask request that already has a session, reuse it.
        # This prevents UnitOfWork from closing the request-scoped session
        # on __exit__, which would break lazy loading for the rest of the
        # request.
        self._try_share_request_session()

    def _try_share_request_session(self) -> None:
        """If running inside a Flask request with an active g.db_session,
        reuse it and relinquish ownership so close() is a no-op.

        The check is intentionally ``has_request_context()`` and **not**
        ``has_app_context()``. Session sharing is only safe within the HTTP
        request lifecycle, where ``before_request`` opens ``g.db_session`` and
        ``teardown_request`` commits/closes it. Background RQ workers run under
        a long-lived *application* context (see taskqueue/worker.py) with no
        request and therefore no teardown hook: if we shared ``g.db_session``
        there, ``__exit__`` would relinquish ownership and never commit, so
        every write performed in a worker job would be silently discarded."""
        try:
            from flask import g, has_request_context
        except ImportError:
            return
        try:
            if has_request_context() and "db_session" in g:
                if not self._owns_session:
                    return  # externally provided session
                self.session = g.db_session
                self._owns_session = False
        except RuntimeError:
            pass  # working outside of application context

    # =========================================================================
    # CONTEXT MANAGER
    # =========================================================================

    def __enter__(self) -> UnitOfWork:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        """
        Commit on clean exit, rollback on exception, always close.

        Returns:
            False — exceptions are never suppressed.
        """
        if exc_type is None:
            if self._owns_session:
                self.commit()
        else:
            if self._owns_session:
                self.rollback()
        self.close()
        return False

    # =========================================================================
    # TRANSACTION OPERATIONS
    # =========================================================================

    def commit(self) -> None:
        """
        Commit the current transaction.

        Raises:
            SQLAlchemyError: If the commit fails. A rollback is performed
                             automatically before re-raising.
        """
        try:
            self.session.commit()
        except SQLAlchemyError as e:
            self.rollback()
            logger.error("Commit failed", exc_info=True)
            raise SQLAlchemyError(f"Commit failed: {e}") from e

    def rollback(self) -> None:
        """
        Roll back the current transaction.

        If the rollback itself fails, the session is closed and recreated
        so that subsequent operations on this UoW can still proceed.
        """
        try:
            if self.session is not None:
                self.session.rollback()
        except Exception as rollback_err:
            logger.error("Rollback failed", exc_info=True)
            if self._owns_session:
                try:
                    self.session.close()
                    self.session = get_session()
                except Exception as e:
                    logger.exception("Failed to recreate session after close")
            raise RuntimeError(
                f"Rollback failed, session has been recreated: {rollback_err}"
            ) from rollback_err

    def close(self) -> None:
        """
        Close the session if this UoW owns it.

        With the session-per-request architecture, the session is no longer
        expunged or removed from the scoped registry here — that is handled
        by the Flask teardown_request hook. Objects remain attached to the
        session for the remainder of the request, allowing lazy loading to
        work without eager-loading workarounds.

        Safe to call multiple times; subsequent calls are no-ops.
        """
        if self._owns_session and self.session is not None:
            try:
                self.session.close()
            finally:
                self.session = None