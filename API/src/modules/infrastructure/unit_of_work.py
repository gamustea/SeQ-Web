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

from typing import Optional

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from src.modules.infrastructure import database


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

        Args:
            session: Optional existing SQLAlchemy session. If not provided,
                        a new session is obtained from the database module.
        """
        if session is not None:
            self.session = session
            self._owns_session = False
        else:
            self.session = database.get_session()
            self._owns_session = True

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
            self.commit()
        else:
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
            if self._owns_session:
                try:
                    self.session.close()
                    self.session = database.get_session()
                except Exception:
                    pass
            raise RuntimeError(
                f"Rollback failed, session has been recreated: {rollback_err}"
            ) from rollback_err

    def close(self) -> None:
        """
        Close the session if this UoW owns it.

        expunge_all() is called before closing so that ORM objects returned
        by queries remain accessible after the UoW exits. Their already-loaded
        attributes (including eagerly loaded relationships) stay intact, but
        any subsequent lazy load attempt will raise DetachedInstanceError —
        which is the correct and expected behaviour outside a session scope.

        Safe to call multiple times; subsequent calls are no-ops.
        """
        if self._owns_session and self.session is not None:
            try:
                self.session.expunge_all()
                self.session.close()
                database.close_all()
            finally:
                self.session = None