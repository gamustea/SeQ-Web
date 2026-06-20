"""
Database connection and session management module.

This module provides the base manager class for all database operations,
offering thread-safe session handling and common utility methods for
CRUD operations.

Classes:
    BaseManager: Base class for all managers requiring database access.

Module Variables:
    ENGINE: SQLAlchemy engine instance (global singleton).
    SESSION_FACTORY: Scoped session factory for thread-safe sessions.
"""

import logging
from typing import Optional, Any, List

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from src.modules.infrastructure import unit_of_work as _uow


ENGINE = None
SESSION_FACTORY = None

logger = logging.getLogger(__name__)


class BaseManager:
    """
    Base class for all managers requiring database access.

    Provides thread-safe session management and utility methods for
    common database operations. Handles connection pooling, session
    lifecycle, and transaction management.

    Attributes:
        session: SQLAlchemy session instance for database operations.
        _owns_session: Boolean indicating if the manager owns the session.

    Example:
    >>> class UserManager(BaseManager):
    ...     def get_user(self, user_id):
    ...         return self._get_by_field(User, 'id', user_id)
    """

    def __init__(self, session: Optional[Session] = None):
        """
        Initialize the manager with an optional existing session.

        Args:
            session: Optional existing SQLAlchemy session. If not provided,
                        a new session will be created from the factory.
        """
        if session is not None:
            self.session = session
            self._owns_session = False
        else:
            self.session = _uow.get_session()
            self._owns_session = True


    # =========================================================================
    # SESSION LIFECYCLE
    # =========================================================================

    @staticmethod
    def warmup_connection(engine=None) -> None:
        """Pre-warm the connection pool by executing a trivial query."""
        _uow.warmup()

    @staticmethod
    def close_all_sessions() -> None:
        """Remove all active sessions from the scoped session factory."""
        _uow.close_all()

    def close_session(self) -> None:
        """Close the current session if this manager owns it."""
        if self._owns_session and self.session is not None:
            try:
                self.session.close()
                _uow.close_all()
            except Exception as e:
                logger.warning(f"Error al cerrar sesión: {e}", exc_info=True)

    @staticmethod
    def _initialize_engine(database_url: Optional[str] = None):
        """
        Initialize the database engine (delegates to unit_of_work.initialize).

        Kept for backwards compatibility with call sites in run.py.

        Args:
            database_url: Optional database URL override.

        Returns:
            The active SQLAlchemy engine instance.
        """
        global ENGINE, SESSION_FACTORY
        engine = _uow.initialize(database_url)
        ENGINE = engine
        SESSION_FACTORY = _uow.SESSION_FACTORY
        return engine


    # =========================================================================
    # QUERY METHODS
    # =========================================================================

    def _exists(self, model, field: str, value: Any) -> bool:
        """
        Check if a record exists in the database.

        Args:
            model: SQLAlchemy model class to query.
            field: Name of the field to filter by.
            value: Value to match in the filter.

        Returns:
            True if at least one matching record exists, False otherwise.
        """
        self._check_session()

        return self.session.query(model).filter(
            getattr(model, field) == value
        ).count() > 0

    def _get_by_field(self, model, field: str, value: Any) -> Optional[Any]:
        """
        Retrieve a single record by field value.

        Args:
            model: SQLAlchemy model class to query.
            field: Name of the field to filter by.
            value: Value to match in the filter.

        Returns:
            The matching model instance, or None if not found.

        Raises:
            Exception: If an error occurs during database query.
        """
        self._check_session()

        try:
            obj = self.session.query(model).filter(
                getattr(model, field) == value
            ).one_or_none()
            return obj

        except Exception as e:
            logger.error(f"Error obtaining {model.__name__}: {e}", exc_info=True)
            raise

    def _get_all(self, model) -> List[Any]:
        """
        Retrieve all records of a given model.

        Args:
            model: SQLAlchemy model class to query.

        Returns:
            List of all model instances.

        Raises:
            Exception: If an error occurs during database query.
        """
        self._check_session()

        try:
            objects = self.session.query(model).all()
            logger.info(f"Se obtained {len(objects)} {model.__name__}s")
            return objects

        except Exception as e:
            logger.error(f"Error obtaining {model.__name__}s: {e}", exc_info=True)
            raise

    def _get_children(self, model, foreign_key, parent_id):
        """
        Retrieve all child records related to a parent.

        Args:
            model: SQLAlchemy model class to query.
            foreign_key: Name of the foreign key field in the child model.
            parent_id: ID of the parent record.

        Returns:
            List of matching child model instances.
        """
        return self.session.query(model).filter(getattr(model, foreign_key) == parent_id).all()


    # =========================================================================
    # CRUD METHODS
    # =========================================================================

    def _save(self, obj):
        """
        Save a new object to the database.

        Adds the object to the session, commits the transaction, and
        refreshes the object to get the generated ID.

        Args:
            obj: SQLAlchemy model instance to save.

        Returns:
            The saved model instance with updated attributes.
        """
        self.session.add(obj)
        self._safe_commit()
        self.session.refresh(obj)
        return obj

    def _update(self, obj):
        """
        Update an existing object in the database.

        Flushes changes to the database and commits the transaction.

        Args:
            obj: SQLAlchemy model instance to update.

        Returns:
            The updated model instance.
        """
        self.session.flush()
        self._safe_commit()
        return obj

    def _delete(self, obj: Any) -> None:
        """
        Delete an object from the database.

        Args:
            obj: SQLAlchemy model instance to delete.

        Raises:
            Exception: If an error occurs during deletion or commit.
        """
        self._check_session()

        try:
            self.session.delete(obj)
            self._safe_commit()

        except Exception as e:
            self._safe_rollback()
            logger.error(f"Error deleting {obj}: {e}", exc_info=True)
            raise


    # =========================================================================
    # TRANSACTION METHODS
    # =========================================================================

    def _check_session(self):
        """
        Verify that a session is available for database operations.

        Raises:
            Exception: If no session is available.
        """
        if self.session is None:
            raise Exception("La sesión de base de datos no está establecida.")

    def _safe_commit(self):
        """
        Commit the current transaction with error handling.

        Returns:
            True if commit was successful.

        Raises:
            SQLAlchemyError: If commit fails, performs rollback first.
        """
        try:
            self.session.commit()
            return True
        except SQLAlchemyError as err:
            logger.error(f"Error durante commit: {err}", exc_info=True)
            self._safe_rollback()
            raise

    def _safe_rollback(self):
        """
        Perform a rollback with error handling and session recovery.

        Attempts to rollback the current transaction. If the rollback
        fails or an error occurs, attempts to close the current session
        and create a new one to ensure subsequent operations can proceed.
        """
        try:
            if self.session is not None:
                self.session.rollback()
                logger.debug("Rollback ejecutado exitosamente")
        except Exception as e:
            logger.warning(f"Error durante rollback: {e}", exc_info=True)
            try:
                if self._owns_session:
                    self.session.close()
                    global SESSION_FACTORY
                    if SESSION_FACTORY is not None:
                        self.session = SESSION_FACTORY()
                        logger.info("Sesión recreada después de error en rollback")
            except Exception as recreate_err:
                logger.error(f"No se pudo recrear la sesión: {recreate_err}", exc_info=True)
