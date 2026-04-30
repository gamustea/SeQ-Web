"""
Database engine and session factory module.

This module manages the SQLAlchemy engine and session factory as singletons,
providing thread-safe session creation and connection pool management.

All engine-level concerns live here: initialization, warmup, and teardown.
Session lifecycle (commit, rollback, close) remains in BaseManager.

Functions:
    initialize:     Initialize the engine and session factory (idempotent).
    get_session:    Return a new scoped session from the factory.
    warmup:         Pre-warm the connection pool with a lightweight query.
    close_all:      Remove all active sessions from the scoped session factory.

Module Variables:
    ENGINE:             SQLAlchemy engine singleton.
    SESSION_FACTORY:    Scoped session factory singleton.
"""

import time
import urllib.parse
from typing import Optional

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, scoped_session, sessionmaker


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

    ENGINE = create_engine(
        database_url,
        pool_pre_ping=True,
        pool_recycle=3600,
        echo=False,
        isolation_level="READ COMMITTED",
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
