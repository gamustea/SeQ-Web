"""
Shared utilities for all API endpoints.

This module provides common functionality used across all blueprints:
- OAuth authentication decorator (require_oauth_token)
- Current user access helpers
- Manager factory (DRY principle)
- Scan lookup helper by ID
- Centralized validation constants
- PDFCreator builder helper

Module Variables:
    limiter: Global rate limiter instance (lazy initialization).
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from functools import wraps
from typing import Optional, Tuple, Any

from flask import request, jsonify

from src.modules.exceptions import (
    ScanNotFoundError,
    UserNotFoundError,
    ValidationError,
    create_error_response,
)


limiter = None


# =========================================================================
# RATE LIMITING
# =========================================================================

def _get_limiter():
    """
    Get or create the global rate limiter instance.

    Initializes the Flask-Limiter with memory storage on first access.
    Used for rate limiting endpoint calls to prevent abuse.

    Returns:
        Limiter: Configured Flask-Limiter instance.
    """
    global limiter
    if limiter is None:
        from flask_limiter import Limiter
        from flask_limiter.util import get_remote_address
        limiter = Limiter(
            get_remote_address,
            default_limits=[],
            storage_uri="memory://",
        )
    return limiter


# =========================================================================
# USER CONTEXT
# =========================================================================

def get_current_user_id() -> int:
    """
    Get the current authenticated user's ID from the request context.

    Returns:
        int: ID of the currently authenticated user.

    Raises:
        AttributeError: If no user is authenticated (token not parsed).
    """
    return request.current_user_id

def get_current_username() -> str:
    """
    Get the current authenticated username from the request context.

    Returns:
        str: Username of the currently authenticated user.

    Raises:
        AttributeError: If no user is authenticated (token not parsed).
    """
    return request.current_username