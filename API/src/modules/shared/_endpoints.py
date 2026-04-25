"""
endpoints/_shared.py
────────────────────
Utilidades compartidas por todos los blueprints:
    - Decorador de autenticación OAuth (require_oauth_token)
    - Helpers de acceso al usuario actual
    - Factoría de managers (DRY)
    - Función auxiliar de búsqueda de escaneos por ID
    - Constantes de validación centralizadas
    - Helper de construcción del PDFCreator
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

def _get_limiter():
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

def get_current_user_id() -> int:
    return request.current_user_id

def get_current_username() -> str:
    return request.current_username