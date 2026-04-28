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
from urllib.parse import urlparse

from flask import request, jsonify

from src.modules.exceptions import (
    ScanNotFoundError,
    UserNotFoundError,
    ValidationError,
    create_error_response,
)

limiter = None
_DNS_TIMEOUT = 3.0


def _gethostbyaddr_with_timeout(ip: str, timeout: float = _DNS_TIMEOUT) -> Optional[str]:
    """
    Wrapper de socket.gethostbyaddr con timeout explícito.
    Devuelve el hostname o None si falla o supera el tiempo límite.
    """
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(socket.gethostbyaddr, ip)
        try:
            return future.result(timeout=timeout)[0]
        except TimeoutError:
            return None
        except (socket.herror, socket.gaierror):
            return None

def normalize_target(
    user_input: str,
    resolve_hostname: bool = False,
    dns_timeout: float = _DNS_TIMEOUT,
) -> Tuple[Optional[str], Optional[str]]:
    """
    Normaliza el target del usuario a IP + hostname.
    Acepta IPs, dominios o URLs completas (http://, https://).

    Args:
        user_input:        IP, dominio o URL completa.
        resolve_hostname:  Si es True y el input es una IP, intenta resolver
                           el hostname vía reverse DNS (con timeout acotado).
                           Si es False, el hostname se omite (se devuelve la IP
                           también en esa posición). Por defecto False.
        dns_timeout:       Segundos máximos para la resolución DNS inversa.

    Returns:
        (ip, hostname): hostname == ip cuando no se resuelve o resolve_hostname=False.
    """
    cleaned_input = user_input.strip()

    if "://" in cleaned_input:
        parsed = urlparse(cleaned_input)
        if not parsed.netloc and parsed.path:
            cleaned_input = parsed.path.split('/')[0]
        else:
            cleaned_input = parsed.netloc.split(':')[0]
    else:
        cleaned_input = cleaned_input.split(':')[0].split('/')[0]

    ip: Optional[str] = None
    hostname: Optional[str] = None

    try:
        ip_obj = ipaddress.ip_address(cleaned_input)
        ip = str(ip_obj)

        if resolve_hostname:
            hostname = _gethostbyaddr_with_timeout(ip, dns_timeout) or ip
        else:
            hostname = ip

    except ValueError:
        hostname = cleaned_input
        try:
            ip = socket.gethostbyname(hostname)
        except socket.gaierror as e:
            raise ValueError(f"No se pudo resolver '{user_input}': {e}")

    return ip, hostname

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