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

import ipaddress
import socket
from functools import wraps
from urllib.parse import urlparse
from typing import Tuple, Optional

from flask import request

from ._exceptions import MissingParameterError, MissingJsonBodyError


limiter = None
_DNS_TIMEOUT = 3.0



# =========================================================================
# HELPERS
# =========================================================================

def normalize_target(
    user_input: str,
    resolve_hostname: bool = False
) -> Tuple[Optional[str], Optional[str]]:
    """
    Normaliza el target del usuario a IP + hostname.
    Acepta IPs, dominios o URLs completas (http://, https://).

    Args:
        user_input:         IP, dominio o URL completa.
        resolve_hostname:   Si es True y el input es una IP, intenta resolver
                            el hostname vía reverse DNS (con timeout acotado).
                            Si es False, el hostname se omite (se devuelve la IP
                            también en esa posición). Por defecto False.
        dns_timeout:        Segundos máximos para la resolución DNS inversa.

    Returns:
        (ip, hostname): hostname == ip cuando no se resuelve o resolve_hostname=False.
    """

    def _gethostbyaddr_with_timeout(ip: str) -> Optional[str]:
        """
        Wrapper de socket.gethostbyaddr para resolución DNS inversa.
        Devuelve el hostname o None si falla.
        """
        try:
            return socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror, OSError):
            return None
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
            hostname = _gethostbyaddr_with_timeout(ip) or ip
        else:
            hostname = ip

    except ValueError:
        hostname = cleaned_input
        try:
            ip = socket.gethostbyname(hostname)
        except socket.gaierror as e:
            raise ValueError(f"No se pudo resolver '{user_input}': {e}") from e

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
# DATA PARSING
# =========================================================================

def require_json(f):
    """Decorador que valida y extrae el cuerpo JSON del request.

    Inyecta los datos validados en request.json_body para que el endpoint los use.
    Lanza MissingJsonBodyError si el Content-Type no es application/json
    o el JSON es inválido.

    Usage:
    >>> @require_json
    >>> def create_user():
    ...    data = request.json_body
    ...    username = require_str(data, "username")
    """
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not request.is_json:
            raise MissingJsonBodyError("Content-Type must be application/json")
        data = request.get_json(silent=True)
        if not data:
            raise MissingJsonBodyError("Request body must be JSON")
        request.json_body = data
        return f(*args, **kwargs)
    return wrapper

def require_str(data: dict, field: str) -> str:
    """Extrae un campo obligatorio del JSON y lo valida como string no vacío.

    Args:
        data: Diccionario con los datos del request.
        field: Nombre del campo a extraer.

    Returns:
        str: El valor del campo, triminado de espacios.

    Raises:
        MissingParameterError: Si el campo falta o está vacío.
    """
    value = data.get(field)
    if not value or not str(value).strip():
        raise MissingParameterError(field)
    return str(value).strip()

def require_arg(arg: str) -> str:
    """Extrae el parámetro 'arg' de la query string como entero.

    Returns:
        str: Valor del argumento pedido

    Raises:
        MissingParameterError: Si el parámetro no existe.

    """
    value = request.args.get(arg)
    if not value:
        raise MissingParameterError(arg)

    return value
