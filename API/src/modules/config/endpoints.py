"""
config/endpoints.py
Endpoints API para gestión de configuración de SecOps.
Registrado en /config.

GET /config    — Obtiene toda la configuración
PUT /config    — Actualiza la configuración

Autenticación: Bearer token requerido.
"""

from flask import Blueprint, jsonify, request
from contextlib import contextmanager

from src.modules.exceptions import (
    ExceptionHandler,
    create_error_response,
)
from src.modules.misc import SecOpsLogger
from src.modules.users import require_oauth_token
from src.modules.shared import limiter

from .managers import ConfigManager


config_bp = Blueprint("config", __name__)
_logger = SecOpsLogger("config").get_logger()


@contextmanager
def get_config_manager():
    """Context manager para ConfigManager."""
    cm = ConfigManager()
    try:
        yield cm
    finally:
        cm.close_session()


@config_bp.get("")
@require_oauth_token
@limiter.limit("30 per hour; 100 per day")
def get_config():
    """Obtiene toda la configuración de SecOpsConfig.json.

    Returns:
        200 — Configuración completa.
        {
            "general": {...},
            "sentinel": {...},
            "aegis": {...}
        }

    Example:
        curl -X GET https://api.example.com/config \\
        -H "Authorization: Bearer <token>"
    """
    try:
        with get_config_manager() as cm:
            config = cm.get_config()
        return jsonify(config), 200

    except FileNotFoundError as exc:
        return jsonify({"error": "config_not_found", "error_description": str(exc)}), 404
    except Exception as exc:
        _logger.error(f"Error obteniendo configuración: {exc}", exc_info=True)
        sec_exc = ExceptionHandler.wrap_exception(exc, logger=_logger)
        err, code = create_error_response(sec_exc, include_debug_info=False)
        return jsonify(err), code


@config_bp.put("")
@require_oauth_token
@limiter.limit("10 per hour; 20 per day")
def update_config():
    """Actualiza la configuración de SecOpsConfig.json.

    Args (JSON body):
        Objeto JSON completo con la nuova configuración.

    Returns:
        200 — Configuración actualizada.
        400 — Error de validación.

    Example:
        curl -X PUT https://api.example.com/config \\
        -H "Authorization: Bearer <token>" \\
        -H "Content-Type: application/json" \\
        -d '@config.json'
    """
    if not request.is_json:
        return jsonify({"error": "invalid_request", "error_description": "Content-Type must be application/json"}), 400

    new_config = request.get_json(silent=True)
    if not new_config:
        return jsonify({"error": "invalid_request", "error_description": "Request body must be JSON"}), 400

    try:
        with get_config_manager() as cm:
            config = cm.update_config(new_config)
        _logger.info("Configuración actualizada correctamente")
        return jsonify(config), 200

    except Exception as exc:
        _logger.error(f"Error actualizando configuración: {exc}", exc_info=True)
        sec_exc = ExceptionHandler.wrap_exception(exc, logger=_logger)
        err, code = create_error_response(sec_exc, include_debug_info=False)
        return jsonify(err), code