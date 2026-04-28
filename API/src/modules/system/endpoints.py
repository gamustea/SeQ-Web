"""
system/endpoints.py
Endpoints API para gestión de configuración de SecOps.
Registrado en /config.

GET /config    — Obtiene toda la configuración
PUT /config    — Actualiza la configuración

Autenticación: Bearer token requerido.
"""

from flask import Blueprint, jsonify, request

from src.modules.exceptions import (
    ExceptionHandler,
    create_error_response,
)
from src.modules.system.logging import SecOpsLogger
from src.modules.users import require_oauth_token
from src.modules.shared import limiter

import src.modules.system.config_reading as CR


system_bp = Blueprint("system", __name__)
_logger = SecOpsLogger("system").get_logger()


@system_bp.get("/say-hello")
@limiter.limit("60 per minute")
def hello():
    """Probe de liveness para verificar disponibilidad del servicio.

    Este endpoint no requiere autenticación y es útil para:
    - Health checks en contenedores
    - Probe de liveness en Kubernetes
    - Verificar que la API está respondiendo

    Returns:
        200 — Servicio disponible.
            {
                "message": "You did it! You reached an endpoint!",
                "status": "ok",
                "version": "3.2"
            }

    Example:
        curl https://api.example.com/say-hello
    """
    _logger.info("GET /say-hello")
    return jsonify({
        "message": "You did it! You reached an endpoint!",
        "status":  "ok",
        "version": "3.2",
    }), 200


@system_bp.get("/status")
def status():
    """Obtiene información de estado del sistema: CPU, memoria y disco.

    Este endpoint no requiere autenticación y proporciona métricas del
    servidor donde se ejecuta la API.

    Returns:
        200 — Métricas del sistema.
            {
                "cpu": {"percent": 25.5},
                "memory": {
                    "total": 17179869184,
                    "available": 8589934592,
                    "percent": 50.0,
                    "used": 8589934592,
                    "free": 8589934592
                },
                "disk": {
                    "total": 500000000000,
                    "used": 250000000000,
                    "free": 250000000000,
                    "percent": 50.0
                },
                "status": "ok"
            }

    Example:
        curl https://api.example.com/status
    """
    _logger.info("GET /status")
    
    cpu_percent = psutil.cpu_percent(interval=1)
    
    memory = psutil.virtual_memory()
    memory_info = {
        "total": memory.total,
        "available": memory.available,
        "percent": memory.percent,
        "used": memory.used,
        "free": memory.free
    }
    
    # Obtener información de disco
    disk = psutil.disk_usage('/')
    disk_info = {
        "total": disk.total,
        "used": disk.used,
        "free": disk.free,
        "percent": disk.percent
    }
    
    return jsonify({
        "cpu": {
            "percent": cpu_percent
        },
        "memory": memory_info,
        "disk": disk_info,
        "status": "ok"
    }), 200


@system_bp.get("")
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
        config = CR.get_full_config()
        return jsonify(config), 200

    except FileNotFoundError as exc:
        return jsonify({"error": "config_not_found", "error_description": str(exc)}), 404
    except Exception as exc:
        _logger.error(f"Error obteniendo configuración: {exc}", exc_info=True)
        sec_exc = ExceptionHandler.wrap_exception(exc, logger=_logger)
        err, code = create_error_response(sec_exc, include_debug_info=False)
        return jsonify(err), code


@system_bp.put("")
@require_oauth_token
@limiter.limit("10 per hour; 20 per day")
def update_config():
    """Actualiza la configuración de SecOpsConfig.json.

    Args (JSON body):
        Objeto JSON completo con la nueva configuración.

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
        config = CR.save_full_config(new_config)
        _logger.info("Configuración actualizada correctamente")
        return jsonify(config), 200

    except Exception as exc:
        _logger.error(f"Error actualizando configuración: {exc}", exc_info=True)
        sec_exc = ExceptionHandler.wrap_exception(exc, logger=_logger)
        err, code = create_error_response(sec_exc, include_debug_info=False)
        return jsonify(err), code