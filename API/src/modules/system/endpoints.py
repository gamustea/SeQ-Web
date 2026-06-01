import psutil

from flask_smorest import Blueprint as SmorestBlueprint
from flask import request

from src.modules.users.services.permissions import Role
from src.modules.shared._endpoints import limiter
from src.modules.shared._exceptions import (
    handle_exceptions,
    IllegalStateError,
    ValidationError,
)
from src.modules.shared.schemas import ErrorSchema
from src.modules.system.logging import SecOpsLogger
from src.modules.users import require_oauth_token, require_role
from .schemas import HelloResponseSchema, SystemStatusSchema

import src.modules.system.config_reading as CR


system_blp = SmorestBlueprint(
    "system", __name__,
    description="Estado, configuración y health check del sistema"
)
_logger = SecOpsLogger("system").get_logger()


@system_blp.get("/say-hello")
@system_blp.response(200, HelloResponseSchema, description="Health check")
@limiter.limit("60 per minute")
def hello():
    """Health check del servicio"""
    _logger.info("GET /say-hello")
    return {
        "message": "You did it! You reached an endpoint!",
        "status":  "ok",
        "version": "3.2",
    }


@system_blp.get("/status")
@system_blp.response(200, SystemStatusSchema, description="System metrics")
@system_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@system_blp.alt_response(403, schema=ErrorSchema, description="Insufficient role")
@limiter.limit("30 per hour; 100 per day")
@require_oauth_token
@require_role(minimum_role=Role.ADMIN)
def status():
    """Métricas en tiempo real del servidor (CPU, memoria, disco)"""
    _logger.info("GET /status")

    cpu_percent = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')

    return {
        "cpu": {"percent": cpu_percent},
        "memory": {
            "total": memory.total,
            "available": memory.available,
            "percent": memory.percent,
            "used": memory.used,
            "free": memory.free,
        },
        "disk": {
            "total": disk.total,
            "used": disk.used,
            "free": disk.free,
            "percent": disk.percent,
        },
        "status": "ok",
    }


@system_blp.get("")
@system_blp.response(200, description="Full SecOps configuration")
@system_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@system_blp.alt_response(403, schema=ErrorSchema, description="Insufficient role")
@limiter.limit("30 per hour; 100 per day")
@require_oauth_token
@require_role(minimum_role=Role.ADMIN)
@handle_exceptions(default_exception=IllegalStateError, logger=_logger)
def get_config():
    """Obtiene toda la configuración de SecOpsConfig.json"""
    config = CR.get_full_config()
    return config


@system_blp.put("")
@system_blp.response(200, description="Updated configuration")
@system_blp.alt_response(400, schema=ErrorSchema, description="Invalid body")
@system_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@system_blp.alt_response(403, schema=ErrorSchema, description="Insufficient role")
@limiter.limit("10 per hour; 20 per day")
@require_oauth_token
@require_role(minimum_role=Role.ADMIN)
@handle_exceptions(default_exception=IllegalStateError, logger=_logger)
def update_config():
    """Actualiza la configuración de SecOpsConfig.json"""
    if not request.is_json:
        raise ValidationError("Content-Type must be application/json")

    new_config = request.get_json(silent=True)
    if not new_config:
        raise ValidationError("Request body must be JSON")

    config = CR.save_full_config(new_config)
    _logger.info("Configuracion actualizada correctamente")
    return config
