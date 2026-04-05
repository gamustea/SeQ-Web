"""
endpoints/health.py
───────────────────
Blueprint de salud. Sirve el endpoint /say-hello sin autenticación,
útil como probe de liveness en contenedores o balanceadores de carga.
"""

from flask import Blueprint, jsonify
from src.misc.logging import SecOpsLogger
from ._shared import limiter
import psutil

health_bp = Blueprint("health", __name__)
_logger   = SecOpsLogger("health").get_logger()


@health_bp.get("/say-hello")
@limiter.limit("60 per minute")
def hello():
    """Probe de liveness — no requiere autenticación."""
    _logger.info("GET /say-hello")
    return jsonify({
        "message": "You did it! You reached an endpoint!",
        "status":  "ok",
        "version": "3.2",
    }), 200


@health_bp.get("/status")
def status():
    """Endpoint para obtener información de estado del sistema: CPU, memoria y disco."""
    _logger.info("GET /status")
    
    # Obtener información de CPU
    cpu_percent = psutil.cpu_percent(interval=1)
    
    # Obtener información de memoria
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
