"""
health_endpoints.py
══════════════════════════════════════════════════════════════════════════════

Blueprint de salud y estado del sistema. Registrado en /.

Este módulo proporciona endpoints para verificar la disponibilidad del servicio
y obtener métricas del sistema. NO requieren autenticación.

────────────────────────────────────────────────────────────────────────────────
ENDPOINTS DISPONIBLES
────────────────────────────────────────────────────────────────────────────────

Salud
    GET /say-hello — Probe de liveness (sin autenticación)
    GET /status    — Estado del sistema (CPU, memoria, disco)

────────────────────────────────────────────────────────────────────────────────
LIMITACIONES
────────────────────────────────────────────────────────────────────────────────

• /say-hello: 60/minute (límite para probes de liveness)
• /status: sin límite

────────────────────────────────────────────────────────────────────────────────
EJEMPLOS DE USO
────────────────────────────────────────────────────────────────────────────────

# Probe de liveness
curl https://api.example.com/say-hello

# Estado del sistema
curl https://api.example.com/status

────────────────────────────────────────────────────────────────────────────────
RESPuestas
────────────────────────────────────────────────────────────────────────────────

/say-hello:
{
    "message": "You did it! You reached an endpoint!",
    "status": "ok",
    "version": "3.2"
}

/status:
{
    "cpu": {"percent": 25.5},
    "memory": {
        "total": 17179869184,
        "available": 8589934592,
        "percent": 50.0
    },
    "disk": {
        "total": 500000000000,
        "used": 250000000000,
        "percent": 50.0
    },
    "timestamp": "2026-04-11T10:30:00Z"
}

────────────────────────────────────────────────────────────────────────────────
"""

import psutil

from flask import Blueprint, jsonify
from src.modules.misc import SecOpsLogger
from src.modules.shared import limiter

health_bp = Blueprint("health", __name__)
_logger   = SecOpsLogger("health").get_logger()


@health_bp.get("/say-hello")
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


@health_bp.get("/status")
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
