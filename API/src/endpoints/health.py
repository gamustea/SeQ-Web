"""
endpoints/health.py
───────────────────
Blueprint de salud. Sirve el endpoint /say-hello sin autenticación,
útil como probe de liveness en contenedores o balanceadores de carga.
"""

from flask import Blueprint, jsonify
from src.misc.logging import SecOpsLogger
from ._shared import limiter

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
