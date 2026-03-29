"""
run.py — Punto de entrada de la API SeQ
════════════════════════════════════════
Responsabilidades de este fichero:
  1. Crear la aplicación Flask.
  2. Configurar CORS y rate limiting.
  3. Registrar los blueprints (via endpoints.register_blueprints).
  4. Instalar manejadores de error globales.
  5. Arrancar el servidor de desarrollo si se ejecuta directamente.

Toda la lógica de rutas vive en el paquete `endpoints/`.
"""

import os

from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from src.endpoints import register_blueprints
from src.misc.logging import SecOpsLogger

# ── Logger ────────────────────────────────────────────────────────────────────

_logger = SecOpsLogger(name="APIMain").get_logger()


# ── Factory de aplicación ─────────────────────────────────────────────────────

def create_app() -> Flask:
    """
    Crea y configura la aplicación Flask.

    Usar el patrón Application Factory facilita los tests de integración:
    cada test puede instanciar su propio `app` sin efectos secundarios globales.
    """
    app = Flask(__name__)

    _configure_cors(app)
    _configure_rate_limiting(app)
    register_blueprints(app)
    _register_error_handlers(app)

    _logger.info("Aplicación SeQ iniciada correctamente")
    return app


# ── CORS ──────────────────────────────────────────────────────────────────────

def _configure_cors(app: Flask) -> None:
    """
    Restringe los orígenes permitidos al valor de la variable de entorno
    ALLOWED_ORIGINS (lista separada por comas).  En local se permite
    http://localhost:8080 y el origen del frontend de desarrollo.
    """
    raw     = os.environ.get("ALLOWED_ORIGINS", "http://localhost:8080")
    origins = [o.strip() for o in raw.split(",") if o.strip()]
    origins.append("http://127.0.0.1:3000")   # dev frontend
    CORS(app, origins=origins, supports_credentials=True)


# ── Rate limiting ─────────────────────────────────────────────────────────────

def _configure_rate_limiting(app: Flask) -> None:
    """
    Aplica límites globales para prevenir fuerza bruta y DDoS básico.
    El límite de /oauth/token se refina dentro del propio blueprint.
    """
    Limiter(
        get_remote_address,
        app=app,
        default_limits=["200 per day", "50 per hour"],
        storage_uri="memory://",
    )


# ── Manejadores de error globales ─────────────────────────────────────────────

def _register_error_handlers(app: Flask) -> None:
    """
    Manejadores de error a nivel de aplicación.

    Los errores de negocio (ValidationError, ScanNotFoundError, …) se capturan
    dentro de cada blueprint; estos manejadores actúan como última red de seguridad
    para errores HTTP puros (404 de ruta, 405, 500 inesperado).
    """

    @app.errorhandler(404)
    def not_found(error):
        _logger.warning(f"Ruta no encontrada: {request.method} {request.url}")
        return jsonify({
            "error":   "not_found",
            "message": "La ruta solicitada no existe",
            "path":    request.path,
        }), 404

    @app.errorhandler(405)
    def method_not_allowed(error):
        _logger.warning(f"Método no permitido: {request.method} {request.url}")
        return jsonify({
            "error":          "method_not_allowed",
            "message":        f"El método {request.method} no está permitido en esta ruta",
            "allowedMethods": list(error.valid_methods) if hasattr(error, "valid_methods") else [],
        }), 405

    @app.errorhandler(429)
    def too_many_requests(error):
        _logger.warning(f"Rate limit superado: {request.remote_addr}")
        return jsonify({
            "error":   "too_many_requests",
            "message": "Has superado el límite de peticiones. Espera un momento e inténtalo de nuevo.",
        }), 429

    @app.errorhandler(500)
    def internal_error(error):
        _logger.error(f"Error interno del servidor: {error}", exc_info=True)
        return jsonify({
            "error":   "internal_server_error",
            "message": "Ha ocurrido un error inesperado en el servidor.",
        }), 500


# ── Arranque ──────────────────────────────────────────────────────────────────

app = create_app()

if __name__ == "__main__":
    # debug=True NUNCA en producción — se controla con la variable de entorno.
    debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(debug=debug_mode, host="0.0.0.0", port=5000)
