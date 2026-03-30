"""
run.py — Punto de entrada de la API SeQ
════════════════════════════════════════
Responsabilidades de este fichero:
  1. Crear la aplicación Flask.
  2. Configurar CORS y rate limiting (via init_app del limiter de _shared).
  3. Registrar los blueprints (via endpoints.register_blueprints).
  4. Instalar manejadores de error globales.
  5. Gestionar el apagado graceful (SIGTERM / SIGINT).
  6. Arrancar el servidor de desarrollo si se ejecuta directamente.

Toda la lógica de rutas vive en el paquete `endpoints/`.
"""

import os
import signal
import sys

from flask import Flask, jsonify, request
from flask_cors import CORS

from src.endpoints import register_blueprints
from src.endpoints._shared import limiter
from src.misc.logging import SecOpsLogger


_logger = SecOpsLogger(name="APIMain").get_logger()

SHUTDOWN_TIMEOUT = 30

def _graceful_shutdown(signum, frame) -> None:
    sig_name = "SIGTERM" if signum == signal.SIGTERM else "SIGINT"
    _logger.info(f"[Shutdown] {sig_name} recibido — iniciando apagado graceful...")

    try:
        from src.logic.managers import ScanManager
        _logger.info(
            f"[Shutdown] Cancelando {len(ScanManager._running_tasks)} tarea(s) activa(s)..."
        )
        ScanManager.cancel_all_running(timeout=SHUTDOWN_TIMEOUT)
        _logger.info("[Shutdown] Todas las tareas finalizadas.")
    except Exception as e:
        _logger.error(f"[Shutdown] Error durante el apagado: {e}")

    _logger.info("[Shutdown] Proceso terminado.")
    sys.exit(0)

signal.signal(signal.SIGTERM, _graceful_shutdown)
signal.signal(signal.SIGINT,  _graceful_shutdown)

def create_app() -> Flask:
    app = Flask(__name__)

    _configure_cors(app)
    _configure_rate_limiting(app)
    register_blueprints(app)
    _register_error_handlers(app)

    _logger.info("Aplicación SeQ iniciada correctamente")
    return app

def _configure_cors(app: Flask) -> None:
    raw     = os.environ.get("ALLOWED_ORIGINS", "http://localhost:8080")
    origins = [o.strip() for o in raw.split(",") if o.strip()]
    origins.append("http://127.0.0.1:3000")
    CORS(app, origins=origins, supports_credentials=True)

def _configure_rate_limiting(app: Flask) -> None:
    """
    Asocia el único Limiter de la aplicación (definido en _shared.py)
    a esta instancia de Flask.

    NO se crea un segundo Limiter aquí: tener dos instancias provoca que
    Flask-Limiter aplique ambos default_limits y gane el más restrictivo,
    lo que generaba 429 con solo 4-5 escaneos en paralelo.
    """
    limiter.init_app(app)

def _register_error_handlers(app: Flask) -> None:
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


app = create_app()

if __name__ == "__main__":
    debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(debug=debug_mode, host="0.0.0.0", port=5000)
