

from functools import wraps
from flask import request, jsonify

from src.modules.misc import SecOpsLogger

from .managers import OAuthTokenManager

_logger = SecOpsLogger().get_logger()

def require_oauth_token(f):
    """
    Verifica el Bearer token en la cabecera Authorization.

    Inyecta `request.current_user_id` y `request.current_username`
    para que los handlers downstream los lean sin tocar la BD.
    Cierra siempre la sesión del OAuthTokenManager en un bloque
    finally para que la conexión se devuelva al pool aunque ocurra
    una excepción durante la verificación.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        oauth_manager = None
        try:
            auth_header = request.headers.get("Authorization")
            if not auth_header:
                return jsonify({
                    "error": "unauthorized",
                    "error_description": "Missing Authorization header",
                }), 401

            parts = auth_header.split()
            if len(parts) != 2 or parts[0].lower() != "bearer":
                return jsonify({
                    "error": "unauthorized",
                    "error_description": "Invalid Authorization header format. Use: Bearer <token>",
                }), 401

            token = parts[1]
            from .endpoints import get_oauth_manager
            with get_oauth_manager() as oauth_mg:
                payload = oauth_mg.verify_access_token(token)

            if not payload:
                return jsonify({
                    "error": "invalid_token",
                    "error_description": "The access token is invalid or expired",
                }), 401

            request.current_user_id = int(payload["sub"])   # type: ignore[attr-defined]
            request.current_username = payload["username"]  # type: ignore[attr-defined]

            return f(*args, **kwargs)

        except Exception as exc:
            _logger.error(F"Error durante la autenticación: {exc}")
            return jsonify({
                "error": "server_error",
                "error_description": "Authentication error",
            }), 500
        finally:
            if oauth_manager is not None:
                try:
                    oauth_manager.close_session()
                except Exception:
                    pass

    return decorated