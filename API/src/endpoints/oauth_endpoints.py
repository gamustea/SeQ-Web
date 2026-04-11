"""
oauth_endpoints.py
══════════════════════════════════════════════════════════════════════════════

Blueprint OAuth 2.0. Registrado en /oauth.

Este módulo implementa el flujo de autenticación OAuth 2.0 con soporte para:
    • Password Grant — login con username/password
    • Refresh Token — renovación de access token
    • Revocación de tokens

────────────────────────────────────────────────────────────────────────────────
ENDPOINTS DISPONIBLES
────────────────────────────────────────────────────────────────────────────────

Autenticación
    POST /oauth/token       — Login (password grant) o renovación (refresh_token)
    POST /oauth/revoke      — Revocar el token actual [autenticado]
    POST /oauth/revoke-all  — Revocar todos los tokens del usuario [autenticado]

────────────────────────────────────────────────────────────────────────────────
AUTENTICACIÓN
────────────────────────────────────────────────────────────────────────────────

El endpoint /oauth/token NO requiere autenticación previa (es el flujo de login).
Los endpoints /oauth/revoke y /oauth/revoke-all requieren token OAuth2 válido.

Límites de tasa:
    • /oauth/token: 20/hour, 100/day
    • /oauth/revoke: sin límite (requiere token válido)
    • /oauth/revoke-all: sin límite (requiere token válido)

────────────────────────────────────────────────────────────────────────────────
FLUJOS DE AUTENTICACIÓN
────────────────────────────────────────────────────────────────────────────────

Password Grant (login):
{
    "grantType": "password",
    "username": "admin",
    "password": "password123"
}

Refresh Token Grant (renovación):
{
    "grantType": "refresh_token",
    "refresh_token": "eyJ..."
}

────────────────────────────────────────────────────────────────────────────────
EJEMPLOS DE USO
────────────────────────────────────────────────────────────────────────────────

# Login con credenciales
curl -X POST https://api.example.com/oauth/token \
  -H "Content-Type: application/json" \
  -d '{"grantType": "password", "username": "admin", "password": "password123"}'

# Renovación de token
curl -X POST https://api.example.com/oauth/token \
  -H "Content-Type: application/json" \
  -d '{"grantType": "refresh_token", "refresh_token": "eyJ..."}'

# Revocar token actual
curl -X POST https://api.example.com/oauth/revoke \
  -H "Authorization: Bearer <access_token>"

# Revocar todos los tokens
curl -X POST https://api.example.com/oauth/revoke-all \
  -H "Authorization: Bearer <access_token>"

────────────────────────────────────────────────────────────────────────────────
RESPUESTAS
────────────────────────────────────────────────────────────────────────────────

Éxito (password grant):
{
    "access_token": "eyJ...",
    "token_type": "Bearer",
    "expires_in": 900,
    "refresh_token": "eyJ..."
}

Éxito (refresh grant):
{
    "access_token": "eyJ...",
    "token_type": "Bearer",
    "expires_in": 900
}

Error:
{
    "error": "invalid_grant",
    "error_description": "Invalid username or password"
}

────────────────────────────────────────────────────────────────────────────────
"""

from flask import Blueprint, jsonify, request
from werkzeug.exceptions import BadRequest

from src.logic.managers import ACCESS_TOKEN_EXPIRE_MINUTES
from src.misc import SecOpsLogger

from ._shared import (
    get_oauth_manager,
    get_user_manager,
    get_current_user_id,
    get_current_username,
    require_oauth_token,
    limiter
)

oauth_bp = Blueprint("oauth", __name__)
_logger  = SecOpsLogger("oauth").get_logger()


# ── POST /oauth/token ────────────────────────────────────────────────────

@oauth_bp.post("/token")
@limiter.limit("20 per hour; 100 per day")
def oauth_token():
    """Emite tokens OAuth 2.0.

    Args (JSON body):
        grantType (str): "password" o "refresh_token"
        
        Para password grant:
            username (str): Nombre de usuario
            password (str): Contraseña
            
        Para refresh_token grant:
            refresh_token (str): Token de renovación

    Returns:
        200 (password grant):
            {
                "access_token": "eyJ...",
                "token_type": "Bearer",
                "expires_in": 900,
                "refresh_token": "eyJ..."
            }
        200 (refresh_token grant):
            {
                "access_token": "eyJ...",
                "token_type": "Bearer",
                "expires_in": 900
            }
        400 — grant_type no soportado.
        401 — Credenciales inválidas.

    Example:
        # Login
        curl -X POST https://api.example.com/oauth/token \\
             -H "Content-Type: application/json" \\
             -d '{"grantType": "password", "username": "admin", "password": "pass"}'

        # Renovación
        curl -X POST https://api.example.com/oauth/token \\
             -H "Content-Type: application/json" \\
             -d '{"grantType": "refresh_token", "refresh_token": "eyJ..."}'
    """
    if not request.is_json:
        return jsonify({"error": "invalid_request", "error_description": "Content-Type must be application/json"}), 400

    data = request.get_json(silent=True) or {}
    grant_type = data.get("grantType")

    # ── password grant ────────────────────────────────────────────────────────
    if grant_type == "password":
        username = data.get("username")
        password = data.get("password")

        if not username or not password:
            return jsonify({"error": "invalid_request", "error_description": "username and password are required"}), 400

        user_manager = get_user_manager()
        try:
            is_valid, uid = user_manager.verify_credentials(username, password)
        finally:
            user_manager.close_session()

        if not is_valid:
            _logger.warning(f"Login fallido para: {username}")
            return jsonify({"error": "invalid_grant", "error_description": "Invalid username or password"}), 401

        oauth_manager = get_oauth_manager()
        try:
            access_token  = oauth_manager.create_access_token(uid, username)   # type: ignore[arg-type]
            refresh_token = oauth_manager.create_refresh_token(uid)            # type: ignore[arg-type]
        finally:
            oauth_manager.close_session()

        _logger.info(f"Tokens emitidos para: {username}")
        return jsonify({
            "access_token":  access_token,
            "token_type":    "Bearer",
            "expires_in":    ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            "refresh_token": refresh_token,
        }), 200

    # ── refresh_token grant ────────────────────────────────────────────────────
    if grant_type == "refresh_token":
        refresh_token = data.get("refresh_token")

        if not refresh_token:
            return jsonify({"error": "invalid_request", "error_description": "refresh_token is required"}), 400

        oauth_manager = get_oauth_manager()
        try:
            uid = oauth_manager.verify_refresh_token(refresh_token)
        finally:
            oauth_manager.close_session()

        if not uid:
            return jsonify({"error": "invalid_grant", "error_description": "Invalid or expired refresh token"}), 401

        user_manager = get_user_manager()
        try:
            user = user_manager.get_user_by_id(uid)
        finally:
            user_manager.close_session()

        if not user:
            return jsonify({"error": "invalid_grant", "error_description": "User not found"}), 401

        oauth_manager2 = get_oauth_manager()
        try:
            access_token = oauth_manager2.create_access_token(uid, user.username)  # type: ignore[arg-type]
        finally:
            oauth_manager2.close_session()

        _logger.info(f"Access token renovado para usuario ID: {uid}")
        return jsonify({
            "access_token": access_token,
            "token_type":   "Bearer",
            "expires_in":   ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        }), 200

    return jsonify({"error": "unsupported_grant_type", "error_description": "Supported: password, refresh_token"}), 400


# ── POST /oauth/revoke ────────────────────────────────────────────────────

@oauth_bp.post("/revoke")
@require_oauth_token
def oauth_revoke():
    """Revoca el token Bearer actual.

    El token usado en la petición será invalidado inmediatamente.

    Returns:
        200 — Token revocado exitosamente.
            {"message": "Token revoked successfully"}

    Example:
        curl -X POST https://api.example.com/oauth/revoke \\
             -H "Authorization: Bearer <token>"
    """
    token = request.headers["Authorization"].split()[1]
    mgr = get_oauth_manager()
    try:
        mgr.revoke_access_token(token)
    finally:
        mgr.close_session()
    _logger.info(f"Token revocado para: {get_current_username()}")
    return jsonify({"message": "Token revoked successfully"}), 200


# ── POST /oauth/revoke-all ──────────────────────────────────────────────────

@oauth_bp.post("/revoke-all")
@require_oauth_token
def oauth_revoke_all():
    """Revoca todos los tokens OAuth del usuario autenticado.

    Después de esta operación, el usuario deberá iniciar sesión nuevamente
    para obtener nuevos tokens.

    Returns:
        200 — Todos los tokens revocados.
            {"message": "All tokens revoked successfully"}

    Warning:
        Esta acción invalida TODOS los tokens activos del usuario.

    Example:
        curl -X POST https://api.example.com/oauth/revoke-all \\
             -H "Authorization: Bearer <token>"
    """
    uid = get_current_user_id()
    mgr = get_oauth_manager()
    try:
        mgr.revoke_all_user_tokens(uid)
    finally:
        mgr.close_session()
    _logger.info(f"Todos los tokens revocados para usuario ID: {uid}")
    return jsonify({"message": "All tokens revoked successfully"}), 200
