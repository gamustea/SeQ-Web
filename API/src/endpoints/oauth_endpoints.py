"""
endpoints/oauth.py
──────────────────
Blueprint OAuth 2.0. Registrado en /oauth.

Rutas:
  POST  /oauth/token       — login (password grant) o renovación (refresh_token grant)
  POST  /oauth/revoke      — revocar el token actual  [autenticado]
  POST  /oauth/revoke-all  — revocar todos los tokens del usuario [autenticado]
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
    """
    Emite tokens OAuth 2.0.

    grant_type = "password"       → credenciales usuario/contraseña
    grant_type = "refresh_token"  → renovar access token con refresh token
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
    """Revoca el token Bearer actual."""
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
    """Revoca todos los tokens del usuario autenticado."""
    uid = get_current_user_id()
    mgr = get_oauth_manager()
    try:
        mgr.revoke_all_user_tokens(uid)
    finally:
        mgr.close_session()
    _logger.info(f"Todos los tokens revocados para usuario ID: {uid}")
    return jsonify({"message": "All tokens revoked successfully"}), 200
