"""
users_endpoints.py
══════════════════════════════════════════════════════════════════════════════

Blueprint de gestión de usuarios y personas. Registrado en /users.

Este módulo proporciona endpoints para registrar personas, crear usuarios,
validar credenciales y gestionar contraseñas.

────────────────────────────────────────────────────────────────────────────────
ENDPOINTS DISPONIBLES
────────────────────────────────────────────────────────────────────────────────

Registro
    POST /users/sign-up        — Registrar un Usuario vinculado a una Persona

Autenticación
    POST /users/check-credentials — Validar credenciales (legacy)

Gestión
    PUT  /users/change-password — Cambiar contraseña del usuario [autenticado]

────────────────────────────────────────────────────────────────────────────────
AUTENTICACIÓN
────────────────────────────────────────────────────────────────────────────────

Todos los endpoints excepto /sign-up y /check-credentials
requieren un token OAuth2 válido en el header:
    Authorization: Bearer <access_token>

Límites de tasa:
    • sign-up: 10/hour, 20/day
    • check-credentials: 10/minute, 30/hour
    • change-password: 5/hour, 10/day

────────────────────────────────────────────────────────────────────────────────
EJEMPLOS DE USO
────────────────────────────────────────────────────────────────────────────────

# Registrar un usuario
curl -X POST https://api.example.com/users/sign-up \
  -H "Content-Type: application/json" \
  -d '{"username": "johnd", "password": "secure123", "email": "john@example.com", "alias": "johnd"}'

# Cambiar contraseña (requiere autenticación)
curl -X PUT https://api.example.com/users/change-password \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"newPassword": "newpassword123"}'

────────────────────────────────────────────────────────────────────────────────
"""

from flask import Blueprint, jsonify, request
from contextlib import contextmanager
from werkzeug.exceptions import BadRequest

from src.modules.shared._exceptions import (
    DatabaseError,
    MissingParameterError,
    ExceptionHandler,
    create_error_response,
)
from src.modules.system.logging import SecOpsLogger
from src.modules.shared._endpoints import _get_limiter, require_json
limiter = _get_limiter()
from .services import Role, require_attributes, require_oauth_token, require_role
from .managers import ACCESS_TOKEN_EXPIRE_MINUTES, UserManager, OAuthTokenManager
from .exceptions import (
    ExistingUserError,
    InvalidCredentialsError,
    UserBindingError,
    ProfileUpdateError,
    AuthorizationError,
    PermissionsError
)


oauth_bp = Blueprint("oauth", __name__)
users_bp = Blueprint("users", __name__)
_logger  = SecOpsLogger("oauth").get_logger()


USER_MANAGER = UserManager()
OAUTH_MANAGER = OAuthTokenManager()


def _require_field(data: dict, field: str) -> str:
    """Extrae un campo requerido del body o lanza MissingParameterError."""
    value = data.get(field)
    if not value:
        raise MissingParameterError(field)
    return value


# =========================================================================
# HELPERS
# =========================================================================

def get_current_user():
    """
    Get the current authenticated user object from the database.

    Uses request-level caching to avoid repeated database queries.

    Returns:
        User: The fully-loaded User object with all attributes.

    Raises:
        AttributeError: If no user is authenticated (token not parsed).
    """
    if not hasattr(request, 'current_user'):
        user_id = request.current_user_id
        request.current_user = UserManager().get_user_by_id(user_id)
    return request.current_user

# =========================================================================
# SELF-APPLIED ENDPOINTS
# =========================================================================


@users_bp.post("/check-credentials")
@limiter.limit("10 per minute; 30 per hour")
@require_json
def check_credentials():
    """Valida credenciales de usuario (endpoint legacy).

    En producción, usar /oauth/token para autenticación OAuth2.

    Args (JSON body):
        username (str): Nombre de usuario.
        password (str): Contraseña del usuario.

    Returns:
        200 — Credenciales válidas.
            {
                "message": "Credenciales válidas",
                "isValid": true,
                "userId": 1,
                "username": "johnd"
            }
        401 — Credenciales inválidas.

    Example:
        curl -X POST https://api.example.com/users/check-credentials \\
                -H "Content-Type: application/json" \\
                -d '{"username": "johnd", "password": "password123"}'
    """
    data = request.json_body
    try:
        username = _require_field(data, "username")
        password = _require_field(data, "password")
    except MissingParameterError as exc:
        err, code = create_error_response(exc, include_debug_info=False)
        return jsonify(err), code

    try:
        is_valid, user_id = USER_MANAGER.verify_credentials(username, password)
        if not is_valid:
            raise InvalidCredentialsError()

        _logger.info(f"Credenciales válidas para: {username} (ID: {user_id})")
        return jsonify({"message": "Credenciales válidas", "isValid": True, "userId": user_id, "username": username}), 200

    except (MissingParameterError, InvalidCredentialsError) as exc:
        err, code = create_error_response(exc, include_debug_info=False)
        return jsonify(err), code
    except Exception as exc:
        _logger.error(f"Error en check-credentials: {exc}", exc_info=True)
        sec_exc = ExceptionHandler.wrap_exception(exc, logger=_logger)
        err, code = create_error_response(sec_exc, include_debug_info=False)
        return jsonify(err), code


@users_bp.put("/change-password")
@require_oauth_token
@limiter.limit("5 per hour; 10 per day")
@require_json
def change_password():
    """Cambia la contraseña del usuario autenticado e invalida todos sus tokens.

    Args (JSON body):
        newPassword (str): Nueva contraseña para el usuario.

    Returns:
        200 — Contraseña cambiada exitosamente.
            {
                "message": "Contraseña cambiada exitosamente. Por favor, inicia sesión de nuevo.",
                "userId": 1,
                "username": "johnd"
            }
        400 — Error de validación (contraseña inválida).

    Warning:
        Esta acción invalida TODOS los tokens OAuth del usuario.
        El usuario deberá iniciar sesión nuevamente.

    Example:
        curl -X PUT https://api.example.com/users/change-password \\
             -H "Authorization: Bearer <token>" \\
             -H "Content-Type: application/json" \\
             -d '{"newPassword": "newpassword123"}'
    """
    data = request.json_body
    try:
        new_password = _require_field(data, "newPassword")
    except MissingParameterError as exc:
        err, code = create_error_response(exc, include_debug_info=False)
        return jsonify(err), code

    try:
        user_id  = get_current_user().id
        username = get_current_user().username

        USER_MANAGER.update_user_password(user_id, new_password)
        OAUTH_MANAGER.revoke_all_user_tokens(user_id)

        _logger.info(f"Contraseña cambiada para: {username} (ID: {user_id})")
        return jsonify({
            "message":  "Contraseña cambiada exitosamente. Por favor, inicia sesión de nuevo.",
            "userId":   user_id,
            "username": username,
        }), 200

    except (MissingParameterError, InvalidCredentialsError) as exc:
        err, code = create_error_response(exc, include_debug_info=False)
        return jsonify(err), code
    except Exception as exc:
        _logger.error(f"Error en change-password: {exc}", exc_info=True)
        sec_exc = ExceptionHandler.wrap_exception(exc, logger=_logger)
        err, code = create_error_response(sec_exc, include_debug_info=False)
        return jsonify(err), code


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

    if grant_type == "password":
        username = data.get("username")
        password = data.get("password")

        if not username or not password:
            return jsonify({"error": "invalid_request", "error_description": "username and password are required"}), 400

        is_valid, uid = UserManager().verify_credentials(username, password)

        if not is_valid:
            _logger.warning(f"Login fallido para: {username}")
            return jsonify({"error": "invalid_grant", "error_description": "Invalid username or password"}), 401

        user = USER_MANAGER.get_user_by_id(uid)
        access_token  = OAUTH_MANAGER.create_access_token(uid, username, user.role if user else "role_user")   # type: ignore[arg-type]
        refresh_token = OAUTH_MANAGER.create_refresh_token(uid)            # type: ignore[arg-type]
        user_attrs = USER_MANAGER.get_user_attributes(uid)

        _logger.info(f"Usuario {uid} atributos: {user_attrs}")
        _logger.info(f"Tokens emitidos para: {username}")
        return jsonify({
            "access_token":  access_token,
            "token_type":    "Bearer",
            "expires_in":    ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            "refresh_token": refresh_token,
            "role":         user.role if user else "role_user",
            "attributes":   user_attrs,
        }), 200

    if grant_type == "refresh_token":
        refresh_token = data.get("refresh_token")

        if not refresh_token:
            return jsonify({"error": "invalid_request", "error_description": "refresh_token is required"}), 400

        uid = OAUTH_MANAGER.verify_refresh_token(refresh_token)

        if not uid:
            return jsonify({"error": "invalid_grant", "error_description": "Invalid or expired refresh token"}), 401

        user = USER_MANAGER.get_user_by_id(uid)

        if not user:
            return jsonify({"error": "invalid_grant", "error_description": "User not found"}), 401

        access_token = OAUTH_MANAGER.create_access_token(uid, user.username, user.role)  # type: ignore[arg-type]
        user_attrs = USER_MANAGER.get_user_attributes(uid)

        _logger.info(f"Access token renovado para usuario ID: {uid}")
        return jsonify({
            "access_token": access_token,
            "token_type":   "Bearer",
            "expires_in":   ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            "role":      user.role,
            "attributes":  user_attrs,
        }), 200

    return jsonify({"error": "unsupported_grant_type", "error_description": "Supported: password, refresh_token"}), 400


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
    OAUTH_MANAGER.revoke_access_token(token)
    _logger.info(f"Token revocado para: {get_current_user().username}")
    return jsonify({"message": "Token revoked successfully"}), 200


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
    uid = get_current_user().id
    OAUTH_MANAGER.revoke_all_user_tokens(uid)
    return jsonify({"message": "All tokens revoked successfully"}), 200


@users_bp.get("/me")
@require_oauth_token
@limiter.limit("30 per hour; 100 per day")
def get_current_profile():
    """Obtiene el perfil del usuario autenticado.

    Returns:
    200 — Perfil del usuario.
    {
    "id": 1,
    "username": "admin",
    "email": "admin@secops.local",
    "first_name": "Admin",
    "last_name": "User",
    "created_at": "2024-01-01T00:00:00Z"
    }

    Example:
    curl -X GET https://api.example.com/users/me \\
    -H "Authorization: Bearer <token>"
    """
    try:
        user_id = get_current_user().id
        username = get_current_user().username

        user = USER_MANAGER.get_user_by_id(user_id)

        if not user:
            return jsonify({"error": "user_not_found", "error_description": "Usuario no encontrado"}), 404

        return jsonify({
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "role": user.role,
            "created_at": user.created_at.isoformat() if user.created_at else None
        }), 200

    except Exception as exc:
        _logger.error(f"Error obteniendo perfil: {exc}", exc_info=True)
        sec_exc = ExceptionHandler.wrap_exception(exc, logger=_logger)
        err, code = create_error_response(sec_exc, include_debug_info=False)
        return jsonify(err), code


# =========================================================================
# USER managing ENDPOINTS (require role_admin or role_root)
# =========================================================================

@users_bp.post("/sign-up")
@require_oauth_token
@require_role(Role.ADMIN)
@limiter.limit("10 per hour; 20 per day")
@require_json
def sign_up_user():
    """Registra un nuevo usuario.

    Solo usuarios con role_root o role_admin pueden crear nuevos usuarios.

    Args (JSON body):
        username    (str): Nombre de usuario único.
        first_name  (str): Nombre real del usuario.
        last_name   (str): Apellido del usuario.
        password    (str): Contraseña del usuario.
        email       (str): Correo electrónico válido.

    Returns:
        201 — Usuario creado exitosamente.
            {
                "message": "Usuario registrado exitosamente",
                "userId": 1,
                "username": "johnd",
                "email": "john@example.com"
            }
        400 — Error de validación (campos faltantes o inválidos).
        409 — El username o email ya existe.

    Example:
        curl -X POST https://api.example.com/users/sign-up \\
            -H "Content-Type: application/json" \\
            -d '{"username": "johnd", "password": "secure123", "email": "john@example.com", "alias": "johnd", "role": "role_user"}'
    """
    data = request.json_body
    try:
        username        = _require_field(data, "username")
        email           = _require_field(data, "email")
        first_name      = _require_field(data, "first_name")
        last_name       = _require_field(data, "last_name")
        password        = _require_field(data, "password")
    except MissingParameterError as exc:
        err, code = create_error_response(exc, include_debug_info=False)
        _logger.error(err)
        return jsonify(err), code

    requested_role = data.get("role") or "role_user"
    current_user_id = get_current_user().id

    try:
        user = USER_MANAGER.sign_in_user(
            username = username,
            email = email,
            first_name = first_name,
            last_name = last_name,
            password = password,
            role = requested_role,
            actor_id = current_user_id
        )
        _logger.info(f"Usuario registrado: {username} con rol {requested_role} (ID: {user.id})")
        return jsonify({
            "message":  "Usuario registrado exitosamente",
            "userId":   user.id,
            "username": user.username,
            "email":    email,
            "role":     requested_role,
        }), 201

    except DatabaseError as exc:
        return jsonify({"code": exc.status_code, "message": "Revisa tus credenciales e inténtalo de nuevo."}), exc.status_code
    except (
        AuthorizationError, 
        MissingParameterError, 
        ExistingUserError, 
        UserBindingError,
        PermissionsError
    ) as exc:
        _logger.error(f"Error en sign-up: {exc}", exc_info=True)
        err, code = create_error_response(exc, include_debug_info=False)
        err["error_description"] = err.get("message", "")
        return jsonify(err), code
    except Exception as exc:
        _logger.error(f"Error en sign-up: {exc}", exc_info=True)
        sec_exc = ExceptionHandler.wrap_exception(exc, logger=_logger)
        err, code = create_error_response(sec_exc, include_debug_info=False)
        return jsonify(err), code


@users_bp.get("")
@require_oauth_token
@require_role(Role.ADMIN)
def list_all_users():
    """Lista todos los usuarios del sistema con sus atributos.

    Solo usuarios con role_root o role_admin pueden acceder.

    Returns:
        200 — Lista de usuarios con atributos.
            [{"id": 1, "username": "admin", "email": "admin@secops.local",
              "role": "role_root", "created_at": "...", "attributes": ["role_root"]}]
    """
    try:
        users = USER_MANAGER.get_all_users()
        result = []
        for user in users:
            result.append({
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "role": user.role,
                "created_at": user.created_at.isoformat() if user.created_at else None,
                "attributes": [a.attribute_name for a in user.attributes]
            })
        return jsonify(result), 200

    except Exception as exc:
        _logger.error(f"Error listando usuarios: {exc}", exc_info=True)
        return jsonify({"error": "server_error", "error_description": str(exc)}), 500


@users_bp.get("/<int:target_user_id>/attributes")
@require_oauth_token
@require_role(Role.ADMIN)
def list_user_attributes(target_user_id: int):
    """Lista los atributos de un usuario específico.

    Solo usuarios con role_root o role_admin pueden acceder.

    Returns:
        200 — Lista de atributos.
            {"attributes": ["role_user", "aegis_read"]}
        403 — Sin permisos.

    Example:
        curl -X GET https://api.example.com/users/5/attributes \\
        -H "Authorization: Bearer <token>"
    """
    current_user_id = get_current_user().id

    if not USER_MANAGER.can_manage_user(current_user_id, target_user_id):
        _logger.warning(f"Usuario {current_user_id} intentó ver atributos de {target_user_id} sin permiso")
        return jsonify({"error": "forbidden", "error_description": "No tienes permiso para ver atributos de este usuario"}), 403

    try:
        target_user = USER_MANAGER.get_user_by_id(target_user_id)
        return jsonify({
            "user_id": target_user_id, 
            "attributes": [a.attribute_name for a in target_user.attributes], 
            "role": target_user.role if target_user else "role_user"
        }), 200

    except Exception as exc:
        _logger.error(f"Error listando atributos: {exc}", exc_info=True)
        return jsonify({"error": "server_error", "error_description": str(exc)}), 500


@users_bp.put("/me")
@require_oauth_token
@limiter.limit("10 per hour; 20 per day")
@require_json
def update_current_profile():
    """Actualiza el perfil del usuario autenticado (nombre y apellidos).

    El username y email NO se pueden modificar (solo lectura).

    Args (JSON body):
    first_name (str): Nombre del usuario.
    last_name (str): Apellidos del usuario.

    Returns:
    200 — Perfil actualizado.
    {
    "id": 1,
    "username": "admin",
    "email": "admin@secops.local",
    "first_name": "NuevoNombre",
    "last_name": "NuevosApellidos",
    "created_at": "2024-01-01T00:00:00Z"
    }

    Example:
    curl -X PUT https://api.example.com/users/me \\
    -H "Authorization: Bearer <token>" \\
    -H "Content-Type: application/json" \\
    -d '{"first_name": "NuevoNombre", "last_name": "NuevosApellidos"}'
    """
    data = request.json_body
    try:
        first_name = _require_field(data, "first_name")
        last_name = _require_field(data, "last_name")
    except MissingParameterError as exc:
        err, code = create_error_response(exc, include_debug_info=False)
        return jsonify(err), code

    try:
        user_id = get_current_user().id
        username = get_current_user().username

        user = USER_MANAGER.update_user_profile(user_id, first_name, last_name)

        return jsonify({
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "role": user.role,
            "created_at": user.created_at.isoformat() if user.created_at else None
        }), 200

    except ProfileUpdateError as exc:
        err, code = create_error_response(exc, include_debug_info=False)
        return jsonify(err), code
    except Exception as exc:
        _logger.error(f"Error actualizando perfil: {exc}", exc_info=True)
        sec_exc = ExceptionHandler.wrap_exception(exc, logger=_logger)
        err, code = create_error_response(sec_exc, include_debug_info=False)
        return jsonify(err), code


@users_bp.put("/<int:target_user_id>/attributes")
@require_oauth_token
@require_role(Role.ADMIN)
@require_json
def add_user_attribute(target_user_id: int):
    """Añade uno o más atributos a un usuario.

    Solo usuarios con role_root o role_admin pueden acceder.

    Args (JSON body):
        attributes (list): Lista de nombres de atributos.
            ["sentinel_read", "aegis_create"]

    Returns:
        200 — Atributos añadidos.
            {"message": "Attributes added", "attributes": ["sentinel_read"]}
        400 — Error de validación.
        403 — Sin permisos.

    Example:
        curl -X POST https://api.example.com/users/5/attributes \\
        -H "Authorization: Bearer <token>" \\
        -H "Content-Type: application/json" \\
        -d '{"attributes": ["sentinel_read"]}'
    """
    current_user_id = get_current_user().id

    if not USER_MANAGER.can_manage_user(current_user_id, target_user_id):
        _logger.warning(f"Usuario {current_user_id} intentó añadir atributos a {target_user_id} sin permiso")
        return jsonify({"error": "forbidden", "error_description": "No tienes permiso para gestionar atributos de este usuario"}), 403

    data = request.json_body
    attrs_to_add = data.get("attributes")
    if not attrs_to_add or not isinstance(attrs_to_add, list):
        return jsonify({"error": "invalid_request", "error_description": "attributes array required"}), 400

    try:
        added_attrs = USER_MANAGER.add_user_attributes(
            target_user_id, attrs_to_add
        )

        _logger.info(f"Atributos {added_attrs} añadidos al usuario {target_user_id}")
        return jsonify({"message": "Attributes added", "attributes": added_attrs}), 200

    except Exception as exc:
        _logger.error(f"Error añadiendo atributos: {exc}", exc_info=True)
        return jsonify({"error": "server_error", "error_description": str(exc)}), 500


@users_bp.delete("/<int:target_user_id>/attributes")
@require_oauth_token
@require_role(Role.ADMIN)
@require_json
def remove_user_attribute(target_user_id: int):
    """Elimina uno o más atributos de un usuario.

    Solo usuarios con role_root o role_admin pueden acceder.

    Args (JSON body):
        attributes (list): Lista de nombres de atributos a eliminar.
            ["sentinel_read", "aegis_create"]

    Returns:
        200 — Atributos eliminados.
            {"message": "Attributes removed", "attributes": ["sentinel_read"]}
        400 — Error de validación.
        403 — Sin permisos.

    Example:
        curl -X DELETE https://api.example.com/users/5/attributes \\
        -H "Authorization: Bearer <token>" \\
        -H "Content-Type: application/json" \\
        -d '{"attributes": ["sentinel_read"]}'
    """
    current_user_id = get_current_user().id

    if not USER_MANAGER.can_manage_user(current_user_id, target_user_id):
        _logger.warning(f"Usuario {current_user_id} intentó eliminar atributos de {target_user_id} sin permiso")
        return jsonify({"error": "forbidden", "error_description": "No tienes permiso para gestionar atributos de este usuario"}), 403

    data = request.json_body
    attrs_to_remove = data.get("attributes")
    if not attrs_to_remove or not isinstance(attrs_to_remove, list):
        return jsonify({"error": "invalid_request", "error_description": "attributes array required"}), 400

    try:
        deleted_count = USER_MANAGER.remove_user_attributes(
            target_user_id, attrs_to_remove
        )

        _logger.info(f"Atributos {attrs_to_remove} eliminados del usuario {target_user_id}")
        return jsonify({"message": "Attributes removed", "attributes": attrs_to_remove}), 200

    except Exception as exc:
        _logger.error(f"Error eliminando atributos: {exc}", exc_info=True)
        return jsonify({"error": "server_error", "error_description": str(exc)}), 500
