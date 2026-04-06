"""
endpoints/users.py
──────────────────
Blueprint de gestión de usuarios. Registrado en /users.

Rutas:
  POST  /users/sign-up-person      — registrar una Persona
  POST  /users/sign-up             — registrar un Usuario (vinculado a una Persona)
  POST  /users/check-credentials   — validar credenciales (legacy)
  PUT   /users/change-password     — cambiar contraseña  [autenticado]
"""

from flask import Blueprint, jsonify, request

from src.core.exceptions import (
    DatabaseError,
    ExistingUserError,
    InvalidCredentialsError,
    MissingParameterError,
    UserBindingError,
    ExceptionHandler,
    create_error_response,
)
from src.misc import SecOpsLogger

from ._shared import (
    get_current_user_id,
    get_current_username,
    get_oauth_manager,
    get_user_manager,
    limiter,
    require_oauth_token,
)

users_bp = Blueprint("users", __name__)
_logger  = SecOpsLogger("users").get_logger()


# ── POST /users/sign-up-person ────────────────────────────────────────────────

@users_bp.post("/sign-up-person")
@limiter.limit("10 per hour; 20 per day")
def sign_up_person():
    """Registra una nueva Persona en el sistema."""
    data = _require_json()
    if isinstance(data, tuple):          # respuesta de error
        return data

    try:
        first_name = _require_field(data, "firstName")
        last_name  = _require_field(data, "lastName")
        alias      = _require_field(data, "alias")
    except MissingParameterError as exc:
        err, code = create_error_response(exc, include_debug_info=False)
        return jsonify(err), code

    try:
        person = get_user_manager().sign_in_person(first_name, last_name, alias)
        _logger.info(f"Persona registrada: {first_name} {last_name} (ID: {person.id})")
        return jsonify({
            "message":   "Persona registrada exitosamente",
            "personId":  person.id,
            "firstName": person.first_name,
            "lastName":  person.last_name,
        }), 201

    except (ExistingUserError,) as exc:
        err, code = create_error_response(exc, include_debug_info=False)
        return jsonify(err), code
    except Exception as exc:
        _logger.error(f"Error en sign-up-person: {exc}", exc_info=True)
        sec_exc = ExceptionHandler.wrap_exception(exc, logger=_logger)
        err, code = create_error_response(sec_exc, include_debug_info=False)
        return jsonify(err), code


# ── POST /users/sign-up ───────────────────────────────────────────────────────

@users_bp.post("/sign-up")
@limiter.limit("10 per hour; 20 per day")
def sign_up_user():
    """Registra un nuevo Usuario vinculándolo a una Persona existente."""
    data = _require_json()
    if isinstance(data, tuple):
        return data

    try:
        username = _require_field(data, "username")
        password = _require_field(data, "password")
        email    = _require_field(data, "email")
        alias    = _require_field(data, "alias")
    except MissingParameterError as exc:
        err, code = create_error_response(exc, include_debug_info=False)
        return jsonify(err), code

    try:
        user = get_user_manager().sign_in_user(username, password, email, alias)
        _logger.info(f"Usuario registrado: {username} (ID: {user.id})")
        return jsonify({
            "message":  "Usuario registrado exitosamente",
            "userId":   user.id,
            "username": user.username,
            "email":    email,
        }), 201

    except DatabaseError as exc:
        return jsonify({"code": exc.status_code, "message": "Revisa tus credenciales e inténtalo de nuevo."}), exc.status_code
    except (MissingParameterError, ExistingUserError, UserBindingError) as exc:
        err, code = create_error_response(exc, include_debug_info=False)
        return jsonify(err), code
    except Exception as exc:
        _logger.error(f"Error en sign-up: {exc}", exc_info=True)
        sec_exc = ExceptionHandler.wrap_exception(exc, logger=_logger)
        err, code = create_error_response(sec_exc, include_debug_info=False)
        return jsonify(err), code


# ── POST /users/check-credentials ────────────────────────────────────────────

@users_bp.post("/check-credentials")
@limiter.limit("10 per minute; 30 per hour")
def check_credentials():
    """Valida credenciales (endpoint legacy — usar /oauth/token en producción)."""
    data = _require_json()
    if isinstance(data, tuple):
        return data

    try:
        username = _require_field(data, "username")
        password = _require_field(data, "password")
    except MissingParameterError as exc:
        err, code = create_error_response(exc, include_debug_info=False)
        return jsonify(err), code

    try:
        is_valid, user_id = get_user_manager().verify_credentials(username, password)
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


# ── PUT /users/change-password ────────────────────────────────────────────────

@users_bp.put("/change-password")
@require_oauth_token
@limiter.limit("5 per hour; 10 per day")
def change_password():
    """Cambia la contraseña del usuario autenticado e invalida todos sus tokens."""
    data = _require_json()
    if isinstance(data, tuple):
        return data

    try:
        new_password = _require_field(data, "newPassword")
    except MissingParameterError as exc:
        err, code = create_error_response(exc, include_debug_info=False)
        return jsonify(err), code

    try:
        user_id  = get_current_user_id()
        username = get_current_username()

        get_user_manager().update_user_password(user_id, new_password)
        get_oauth_manager().revoke_all_user_tokens(user_id)

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


# ── Helpers privados ──────────────────────────────────────────────────────────

def _require_json():
    """
    Devuelve el body JSON o una respuesta de error 400 si el Content-Type
    no es application/json o el body está vacío.
    """
    if not request.is_json:
        return jsonify({"error": "invalid_request", "error_description": "Content-Type must be application/json"}), 400
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "invalid_request", "error_description": "Request body must be JSON"}), 400
    return data


def _require_field(data: dict, field: str) -> str:
    """Extrae un campo requerido del body o lanza MissingParameterError."""
    value = data.get(field)
    if not value:
        raise MissingParameterError(field)
    return value
