from typing import Any

from flask import jsonify, request
from flask_smorest import Blueprint as SmorestBlueprint

from src.modules.shared._endpoints import limiter
from src.modules.shared._exceptions import (
    handle_exceptions,
    DatabaseError,
    IllegalStateError,
)
from src.modules.shared.schemas import ErrorSchema
from src.modules.system import SecOpsLogger

from .services import Role, require_oauth_token, require_role
from .managers import ACCESS_TOKEN_EXPIRE_MINUTES, UserManager, OAuthTokenManager
from .exceptions import InvalidCredentialsError
from .model import User
from .schemas import (
    TokenRequestSchema,
    TokenResponseSchema,
    SignUpRequestSchema,
    SignUpResponseSchema,
    CheckCredentialsRequestSchema,
    CheckCredentialsResponseSchema,
    ChangePasswordRequestSchema,
    ChangePasswordResponseSchema,
    UpdateProfileRequestSchema,
    UserProfileSchema,
    UserListItemSchema,
    AttributesRequestSchema,
    UserAttributesResponseSchema,
    AttributeOperationResponseSchema,
    RevokeResponseSchema,
)


oauth_blp = SmorestBlueprint("oauth", __name__, description="Autenticacion OAuth 2.0")
users_blp = SmorestBlueprint("users", __name__, description="Gestion de usuarios")
_logger = SecOpsLogger("oauth").get_logger()


USER_MANAGER = UserManager()
OAUTH_MANAGER = OAuthTokenManager()


def get_current_user() -> "User":
    if not hasattr(request, 'current_user'):
        user_id = request.current_user_id
        user = UserManager().get_user_by_id(user_id)
        if user is None:
            raise IllegalStateError("'user' detectado como None")
    return user


# =========================================================================
# OAUTH ENDPOINTS
# =========================================================================


@oauth_blp.post("/token")
@oauth_blp.arguments(TokenRequestSchema)
@oauth_blp.response(200, TokenResponseSchema, description="Token issued")
@oauth_blp.alt_response(400, schema=ErrorSchema, description="Invalid parameters")
@oauth_blp.alt_response(401, schema=ErrorSchema, description="Invalid credentials")
@limiter.limit("20 per hour; 100 per day")
def oauth_token(data: dict[str, Any]):
    """Emitir tokens OAuth 2.0 (password o refresh_token)"""
    grant_type = data["grantType"]

    if grant_type == "password":
        username = data["username"]
        password = data["password"]

        is_valid, uid = UserManager().verify_credentials(username, password)
        if not is_valid or uid is None:
            _logger.warning(f"Login fallido para: {username}")
            return jsonify({
                "error": "invalid_grant",
                "error_description": "Invalid username or password",
            }), 401

        user = USER_MANAGER.get_user_by_id(uid)
        access_token = OAUTH_MANAGER.create_access_token(
            user_id=uid, username=username,
            role=user.role if user else "role_user",
        )
        refresh_token = OAUTH_MANAGER.create_refresh_token(uid)
        user_attrs = USER_MANAGER.get_user_attributes(uid)

        _logger.info(f"Tokens emitidos para: {username}")
        return {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            "refresh_token": refresh_token,
            "role": user.role if user else "role_user",
            "attributes": user_attrs,
        }

    if grant_type == "refresh_token":
        refresh_token_str = data["refresh_token"]
        uid = OAUTH_MANAGER.verify_refresh_token(refresh_token_str)
        if not uid:
            return jsonify({
                "error": "invalid_grant",
                "error_description": "Invalid or expired refresh token",
            }), 401

        user = USER_MANAGER.get_user_by_id(uid)
        if not user:
            return jsonify({
                "error": "invalid_grant",
                "error_description": "User not found",
            }), 401

        access_token = OAUTH_MANAGER.create_access_token(uid, user.username, user.role)
        user_attrs = USER_MANAGER.get_user_attributes(uid)

        _logger.info(f"Access token renovado para usuario ID: {uid}")
        return {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            "role": user.role,
            "attributes": user_attrs,
        }

    return jsonify({
        "error": "unsupported_grant_type",
        "error_description": "Supported: password, refresh_token",
    }), 400


@oauth_blp.post("/revoke")
@oauth_blp.response(200, RevokeResponseSchema, description="Token revoked")
@oauth_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@require_oauth_token
def oauth_revoke():
    """Revocar el token Bearer actual"""
    token = request.headers["Authorization"].split()[1]
    OAUTH_MANAGER.revoke_access_token(token)
    _logger.info(f"Token revocado para: {get_current_user().username}")
    return {"message": "Token revoked successfully"}


@oauth_blp.post("/revoke-all")
@oauth_blp.response(200, RevokeResponseSchema, description="All tokens revoked")
@oauth_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@require_oauth_token
def oauth_revoke_all():
    """Revocar todos los tokens del usuario autenticado"""
    user = get_current_user()
    OAUTH_MANAGER.revoke_all_user_tokens(user.id)
    return {"message": "All tokens revoked successfully"}


# =========================================================================
# SELF-APPLIED ENDPOINTS
# =========================================================================


@users_blp.post("/check-credentials")
@users_blp.arguments(CheckCredentialsRequestSchema)
@users_blp.response(200, CheckCredentialsResponseSchema, description="Valid credentials")
@users_blp.alt_response(401, schema=ErrorSchema, description="Invalid credentials")
@limiter.limit("10 per minute; 30 per hour")
@handle_exceptions(default_exception=InvalidCredentialsError, logger=_logger)
def check_credentials(data: dict[str, Any]):
    """Validar credenciales de usuario (endpoint legacy)"""
    username = data["username"]
    password = data["password"]

    is_valid, user_id = USER_MANAGER.verify_credentials(username, password)
    if not is_valid:
        raise InvalidCredentialsError()

    _logger.info(f"Credenciales validas para: {username} (ID: {user_id})")
    return {"message": "Credenciales validas", "isValid": True, "userId": user_id, "username": username}


@users_blp.put("/change-password")
@users_blp.arguments(ChangePasswordRequestSchema)
@users_blp.response(200, ChangePasswordResponseSchema, description="Password changed")
@users_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@require_oauth_token
@limiter.limit("5 per hour; 10 per day")
@handle_exceptions(default_exception=DatabaseError, logger=_logger)
def change_password(data: dict[str, Any]):
    """Cambiar la contrasena del usuario autenticado. Invalida todos sus tokens."""
    new_password = data["newPassword"]

    user = get_current_user()
    user_id = user.id
    username = user.username

    USER_MANAGER.update_user_password(user_id, new_password)
    OAUTH_MANAGER.revoke_all_user_tokens(user_id)

    _logger.info(f"Contrasena cambiada para: {username} (ID: {user_id})")
    return {
        "message": "Contrasena cambiada exitosamente. Por favor, inicia sesion de nuevo.",
        "userId": user_id,
        "username": username,
    }


@users_blp.get("/me")
@users_blp.response(200, UserProfileSchema, description="Current user profile")
@users_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@require_oauth_token
@limiter.limit("30 per hour; 100 per day")
@handle_exceptions(default_exception=DatabaseError, logger=_logger)
def get_current_profile():
    """Obtener el perfil del usuario autenticado"""
    user = get_current_user()
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "role": user.role,
        "created_at": user.created_at,
    }


@users_blp.put("/me")
@users_blp.arguments(UpdateProfileRequestSchema)
@users_blp.response(200, UserProfileSchema, description="Updated profile")
@users_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@require_oauth_token
@limiter.limit("10 per hour; 20 per day")
@handle_exceptions(default_exception=DatabaseError, logger=_logger)
def update_current_profile(data: dict[str, Any]):
    """Actualizar nombre y apellidos del perfil propio"""
    first_name = data["first_name"]
    last_name = data["last_name"]

    user = get_current_user()
    user = USER_MANAGER.update_user_profile(user.id, first_name, last_name)

    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "role": user.role,
        "created_at": user.created_at,
    }


@users_blp.post("/sign-up")
@users_blp.arguments(SignUpRequestSchema)
@users_blp.response(201, SignUpResponseSchema, description="User created")
@users_blp.alt_response(400, schema=ErrorSchema, description="Validation error")
@users_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@users_blp.alt_response(403, schema=ErrorSchema, description="Insufficient role")
@users_blp.alt_response(409, schema=ErrorSchema, description="Already exists")
@limiter.limit("10 per hour; 20 per day")
@require_oauth_token
@require_role(Role.ADMIN)
@handle_exceptions(default_exception=DatabaseError, logger=_logger)
def sign_up_user(data: dict[str, Any]):
    """Registrar un nuevo usuario (requiere role_admin o role_root)"""
    username = data["username"]
    email = data["email"]
    first_name = data["first_name"]
    last_name = data["last_name"]
    password = data["password"]
    requested_role = data.get("role") or "role_user"
    current_user_id = get_current_user().id

    user = USER_MANAGER.sign_in_user(
        username=username,
        email=email,
        first_name=first_name,
        last_name=last_name,
        password=password,
        role=requested_role,
        actor_id=current_user_id,
    )
    _logger.info(f"Usuario registrado: {username} con rol {requested_role} (ID: {user.id})")
    return {
        "message": "Usuario registrado exitosamente",
        "userId": user.id,
        "username": user.username,
        "email": email,
        "role": requested_role,
    }


@users_blp.get("")
@users_blp.response(200, UserListItemSchema(many=True), description="List of all users")
@users_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@users_blp.alt_response(403, schema=ErrorSchema, description="Insufficient role")
@require_oauth_token
@require_role(Role.ADMIN)
@handle_exceptions(default_exception=DatabaseError, logger=_logger)
def list_all_users():
    """Listar todos los usuarios del sistema con sus atributos"""
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
            "created_at": user.created_at,
            "attributes": [a.attribute_name for a in user.attributes],
        })
    return result


@users_blp.get("/<int:target_user_id>/attributes")
@users_blp.response(200, UserAttributesResponseSchema, description="User attributes")
@users_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@users_blp.alt_response(403, schema=ErrorSchema, description="Insufficient role")
@require_oauth_token
@require_role(Role.ADMIN)
@handle_exceptions(default_exception=DatabaseError, logger=_logger)
def list_user_attributes(target_user_id: int):
    """Listar los atributos de un usuario especifico"""
    current_user = get_current_user()
    uid = current_user.id

    if not USER_MANAGER.can_manage_user(uid, target_user_id):
        _logger.warning(f"Usuario {uid} intento ver atributos de {target_user_id} sin permiso")
        return jsonify({
            "error": "forbidden",
            "error_description": "No tienes permiso para ver atributos de este usuario",
        }), 403

    target_user = USER_MANAGER.get_user_by_id(target_user_id)
    return {
        "user_id": target_user_id,
        "attributes": [a.attribute_name for a in target_user.attributes],
        "role": target_user.role if target_user else "role_user",
    }


@users_blp.put("/<int:target_user_id>/attributes")
@users_blp.arguments(AttributesRequestSchema)
@users_blp.response(200, AttributeOperationResponseSchema, description="Attributes added")
@users_blp.alt_response(400, schema=ErrorSchema, description="Validation error")
@users_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@users_blp.alt_response(403, schema=ErrorSchema, description="Insufficient role")
@require_oauth_token
@require_role(Role.ADMIN)
@handle_exceptions(default_exception=DatabaseError, logger=_logger)
def add_user_attribute(data: dict[str, Any], target_user_id: int):
    """Anadir atributos a un usuario"""
    current_user_id = get_current_user().id

    if not USER_MANAGER.can_manage_user(current_user_id, target_user_id):
        _logger.warning(f"Usuario {current_user_id} intento anadir atributos a {target_user_id} sin permiso")
        return jsonify({
            "error": "forbidden",
            "error_description": "No tienes permiso para gestionar atributos de este usuario",
        }), 403

    attrs_to_add = data["attributes"]
    added_attrs = USER_MANAGER.add_user_attributes(
        user_id=target_user_id, attribute_names=attrs_to_add,
    )

    _logger.info(f"Atributos {added_attrs} anadidos al usuario {target_user_id}")
    return {"message": "Attributes added", "attributes": added_attrs}


@users_blp.delete("/<int:target_user_id>/attributes")
@users_blp.arguments(AttributesRequestSchema)
@users_blp.response(200, AttributeOperationResponseSchema, description="Attributes removed")
@users_blp.alt_response(400, schema=ErrorSchema, description="Validation error")
@users_blp.alt_response(401, schema=ErrorSchema, description="Not authenticated")
@users_blp.alt_response(403, schema=ErrorSchema, description="Insufficient role")
@require_oauth_token
@require_role(Role.ADMIN)
@handle_exceptions(default_exception=DatabaseError, logger=_logger)
def remove_user_attribute(data: dict[str, Any], target_user_id: int):
    """Eliminar atributos de un usuario"""
    current_user_id = get_current_user().id

    if not USER_MANAGER.can_manage_user(current_user_id, target_user_id):
        _logger.warning(
            f"Usuario {current_user_id} intento eliminar atributos de {target_user_id} sin permiso"
        )
        return jsonify({
            "error": "forbidden",
            "error_description": "No tienes permiso para gestionar atributos de este usuario",
        }), 403

    attrs_to_remove = data["attributes"]
    USER_MANAGER.remove_user_attributes(
        user_id=target_user_id, attribute_names=attrs_to_remove,
    )

    _logger.info(f"Atributos {attrs_to_remove} eliminados del usuario {target_user_id}")
    return {"message": "Attributes removed", "attributes": attrs_to_remove}
