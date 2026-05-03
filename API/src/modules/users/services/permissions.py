

from enum import Enum
from functools import wraps
from typing import List, Optional

from flask import request, jsonify

from src.modules.system.logging import SecOpsLogger

from ..managers import OAuthTokenManager
from ..model import UserAttribute
from src.modules.infrastructure import UnitOfWork


_logger = SecOpsLogger().get_logger()


class AttributeType(Enum):
    """
    Permission attributes for access control.

    Attributes follow a naming convention of {MODULE}_{OPERATION} for CRUD,
    and {ROLE}_{NAME} for role-based access.
    """
    AEGIS_CREATE = "aegis_create"
    AEGIS_READ = "aegis_read"
    AEGIS_UPDATE = "aegis_update"
    AEGIS_DELETE = "aegis_delete"

    SENTINEL_CREATE = "sentinel_create"
    SENTINEL_READ = "sentinel_read"
    SENTINEL_UPDATE = "sentinel_update"
    SENTINEL_DELETE = "sentinel_delete"

    ACHERON_CREATE = "acheron_create"
    ACHERON_READ = "acheron_read"
    ACHERON_UPDATE = "acheron_update"
    ACHERON_DELETE = "acheron_delete"

    ROLE_ROOT = "role_root"
    ROLE_ADMIN = "role_admin"
    ROLE_USER = "role_user"

    _DESCRIPTIONS = {
        "aegis_create": "Create access for Aegis awareness pills",
        "aegis_read": "Read access for Aegis awareness pills",
        "aegis_update": "Update access for Aegis awareness pills",
        "aegis_delete": "Delete access for Aegis awareness pills",
        "sentinel_create": "Create access for Sentinel security scans",
        "sentinel_read": "Read access for Sentinel security scans",
        "sentinel_update": "Update access for Sentinel security scans",
        "sentinel_delete": "Delete access for Sentinel security scans",
        "acheron_create": "Create access for Acheron vault secrets",
        "acheron_read": "Read access for Acheron vault secrets",
        "acheron_update": "Update access for Acheron vault secrets",
        "acheron_delete": "Delete access for Acheron vault secrets",
        "role_root": "Root-level access (full system control)",
        "role_admin": "Admin-level access (user management)",
        "role_user": "Standard user access (baseline permissions)",
    }

    @property
    def db_name(self) -> str:
        return self.value

    @property
    def db_description(self) -> str:
        return self._DESCRIPTIONS.get(self.value, "")


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

            payload = OAuthTokenManager().verify_access_token(token)

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


def require_attributes(
    at_least_one: Optional[List[AttributeType]] = None,
    all_required: Optional[List[AttributeType]] = None,
):
    """
    Decorador para verificar atributos del usuario.

    Debe usarse DESPUÉS de @require_oauth_token, ya que depende de
    request.current_user_id establecido por ese decorador.

    Args:
        at_least_one: Lista de atributos. El usuario debe tener AL MENOS UNO.
        all_required: Lista de atributos. El usuario debe tener TODOS.

    Returns:
        403 si el usuario no cumple los requisitos de atributos.

    Ejemplo:
        @require_oauth_token
        @require_attributes(at_least_one=[AttributeType.SENTINEL_READ])
        def mi_endpoint():
            ...

        @require_oauth_token
        @require_attributes(all_required=[AttributeType.ROLE_ROOT])
        def solo_root():
            ...
    """
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            user_id = getattr(request, "current_user_id", None)
            if user_id is None:
                return jsonify({
                    "error": "forbidden",
                    "error_description": "Authentication required before attribute check",
                }), 403

            try:
                with UnitOfWork() as uow:
                    user_attrs = (
                        uow.session.query(UserAttribute.attribute_name)
                        .filter(UserAttribute.user_id == user_id)
                        .all()
                    )
                    user_attribute_names = {ua.attribute_name for ua in user_attrs}

                missing_at_least_one: List[AttributeType] = []
                if at_least_one:
                    for attr in at_least_one:
                        if attr.db_name not in user_attribute_names:
                            missing_at_least_one.append(attr)

                missing_all_required: List[AttributeType] = []
                if all_required:
                    for attr in all_required:
                        if attr.db_name not in user_attribute_names:
                            missing_all_required.append(attr)

                has_at_least_one = not at_least_one or len(missing_at_least_one) < len(at_least_one)
                has_all_required = not all_required or len(missing_all_required) == 0

                if not has_at_least_one or not has_all_required:
                    _logger.warning(
                        f"Usuario {user_id} denegado. at_least_one={missing_at_least_one}, "
                        f"all_required={missing_all_required}"
                    )
                    return jsonify({
                        "error": "forbidden",
                        "error_description": "Insufficient permissions",
                        "missing_attributes": {
                            "at_least_one": [a.db_name for a in missing_at_least_one],
                            "all_required": [a.db_name for a in missing_all_required],
                        },
                    }), 403

                _logger.info(
                    f"Usuario {user_id} autorizado para {f.__name__}. "
                    f"at_least_one={at_least_one}, all_required={all_required}"
                )

                return f(*args, **kwargs)

            except Exception as exc:
                _logger.error(f"Error en require_attributes: {exc}")
                return jsonify({
                    "error": "server_error",
                    "error_description": "Permission check failed",
                }), 500

        return decorated
    return decorator


def require_auth(
    attrs: Optional[List[AttributeType]] = None,
    mode: str = "any",
):
    """
    Decorador combinado: autentica y verifica atributos en un solo paso.

    Args:
        attrs: Lista de atributos requeridos.
        mode: "any" (al menos uno) o "all" (todos requeridos).

    Returns:
        401 si no hay token, 403 si no tiene atributos.

    Ejemplo:
        @require_auth(attrs=[AttributeType.SENTINEL_READ])
        @require_auth(attrs=[AttributeType.ROLE_ROOT], mode="all")
    """
    def decorator(f):
        @require_oauth_token
        @wraps(f)
        def decorated(*args, **kwargs):
            user_id = getattr(request, "current_user_id", None)
            if user_id is None:
                return jsonify({
                    "error": "forbidden",
                    "error_description": "Authentication required",
                }), 403

            try:
                with UnitOfWork() as uow:
                    user_attrs = (
                        uow.session.query(UserAttribute.attribute_name)
                        .filter(UserAttribute.user_id == user_id)
                        .all()
                    )
                    user_attribute_names = {ua.attribute_name for ua in user_attrs}

                missing: List[AttributeType] = []
                if attrs:
                    for attr in attrs:
                        if attr.db_name not in user_attribute_names:
                            missing.append(attr)

                if mode == "all":
                    has_permission = not attrs or len(missing) == 0
                    check_desc = f"all_required={attrs}"
                else:
                    has_permission = not attrs or len(missing) < len(attrs)
                    check_desc = f"at_least_one={attrs}"

                if not has_permission:
                    _logger.warning(
                        f"Usuario {user_id} denegado en {f.__name__}. {check_desc}"
                    )
                    return jsonify({
                        "error": "forbidden",
                        "error_description": "Insufficient permissions",
                        "missing_attributes": [a.db_name for a in missing],
                    }), 403

                _logger.info(
                    f"Usuario {user_id} autorizado para {f.__name__}. {check_desc}"
                )
                return f(*args, **kwargs)

            except Exception as exc:
                _logger.error(f"Error en require_auth: {exc}")
                return jsonify({
                    "error": "server_error",
                    "error_description": "Permission check failed",
                }), 500

        return decorated
    return decorator


