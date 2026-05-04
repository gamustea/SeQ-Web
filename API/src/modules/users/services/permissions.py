from enum import Enum
from functools import wraps
from typing import List, Optional, Set

from flask import request, jsonify

from src.modules.system.logging import SecOpsLogger

from ..managers import OAuthTokenManager
from ..model import UserAttribute
from src.modules.infrastructure import UnitOfWork


_logger = SecOpsLogger().get_logger()


# =========================================================================
# ROLE ENUM — structural identity (who the user is)
# =========================================================================

class Role(Enum):
    """
    Structural roles that express a user's identity tier.

    Roles are mutually exclusive and stored in User.role — never in
    UserAttribute. The hierarchy is: ROOT > ADMIN > USER.

    Use Role to gate access based on identity level (e.g. only admins
    can create users). Use AttributeType for fine-grained capability checks
    (e.g. only users with sentinel_read can list scans).
    """
    ROOT  = "role_root"
    ADMIN = "role_admin"
    USER  = "role_user"

    # Ordered from lowest to highest privilege.
    # Used by require_role() for hierarchy comparisons.
    _HIERARCHY = ["role_user", "role_admin", "role_root"]

    @property
    def db_name(self) -> str:
        return self.value

    @classmethod
    def hierarchy(cls) -> List[str]:
        """Return role values ordered from least to most privileged."""
        return ["role_user", "role_admin", "role_root"]

    def rank(self) -> int:
        """Return the privilege rank of this role (higher = more privileged)."""
        return self.hierarchy().index(self.value)


# =========================================================================
# AttributeType ENUM — fine-grained ABAC capabilities (what the user can do)
# =========================================================================

class AttributeType(Enum):
    """
    ABAC capability attributes for fine-grained access control.

    Attributes follow the naming convention {MODULE}_{OPERATION} and are
    stored as rows in the UserAttribute table. They express what a user
    can do within a specific module, independently of their role tier.

    A user's effective permissions are the union of:
        - All permissions granted by their Role (via ROLE_PERMISSIONS), AND
        - Any extra AttributeType rows in UserAttribute.

    Root users bypass all AttributeType checks — they have implicit access
    to every operation without needing explicit attribute rows.
    """
    AEGIS_CREATE    = "aegis_create"
    AEGIS_READ      = "aegis_read"
    AEGIS_UPDATE    = "aegis_update"
    AEGIS_DELETE    = "aegis_delete"

    SENTINEL_CREATE = "sentinel_create"
    SENTINEL_READ   = "sentinel_read"
    SENTINEL_UPDATE = "sentinel_update"
    SENTINEL_DELETE = "sentinel_delete"

    ACHERON_CREATE  = "acheron_create"
    ACHERON_READ    = "acheron_read"
    ACHERON_UPDATE  = "acheron_update"
    ACHERON_DELETE  = "acheron_delete"

    _DESCRIPTIONS = {
        "aegis_create":    "Create access for Aegis awareness pills",
        "aegis_read":      "Read access for Aegis awareness pills",
        "aegis_update":    "Update access for Aegis awareness pills",
        "aegis_delete":    "Delete access for Aegis awareness pills",
        "sentinel_create": "Create access for Sentinel security scans",
        "sentinel_read":   "Read access for Sentinel security scans",
        "sentinel_update": "Update access for Sentinel security scans",
        "sentinel_delete": "Delete access for Sentinel security scans",
        "acheron_create":  "Create access for Acheron vault secrets",
        "acheron_read":    "Read access for Acheron vault secrets",
        "acheron_update":  "Update access for Acheron vault secrets",
        "acheron_delete":  "Delete access for Acheron vault secrets",
    }

    @property
    def db_name(self) -> str:
        return self.value

    @property
    def db_description(self) -> str:
        return self._DESCRIPTIONS.get(self.value, "")


# =========================================================================
# ROLE → AttributeType MATRIX
# =========================================================================

# Defines the baseline permissions each role grants implicitly.
# When checking permissions, a user's effective set is:
#     ROLE_PERMISSIONS[user.role]  ∪  {explicit UserAttribute rows}
#
# Root is intentionally absent — it short-circuits all checks.

ROLE_PERMISSIONS: dict[Role, Set[AttributeType]] = {
    Role.USER: {
        AttributeType.AEGIS_READ,
        AttributeType.SENTINEL_READ,
        AttributeType.ACHERON_READ,
    },
    Role.ADMIN: {
        AttributeType.AEGIS_CREATE,
        AttributeType.AEGIS_READ,
        AttributeType.AEGIS_UPDATE,
        AttributeType.AEGIS_DELETE,
        AttributeType.SENTINEL_CREATE,
        AttributeType.SENTINEL_READ,
        AttributeType.SENTINEL_UPDATE,
        AttributeType.SENTINEL_DELETE,
        AttributeType.ACHERON_READ,
    },
}


def _get_effective_permissions(user_id: int, user_role: str) -> Set[str]:
    """
    Return the effective AttributeType set for a user as a set of db_name strings.

    Combines role-baseline permissions with any explicit UserAttribute rows.
    Root users are handled upstream (they bypass this function entirely).

    Args:
        user_id:   User primary key.
        user_role: Role string from User.role (e.g. "role_admin").

    Returns:
        Set of AttributeType db_name strings effective for this user.
    """
    try:
        role_enum = Role(user_role)
    except ValueError:
        role_enum = Role.USER

    baseline: Set[str] = {p.db_name for p in ROLE_PERMISSIONS.get(role_enum, set())}

    with UnitOfWork() as uow:
        extra_attrs = (
            uow.session.query(UserAttribute.attribute_name)
            .filter(UserAttribute.user_id == user_id)
            .all()
        )
    extra: Set[str] = {ua.attribute_name for ua in extra_attrs}

    return baseline | extra


# =========================================================================
# DECORATORS
# =========================================================================

def require_oauth_token(f):
    """
    Verifica el Bearer token en la cabecera Authorization.

    Inyecta en el request:
        - request.current_user_id   (int)
        - request.current_username  (str)
        - request.current_user_role (str)  ← nuevo: rol estructural del usuario

    Cierra siempre la sesión del OAuthTokenManager en un bloque
    finally para que la conexión se devuelva al pool.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
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

            request.current_user_id   = int(payload.get("sub", "0"))      # type: ignore[attr-defined]
            request.current_username  = payload.get("username", "")       # type: ignore[attr-defined]
            request.current_user_role = payload.get("role", "role_user")  # type: ignore[attr-defined]

            return f(*args, **kwargs)

        except Exception as exc:
            _logger.error(f"Error durante la autenticación: {exc}")
            return jsonify({
                "error": "server_error",
                "error_description": "Authentication error",
            }), 500

    return decorated


def require_role(minimum_role: Role):
    """
    Verifica que el usuario tiene al menos el rol indicado en la jerarquía.

    Jerarquía (de menor a mayor): USER < ADMIN < ROOT.
    Debe usarse DESPUÉS de @require_oauth_token.

    Args:
        minimum_role: Rol mínimo requerido.

    Returns:
        403 si el usuario está por debajo del nivel requerido.

    Ejemplo:
        @require_oauth_token
        @require_role(Role.ADMIN)
        def crear_usuario(): ...
    """
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            user_role_str = getattr(request, "current_user_role", Role.USER.value)
            user_id       = getattr(request, "current_user_id", None)

            try:
                user_role = Role(user_role_str)
            except ValueError:
                user_role = Role.USER

            if user_role.rank() < minimum_role.rank():
                _logger.warning(
                    f"Usuario {user_id} (rol={user_role_str}) denegado. "
                    f"Se requiere mínimo: {minimum_role.value}"
                )
                return jsonify({
                    "error": "forbidden",
                    "error_description": f"Requires at least role: {minimum_role.value}",
                }), 403

            return f(*args, **kwargs)
        return decorated
    return decorator


def require_permissions(
    at_least_one: Optional[List[AttributeType]] = None,
    all_required: Optional[List[AttributeType]] = None,
):
    """
    Verifica permisos ABAC del usuario teniendo en cuenta su rol.

    Los permisos efectivos son la unión de:
        - Permisos base del rol (ROLE_PERMISSIONS)
        - Atributos explícitos en UserAttribute

    Los usuarios con Role.ROOT bypasean siempre esta verificación.
    Debe usarse DESPUÉS de @require_oauth_token.

    Args:
        at_least_one: El usuario debe tener AL MENOS UNO de estos permisos.
        all_required: El usuario debe tener TODOS estos permisos.

    Returns:
        403 si el usuario no cumple los requisitos.

    Ejemplo:
        @require_oauth_token
        @require_permissions(at_least_one=[AttributeType.SENTINEL_READ])
        def listar_scans(): ...

        @require_oauth_token
        @require_permissions(all_required=[AttributeType.ACHERON_CREATE, AttributeType.ACHERON_READ])
        def crear_secreto(): ...
    """
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            user_id       = getattr(request, "current_user_id", None)
            user_role_str = getattr(request, "current_user_role", Role.USER.value)

            if user_id is None:
                return jsonify({
                    "error": "forbidden",
                    "error_description": "Authentication required before AttributeType check",
                }), 403

            # Root bypasses all AttributeType checks.
            if user_role_str == Role.ROOT.value:
                return f(*args, **kwargs)

            try:
                effective = _get_effective_permissions(user_id, user_role_str)

                missing_at_least_one: List[AttributeType] = []
                if at_least_one:
                    missing_at_least_one = [p for p in at_least_one if p.db_name not in effective]

                missing_all_required: List[AttributeType] = []
                if all_required:
                    missing_all_required = [p for p in all_required if p.db_name not in effective]

                has_at_least_one = not at_least_one or len(missing_at_least_one) < len(at_least_one)
                has_all_required = not all_required or len(missing_all_required) == 0

                if not has_at_least_one or not has_all_required:
                    _logger.warning(
                        f"Usuario {user_id} (rol={user_role_str}) denegado en {f.__name__}. "
                        f"at_least_one_missing={[p.db_name for p in missing_at_least_one]}, "
                        f"all_required_missing={[p.db_name for p in missing_all_required]}"
                    )
                    return jsonify({
                        "error": "forbidden",
                        "error_description": "Insufficient permissions",
                        "missing_permissions": {
                            "at_least_one": [p.db_name for p in missing_at_least_one],
                            "all_required":  [p.db_name for p in missing_all_required],
                        },
                    }), 403

                _logger.info(
                    f"Usuario {user_id} autorizado para {f.__name__}. "
                    f"at_least_one={at_least_one}, all_required={all_required}"
                )
                return f(*args, **kwargs)

            except Exception as exc:
                _logger.error(f"Error en require_permissions: {exc}")
                return jsonify({
                    "error": "server_error",
                    "error_description": "AttributeType check failed",
                }), 500

        return decorated
    return decorator



def require_attributes(
    at_least_one: Optional[List[AttributeType]] = None,
    all_required: Optional[List[AttributeType]] = None,
):
    """
    Alias de require_permissions() para compatibilidad con código existente.

    Deprecated: usar require_permissions() en código nuevo.
    """
    return require_permissions(at_least_one=at_least_one, all_required=all_required)


def require_auth(
    attrs: Optional[List[AttributeType]] = None,
    mode: str = "any",
):
    """
    Decorador combinado legacy: autentica y verifica permisos en un paso.

    Deprecated: usar @require_oauth_token + @require_permissions() en código nuevo.

    Args:
        attrs: Lista de permisos requeridos.
        mode:  "any" (al menos uno) o "all" (todos requeridos).
    """
    def decorator(f):
        @require_oauth_token
        @wraps(f)
        def decorated(*args, **kwargs):
            user_id       = getattr(request, "current_user_id", None)
            user_role_str = getattr(request, "current_user_role", Role.USER.value)

            if user_id is None:
                return jsonify({"error": "forbidden", "error_description": "Authentication required"}), 403

            if user_role_str == Role.ROOT.value:
                return f(*args, **kwargs)

            try:
                effective = _get_effective_permissions(user_id, user_role_str)
                missing = [a for a in (attrs or []) if a.db_name not in effective]

                if mode == "all":
                    has_permission = not attrs or len(missing) == 0
                else:
                    has_permission = not attrs or len(missing) < len(attrs)

                if not has_permission:
                    _logger.warning(f"Usuario {user_id} denegado en {f.__name__}.")
                    return jsonify({
                        "error": "forbidden",
                        "error_description": "Insufficient permissions",
                        "missing_attributes": [a.db_name for a in missing],
                    }), 403

                return f(*args, **kwargs)

            except Exception as exc:
                _logger.error(f"Error en require_auth: {exc}")
                return jsonify({"error": "server_error", "error_description": "AttributeType check failed"}), 500

        return decorated
    return decorator