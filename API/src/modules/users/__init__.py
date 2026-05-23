"""
src.modules.users - Módulo de gestión de usuarios y autenticación

Exponente:
    - UserManager: Gestión de usuarios
    - OAuthTokenManager: Gestión de tokens
    - Modelos: User, AccessToken, RefreshToken
    - Endpoints: users_bp, oauth_bp
"""

from .model import (
    User,
    AccessToken,
    RefreshToken,
    UserAttribute,
)
from .services import require_oauth_token, require_attributes, require_role, AttributeType
from .endpoints import oauth_bp, users_bp, get_current_user
from .managers import UserManager, OAuthTokenManager


class _LazyLoader:
    _users_bp = None
    _oauth_bp = None

    @property
    def users_bp(self):
        if self._users_bp is None:
            self._users_bp = users_bp
        return self._users_bp

    @property
    def oauth_bp(self):
        if self._oauth_bp is None:
            self._oauth_bp = oauth_bp
        return self._oauth_bp

_loader = _LazyLoader()

def __getattr__(name):
    if name == "users_bp":
        return _loader.users_bp
    if name == "oauth_bp":
        return _loader.oauth_bp
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "User",
    "AccessToken",
    "RefreshToken",
    "UserAttribute",
    "UserManager",
    "OAuthTokenManager",
    "users_bp",
    "oauth_bp",
    "require_oauth_token",
    "require_attributes",
    "require_role",
    "AttributeType",
    "get_current_user"
]
