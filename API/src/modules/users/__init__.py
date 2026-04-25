"""
src.modules.users - Módulo de gestión de usuarios y autenticación

Exponente:
    - UserManager: Gestión de usuarios
    - OAuthTokenManager: Gestión de tokens
    - Modelos: User, Person, AccessToken, RefreshToken
    - Endpoints: users_bp, oauth_bp
"""

from contextlib import contextmanager

from .model import (
    Person,
    Rol,
    User,
    AccessToken,
    RefreshToken,
)
from .permissions import require_oauth_token


def get_user_manager():
    from .managers import UserManager
    @contextmanager
    def _um():
        um = UserManager()
        try:
            yield um
        finally:
            um.close_session()
    return _um()

def get_oauth_manager():
    from .managers import OAuthTokenManager
    @contextmanager
    def _om():
        om = OAuthTokenManager()
        try:
            yield om
        finally:
            om.close_session()
    return _om()

def get_user_endpoints():
    from .endpoints import users_bp
    return users_bp

def get_oauth_endpoints():
    from .endpoints import oauth_bp
    return oauth_bp


# For backwards compatibility - lazily loaded at first access
class _LazyLoader:
    _users_bp = None
    _oauth_bp = None
    
    @property
    def users_bp(self):
        if self._users_bp is None:
            from .endpoints import users_bp
            self._users_bp = users_bp
        return self._users_bp
    
    @property
    def oauth_bp(self):
        if self._oauth_bp is None:
            from .oauth_endpoints import oauth_bp
            self._oauth_bp = oauth_bp
        return self._oauth_bp

_loader = _LazyLoader()

# For backwards compatibility - these load lazily on first access
def __getattr__(name):
    if name == "users_bp":
        return _loader.users_bp
    if name == "oauth_bp":
        return _loader.oauth_bp
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    # Models
    "Person",
    "Rol",
    "User",
    "AccessToken",
    "RefreshToken",
    # Lazy getters
    "get_user_manager",
    "get_oauth_manager",
    "get_user_endpoints",
    "get_oauth_endpoints",
    # For backwards compatibility
    "users_bp",
    "oauth_bp",
]