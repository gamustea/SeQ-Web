"""
src - Aliases para backwards compatibility
"""

# Re-exportar desde las nuevas ubicaciones
from src.modules.shared import Base, Document, BaseManager, AIWriter
from src.modules.sentinel import NmapScanManager, NiktoScanManager, OpenVASScanManager

# Lazy imports for user managers to avoid circular import
def _get_user_managers():
    from src.modules.users import get_user_manager, get_oauth_manager
    UserManager = get_user_manager()
    OAuthTokenManager = get_oauth_manager()
    return UserManager, OAuthTokenManager

def _lazy_user_manager():
    return _get_user_managers()[0]

def _lazy_oauth_manager():
    return _get_user_managers()[1]

# For backwards compatibility
UserManager = _lazy_user_manager
OAuthTokenManager = _lazy_oauth_manager

__all__ = [
    'Base',
    'Document', 
    'BaseManager',
    'AIWriter',
    'CR',
    'SecOpsLogger',
    'normalize_target',
    'UserManager',
    'OAuthTokenManager',
    'NmapScanManager',
    'NiktoScanManager',
    'OpenVASScanManager',
]