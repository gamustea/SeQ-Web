"""
src - Aliases para backwards compatibility

Permite que los imports antiguos funcionen:
- from src.core.model import X  -> from src.modules.shared import X (partial)
- from src.misc import X     -> from src.modules.misc import X
- from src.logic.managers import X -> from src.modules.shared import X
"""

# Re-exportar desde las nuevas ubicaciones
from src.modules.shared import Base, Document, BaseManager, AIWriter
from src.modules.misc import (
    ConfigReader,
    SecOpsLogger,
    IPValidator,
    PortValidator,
    normalize_target,
    DirectoryType,
    SentinelTool,
)
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
    'ConfigReader',
    'SecOpsLogger',
    'IPValidator',
    'PortValidator',
    'normalize_target',
    'DirectoryType',
    'SentinelTool',
    'UserManager',
    'OAuthTokenManager',
    'NmapScanManager',
    'NiktoScanManager',
    'OpenVASScanManager',
]