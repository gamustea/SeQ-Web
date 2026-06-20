"""
src - Aliases para backwards compatibility
"""

from src.modules.shared import Base, Document, BaseManager
from src.modules.sentinel import NmapScanManager, NiktoScanManager, OpenVASScanManager

__all__ = [
    'Base',
    'Document',
    'BaseManager',
    'NmapScanManager',
    'NiktoScanManager',
    'OpenVASScanManager',
]