"""
src - Aliases para backwards compatibility
"""

# Re-exportar desde las nuevas ubicaciones
from src.modules.shared import Base, Document, BaseManager, AIWriter
from src.modules.sentinel import NmapScanManager, NiktoScanManager, OpenVASScanManager

__all__ = [
    'Base',
    'Document',
    'BaseManager',
    'AIWriter',
    'NmapScanManager',
    'NiktoScanManager',
    'OpenVASScanManager',
]