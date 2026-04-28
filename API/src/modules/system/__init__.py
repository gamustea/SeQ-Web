"""
system/__init__.py
Módulo de gestión de configuración de SecOps.
Proporciona endpoints para leer y escribir SecOpsConfig.json.
"""

from .logging import SecOpsLogger
from .platform import PlatformDetector

__all__ = [
    "SecOpsLogger",
    "PlatformDetector"
]