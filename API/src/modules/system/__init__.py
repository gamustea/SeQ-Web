"""
system/__init__.py
Módulo de gestión de configuración de SecOps.
Proporciona endpoints para leer y escribir SecOpsConfig.json.
"""

from .endpoints import system_bp
from .managers import ConfigManager

__all__ = [
    "system_bp",
    "ConfigManager",
]