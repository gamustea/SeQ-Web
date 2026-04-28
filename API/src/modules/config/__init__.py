"""
config/__init__.py
Módulo de gestión de configuración de SecOps.
Proporciona endpoints para leer y escribir SecOpsConfig.json.
"""

from .endpoints import config_bp
from .managers import ConfigManager

__all__ = [
    "config_bp",
    "ConfigManager",
]