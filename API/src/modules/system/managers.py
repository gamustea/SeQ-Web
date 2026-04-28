"""
system/managers.py
Gestor de configuración de SecOps.
Lee y escribe el archivo SecOpsConfig.json.
"""

import json
from pathlib import Path
from typing import Any, Dict, Optional

from src.modules.shared import BaseManager


class ConfigManager(BaseManager):
    """Gestor para leer y escribir configuración de SecOps."""

    CONFIG_FILE = "SecOpsConfig.json"

    def __init__(self):
        super().__init__()
        self._config_path = self._find_config_file()

    def _find_config_file(self) -> Path:
        """Encuentra el archivo de configuración SecOpsConfig.json."""
        current = Path(__file__).parent
        for _ in range(5):
            config_file = current / self.CONFIG_FILE
            if config_file.exists():
                return config_file
            current = current.parent
        raise FileNotFoundError(f"{self.CONFIG_FILE} not found in project hierarchy")

    def get_config(self) -> Dict[str, Any]:
        """Lee y devuelve toda la configuración."""
        self._check_session()
        try:
            with open(self._config_path, "r", encoding="utf-8") as f:
                config = json.load(f)
            self.logger.info(f"Configuración leída desde {self._config_path}")
            return config
        except FileNotFoundError as e:
            self.logger.error(f"Archivo de configuración no encontrado: {e}")
            raise
        except json.JSONDecodeError as e:
            self.logger.error(f"Error decodificando JSON: {e}")
            raise
        except Exception as e:
            self.logger.error(f"Error leyendo configuración: {e}")
            raise

    def update_config(self, new_config: Dict[str, Any]) -> Dict[str, Any]:
        """Guarda la configuración actualizada."""
        self._check_session()
        try:
            with open(self._config_path, "w", encoding="utf-8") as f:
                json.dump(new_config, f, indent=2, ensure_ascii=False)
                f.flush()
            self.logger.info(f"Configuración guardada en {self._config_path}")
            return new_config
        except Exception as e:
            self.logger.error(f"Error guardando configuración: {e}")
            raise