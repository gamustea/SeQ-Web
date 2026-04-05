import json
from pathlib import Path
from typing import Optional
from enum import Enum

class DirectoryType(Enum):
    """Enumeración de tipos de directorios disponibles"""
    TEMP = "tempdir"
    LOG = "logdir"
    RESULT = "resultdir"
    RESOURCE = "resourcedir"


class ConfigReader:
    """
    Lee SecConfig.json sin importar desde dónde se ejecute el proceso.

    Estrategia de búsqueda (primera que exista gana):
        1. Ruta explícita pasada al constructor (si existe en disco)
        2. Relativa a la raíz del paquete: <repo>/API/src/config/SecConfig.json
            (útil cuando se ejecuta desde la raíz del repositorio en Windows)
        3. Relativa a este mismo fichero: subiendo hasta encontrar src/config/
            (útil dentro del contenedor Docker donde WORKDIR=/app y el código
            está en /app/src/…)
    """

    _DEFAULT_RELATIVE = "API/src/config/SecConfig.json"

    def __init__(self, configs_file: str = _DEFAULT_RELATIVE) -> None:
        self.configs_path = self._resolve(configs_file)

    # ── Resolución de ruta ────────────────────────────────────────────────────

    @staticmethod
    def _resolve(configs_file: str) -> Path:
        # 1. Ruta tal cual (absoluta o relativa al CWD)
        explicit = Path(configs_file)
        if explicit.is_absolute() and explicit.exists():
            return explicit
        resolved = explicit.resolve()
        if resolved.exists():
            return resolved

        # 2. Relativo a este fichero: sube configread.py → misc/ → src/ → app_root
        #    En el contenedor: /app/src/misc/configread.py → /app/src/config/SecConfig.json
        #    En el repo:       API/src/misc/configread.py  → API/src/config/SecConfig.json
        this_file = Path(__file__).resolve()           # …/src/misc/configread.py
        src_dir   = this_file.parent.parent            # …/src/
        from_src  = src_dir / "config" / "SecConfig.json"
        if from_src.exists():
            return from_src

        # 3. Fallback: devolver la ruta resuelta aunque no exista (lanzará error al leer)
        return resolved

    # ── Lectura ───────────────────────────────────────────────────────────────

    def read_configs(self) -> dict:
        with open(self.configs_path, "r") as config_file:
            configs = json.load(config_file)
        return configs

    # ── Getters de sección ────────────────────────────────────────────────────

    def get_db_crendetials(self) -> tuple:
        configs = self.read_configs()
        username = configs["dbconfig"]["username"]
        password = configs["dbconfig"]["password"]
        host     = configs["dbconfig"]["host"]
        database = configs["dbconfig"]["dbname"]
        return (username, password, host, database)

    def get_directory_of(self, directory_type: DirectoryType) -> str:
        """
        Devuelve la ruta del directorio especificado en la configuración.
        Si la ruta guardada en el JSON es relativa, se interpreta como
        relativa a la raíz del paquete (directorio padre de src/).
        """
        configs    = self.read_configs()
        directories = configs["directories"]

        dir_key = directory_type.value
        if dir_key not in directories:
            raise ValueError(f"Directorio '{dir_key}' no encontrado en la configuración.")

        raw_path = directories[dir_key]
        path     = Path(raw_path)

        if not path.is_absolute():
            app_root = Path(__file__).resolve().parent.parent.parent
            path = app_root / path

        return str(path)

    def get_oauth_config(self) -> tuple[float, float, str, str]:
        configs       = self.read_configs()
        oauth_configs = configs.get("oauth", {})
        return (
            float(oauth_configs["access_token_expiry_minutes"]),
            float(oauth_configs["refresh_token_expiry_days"]),
            oauth_configs["jwt_secret_key"],
            oauth_configs["jwt_algorithm"],
        )

    def get_openvas_config(self) -> dict[str, str]:
        return self.read_configs()["openvas"]

    def get_aegis_config(self) -> dict[str, str]:
        return self.read_configs()["aegis"]