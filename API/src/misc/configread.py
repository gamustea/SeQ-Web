import json
import os
from pathlib import Path
from typing import Optional
from enum import Enum

from dotenv import load_dotenv

# Carga el .env si existe (dev local sin Docker).
# En Docker las variables ya están en el entorno, load_dotenv() las respeta.
load_dotenv()


class DirectoryType(Enum):
    """Enumeración de tipos de directorios disponibles"""
    TEMP     = "tempdir"
    LOG      = "logdir"
    RESULT   = "resultdir"
    RESOURCE = "resourcedir"


class ConfigReader:
    """
    Fuente de configuración con prioridad: entorno > SecConfig.json

    Orden de resolución:
        1. Variables de entorno (inyectadas por Docker o cargadas desde .env).
        2. Fallback al SecConfig.json (desarrollo local sin .env).

    Estrategia de búsqueda del JSON (primera ruta que exista gana):
        1. Ruta explícita pasada al constructor.
        2. Relativa a la raíz del paquete: API/src/config/SecConfig.json.
        3. Relativa a este fichero: subiendo hasta src/config/SecConfig.json.
    """

    _DEFAULT_RELATIVE = "API/src/config/SecConfig.json"

    def __init__(self, configs_file: str = _DEFAULT_RELATIVE) -> None:
        self.configs_path = self._resolve(configs_file)

    # ── Resolución de ruta ────────────────────────────────────────────────────

    @staticmethod
    def _resolve(configs_file: str) -> Path:
        explicit = Path(configs_file)
        if explicit.is_absolute() and explicit.exists():
            return explicit
        resolved = explicit.resolve()
        if resolved.exists():
            return resolved

        this_file = Path(__file__).resolve()
        src_dir   = this_file.parent.parent
        from_src  = src_dir / "config" / "SecConfig.json"
        if from_src.exists():
            return from_src

        return resolved

    # ── Lectura del JSON (solo para fallback) ─────────────────────────────────

    def _read_configs(self) -> dict:
        with open(self.configs_path, "r") as f:
            return json.load(f)

    # ── Getters ───────────────────────────────────────────────────────────────

    def get_db_credentials(self) -> tuple:
        """
        Prioridad: variables de entorno → SecConfig.json
        Variables esperadas: POSTGRES_USER, POSTGRES_PASSWORD,
                            POSTGRES_HOST, POSTGRES_DB
        """
        user     = os.getenv("POSTGRES_USER")
        password = os.getenv("POSTGRES_PASSWORD")
        host     = os.getenv("POSTGRES_HOST", "postgres")
        database = os.getenv("POSTGRES_DB")

        if all([user, password, host, database]):
            return (user, password, host, database)

        raise ValueError("Faltan variables de entorno para la base de datos. "
                        "Asegúrate de definir POSTGRES_USER, POSTGRES_PASSWORD, "
                        "POSTGRES_HOST y POSTGRES_DB.")

    def get_directory_of(self, directory_type: DirectoryType) -> str:
        """
        Los directorios no son secretos → siempre desde el JSON.
        """
        configs    = self._read_configs()
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
        """
        Prioridad: variables de entorno → SecConfig.json
        Variables esperadas: JWT_SECRET_KEY, JWT_ALGORITHM,
                            ACCESS_TOKEN_EXPIRY_MINUTES, REFRESH_TOKEN_EXPIRY_DAYS
        """
        secret    = os.getenv("JWT_SECRET_KEY")
        algorithm = os.getenv("JWT_ALGORITHM")
        access    = os.getenv("ACCESS_TOKEN_EXPIRY_MINUTES")
        refresh   = os.getenv("REFRESH_TOKEN_EXPIRY_DAYS")

        if all([secret, algorithm, access, refresh]):
            return (float(access), float(refresh), secret, algorithm)

        raise ValueError("Faltan variables de entorno para OAuth. "
                        "Asegúrate de definir JWT_SECRET_KEY, JWT_ALGORITHM, "
                        "ACCESS_TOKEN_EXPIRY_MINUTES y REFRESH_TOKEN_EXPIRY_DAYS.")

    def get_openvas_config(self) -> dict[str, str]:
        """ 
        Prioridad: variables de entorno → SecConfig.json
        Variables esperadas: OPENVAS_HOST, OPENVAS_PORT,
                            OPENVAS_USERNAME, OPENVAS_PASSWORD
        """
        hostname = os.getenv("OPENVAS_HOST")
        port     = os.getenv("OPENVAS_PORT")
        user     = os.getenv("OPENVAS_USERNAME")
        password = os.getenv("OPENVAS_PASSWORD")

        if all([hostname, port, user, password]):
            return {"hostname": hostname, "port": port,
                    "username": user, "password": password}
        
        raise ValueError("Faltan variables de entorno para OpenVAS. "
                        "Asegúrate de definir OPENVAS_HOST, OPENVAS_PORT, "
                        "OPENVAS_USERNAME y OPENVAS_PASSWORD.")

    def get_aegis_config(self) -> dict[str, str]:
        """
        La config de Aegis (parámetros del modelo, rutas, etc.)
        no son secretos → siempre desde el JSON.
        Excepción: OLLAMA_HOST si se define en el entorno.
        """
        cfg = self._read_configs()["aegis"]

        ollama_host = os.getenv("OLLAMA_HOST")
        if ollama_host:
            cfg["host"] = ollama_host

        return cfg