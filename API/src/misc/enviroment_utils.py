
import json
import os
import logging
import platform
import shutil

from pathlib import Path
from enum import Enum
from dotenv import load_dotenv
from typing import List,Optional
from pathlib import Path

load_dotenv()

class PlatformType(Enum):
    """Enumeración de tipos de plataforma"""
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"
    UNKNOWN = "unknown"


class PlatformDetector:
    """
    Detecta la plataforma actual y proporciona utilidades
    para construir comandos adaptados al sistema operativo.
    """

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._platform = cls._detect_platform()
            cls._instance._wsl_available = cls._check_wsl()
        return cls._instance

    @staticmethod
    def _detect_platform() -> PlatformType:
        system = platform.system().lower()
        if system == "windows":
            return PlatformType.WINDOWS
        elif system == "linux":
            return PlatformType.LINUX
        elif system == "darwin":
            return PlatformType.MACOS
        return PlatformType.UNKNOWN

    @staticmethod
    def _check_wsl() -> bool:
        if platform.system().lower() != "windows":
            return False
        return shutil.which("wsl") is not None

    @property
    def platform(self) -> PlatformType:
        return self._platform

    @property
    def is_windows(self) -> bool:
        return self._platform == PlatformType.WINDOWS

    @property
    def is_linux(self) -> bool:
        return self._platform == PlatformType.LINUX

    @property
    def is_macos(self) -> bool:
        return self._platform == PlatformType.MACOS

    @property
    def wsl_available(self) -> bool:
        return self._instance._wsl_available if hasattr(self, '_instance') else self._wsl_available

    def wrap_wsl_command(self, cmd: List[str], wsl_distro: str = "Ubuntu", wsl_user: str = "gmiga") -> List[str]:
        """
        Envuelve un comando Linux para ejecutarlo a través de WSL en Windows.
        """
        if not self.is_windows or not self._wsl_available:
            return cmd
        return ["wsl", "-d", wsl_distro, "-u", wsl_user] + cmd

    def convert_path_to_wsl(self, windows_path: str) -> str:
        """
        Convierte una ruta de Windows a formato WSL (/mnt/c/...).
        """
        if not self.is_windows:
            return windows_path
        path = windows_path.replace("\\", "/")
        if len(path) > 2 and path[1] == ":":
            drive = path[0].lower()
            return f"/mnt/{drive}/{path[3:]}"
        return path


class DirectoryType(Enum):
    """Enumeración de tipos de directorios disponibles"""
    TEMP     = "tempdir"
    LOG      = "logdir"
    RESULT   = "resultdir"
    RESOURCE = "resourcedir"


class DirectoryChecker:

    def __init__(self):
        self.config_reader = ConfigReader()

    def verify_directory(self, directory: DirectoryType) -> Path:
        dir_path = Path(self.config_reader.get_directory_of(directory)).resolve()
        dir_path.mkdir(parents=True, exist_ok=True)

        return dir_path


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


class SecOpsLogger:

    def __init__(self, name=None, level=logging.DEBUG):
        """
        Inicializa un logger con nombre, nivel y archivo de log opcional.
        """
        self.logger = logging.getLogger(name)
        self.logger.setLevel(level)

        reader = ConfigReader()

        if not self.logger.hasHandlers():
            formatter = logging.Formatter(
                "[+] [%(levelname)s] (%(asctime)s) %(message)s"
            )

            console_handler = logging.StreamHandler()
            console_handler.setFormatter(formatter)
            self.logger.addHandler(console_handler)

            path = Path(reader.get_directory_of(DirectoryType.LOG)).resolve()
            path.mkdir(parents=True, exist_ok=True)
            log_file = path / "secops.log"

            if log_file:
                file_handler = logging.FileHandler(log_file)
                file_handler.setFormatter(formatter)
                self.logger.addHandler(file_handler)

    def get_logger(self):
        """
        Devuelve el logger configurado.
        """
        return self.logger