
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
    TEMP            = "tempdir"
    LOG             = "logdir"
    RESOURCE        = "resourcedir"
    
    STACK_AEGIS     = "aegis.stack"
    OUTPUT_AEGIS    = "aegis.output"
    
    OUTPUT_SENTINEL = "sentinel.output"


class SentinelTool(Enum):
    """Enumeración de herramientas disponibles en Sentinel"""
    NMAP    = "nmap"
    NIKTO   = "nikto"
    OPENVAS = "openvas"


class DirectoryChecker:

    def __init__(self):
        pass

    def verify_directory(self, directory: DirectoryType) -> Path:
        dir_path = Path(ConfigReader.get_directory_of(directory)).resolve()
        dir_path.mkdir(parents=True, exist_ok=True)

        return dir_path


class ConfigReader:
    """
    Singleton para gestión de configuración.
    
    La primera vez que se accede a la configuración, se lee del archivo JSON
    y se guarda en memoria. Las siguientes lecturas son de memoria.
    
    Orden de resolución:
        1. Variables de entorno (inyectadas por Docker o cargadas desde .env).
        2. Fallback al SecOpsConfig.json (desarrollo local sin .env).
    """

    _instance = None
    _configs: dict = {}
    _configs_path: Path = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    @classmethod
    def _resolve_config_path(cls) -> Path:
        if cls._configs_path is not None:
            return cls._configs_path
        
        this_file = Path(__file__).resolve()
        
        candidates = [
            this_file.parent.parent.parent / "SecOpsConfig.json",
            this_file.parent.parent.parent / "SecConfig.json",
            this_file.parent.parent / "SecOpsConfig.json",
            this_file.parent.parent / "SecConfig.json",
            this_file.parent / "SecOpsConfig.json",
            this_file.parent / "SecConfig.json",
        ]
        
        for candidate in candidates:
            if candidate.exists():
                cls._configs_path = candidate
                return cls._configs_path
        
        raise FileNotFoundError("No se encontró ningún archivo de configuración.")

    @classmethod
    def _load_configs(cls) -> dict:
        if not cls._configs:
            path = cls._resolve_config_path()
            with open(path, "r", encoding="utf-8") as f:
                cls._configs = json.load(f)
        return cls._configs

    @classmethod
    def reload(cls) -> None:
        """Fuerza la recarga de la configuración desde el archivo."""
        cls._configs = {}
        cls._configs_path = None
        cls._load_configs()

    # ── Getters ───────────────────────────────────────────────────────────────

    @staticmethod
    def get_ollama_config() -> tuple[str, str]:
        """
        Obtiene la configuración de Ollama (host y modelo) desde variables de entorno.
        
        Variables de entorno:
            OLLAMA_HOST: URL del servidor Ollama (default: http://localhost:11434)
            OLLAMA_MODEL: Nombre del modelo a usar (default: llama3.2)
        
        Returns:
            tuple[str, str]: (host, model)
        """
        host = os.getenv("OLLAMA_HOST", "http://localhost:11434")
        model = os.getenv("OLLAMA_MODEL", "llama3.2")
        return host, model

    @staticmethod
    def get_db_credentials() -> dict:
        """
        Prioridad: variables de entorno → SecConfig.json
        Variables esperadas: POSTGRES_USER, POSTGRES_PASSWORD,
                            POSTGRES_HOST, POSTGRES_DB, POSTGRES_PORT, POSTGRES_DIALECT
        
        Returns:
            dict: {dialect, username, password, host, port, dbname}
        """
        user = os.getenv("POSTGRES_USER")
        password = os.getenv("POSTGRES_PASSWORD")
        host = os.getenv("POSTGRES_HOST", "postgres")
        database = os.getenv("POSTGRES_DB")
        port = os.getenv("POSTGRES_PORT", "5432")
        dialect = os.getenv("POSTGRES_DIALECT", "postgresql+psycopg2")

        if all([user, password, host, database]):
            return {
                "dialect": dialect,
                "username": user,
                "password": password,
                "host": host,
                "port": port,
                "dbname": database
            }

        configs = ConfigReader._load_configs()
        dbconfig = configs["dbconfig"]

        return {
            "dialect": dbconfig.get("dialect", "postgresql+psycopg2"),
            "username": dbconfig.get("username"),
            "password": dbconfig.get("password"),
            "host": dbconfig.get("host", "postgres"),
            "port": str(dbconfig.get("port", "5432")),
            "dbname": dbconfig.get("dbname")
        }

    @staticmethod
    def get_directory_of(directory_type: DirectoryType) -> str:
        """
        Los directorios no son secretos → siempre desde el JSON.
        
        Args:
            directory_type: DirectoryType enum member.
            
        Returns:
            Absolute path string to the directory.
        """
        configs = ConfigReader._load_configs()
        
        dir_key = directory_type.value

        if "." in dir_key:
            parts = dir_key.split(".")
            module_key = parts[0]
            if module_key not in configs:
                raise ValueError(f"Módulo '{module_key}' no encontrado en la configuración.")
            module_config = configs[module_key]
            if "directories" not in module_config:
                raise ValueError(f"Directorio '{dir_key}' no encontrado en la configuración.")
            directories = module_config["directories"]
            sub_key = parts[1]
            if sub_key not in directories:
                raise ValueError(f"Directorio '{sub_key}' no encontrado en la configuración.")
            raw_path = directories[sub_key]
        else:
            if dir_key not in configs.get("general", {}).get("directories", {}):
                raise ValueError(f"Directorio '{dir_key}' no encontrado en la configuración.")
            raw_path = configs["general"]["directories"][dir_key]

        path = Path(raw_path)

        if not path.is_absolute():
            app_root = Path(__file__).resolve().parent.parent.parent
            path = app_root / path

        return str(path)

    @staticmethod
    def get_oauth_config() -> tuple[float, float, str, str]:
        """
        Prioridad: variables de entorno → SecConfig.json
        Variables esperadas: JWT_SECRET_KEY, JWT_ALGORITHM,
                            ACCESS_TOKEN_EXPIRY_MINUTES, REFRESH_TOKEN_EXPIRY_DAYS
        """
        secret = os.getenv("JWT_SECRET_KEY")
        algorithm = os.getenv("JWT_ALGORITHM")
        access = os.getenv("ACCESS_TOKEN_EXPIRY_MINUTES")
        refresh = os.getenv("REFRESH_TOKEN_EXPIRY_DAYS")

        if all([secret, algorithm, access, refresh]):
            return (float(access), float(refresh), secret, algorithm)

        raise ValueError("Faltan variables de entorno para OAuth. "
                    "Asegúrate de definir JWT_SECRET_KEY, JWT_ALGORITHM, "
                    "ACCESS_TOKEN_EXPIRY_MINUTES y REFRESH_TOKEN_EXPIRY_DAYS.")

    @staticmethod
    def get_openvas_config() -> dict[str, str]:
        """ 
        Prioridad: variables de entorno → SecConfig.json
        Variables esperadas: OPENVAS_HOST, OPENVAS_PORT,
                            OPENVAS_USERNAME, OPENVAS_PASSWORD
        """
        hostname = os.getenv("OPENVAS_HOST")
        port = os.getenv("OPENVAS_PORT")
        user = os.getenv("OPENVAS_USERNAME")
        password = os.getenv("OPENVAS_PASSWORD")

        if all([hostname, port, user, password]):
            return {"hostname": hostname, "port": port,
                    "username": user, "password": password}
        
        raise ValueError("Faltan variables de entorno para OpenVAS. "
                    "Asegúrate de definir OPENVAS_HOST, OPENVAS_PORT, "
                    "OPENVAS_USERNAME y OPENVAS_PASSWORD.")

    @staticmethod
    def get_aegis_config() -> dict[str, str]:
        """
        La config de Aegis (parámetros del modelo, etc.)
        no son secretos → siempre desde el JSON.
        Excepción: OLLAMA_HOST si se define en el entorno.
        """
        cfg = ConfigReader._load_configs()["aegis"].copy()
        if "directories" in cfg:
            del cfg["directories"]
        if "prompts" in cfg:
            del cfg["prompts"]

        return cfg

    @staticmethod
    def get_aegis_prompts() -> dict:
        """
        Obtiene la configuración de prompts para Aegis desde SecOpsConfig.json.
        
        Returns:
            dict: Diccionario con 'system' key.
        """
        configs = ConfigReader._load_configs()
        aegis = configs.get("aegis", {})
        return aegis.get("prompts", {})

    @staticmethod
    def get_sentinel_config() -> dict:
        """
        Obtiene la configuración de Sentinel desde SecOpsConfig.json.
        
        Returns:
            dict: Configuración completa de sentinel.
        """
        configs = ConfigReader._load_configs()
        return configs.get("sentinel", {})

    @staticmethod
    def get_prompts_config() -> dict:
        """
        Obtiene la configuración de prompts para AI analysis desde SecOpsConfig.json.
        
        Returns:
            dict: Dictionary containing prompts for different scanners.
                    Each scanner has 'system' and 'userTemplate' keys.
        """
        configs = ConfigReader._load_configs()
        sentinel = configs.get("sentinel", {})
        
        return {
            "nmap": sentinel.get("nmap", {}).get("prompts", {}),
            "nikto": sentinel.get("nikto", {}).get("prompts", {}),
            "openvas": sentinel.get("openvas", {}).get("prompts", {}),
        }

    @staticmethod
    def get_tool_prompts(tool: SentinelTool) -> dict:
        """
        Obtiene la configuración de prompts para un tool específico.
        
        Args:
            tool: SentinelTool enum member.
            
        Returns:
            dict: Diccionario con 'system' y 'userTemplate' keys.
        """
        prompts = ConfigReader.get_prompts_config()
        return prompts.get(tool.value, {})

    @staticmethod
    def get_tool_color_palette(tool: SentinelTool) -> dict:
        """
        Obtiene la paleta de colores para un tool específico.
        
        Args:
            tool: SentinelTool enum member.
            
        Returns:
            dict: Diccionario con las couleurs (black, dark, main, secondary, light, white).
        """
        configs = ConfigReader._load_configs()
        sentinel = configs.get("sentinel", {})
        
        tool_key = tool.value
        if tool_key not in sentinel:
            return {}
        
        tool_config = sentinel[tool_key]
        return tool_config.get("colorPalette", {})


class SecOpsLogger:

    def __init__(self, name=None, level=logging.DEBUG):
        """
        Inicializa un logger con nombre, nivel y archivo de log opcional.
        """
        self.logger = logging.getLogger(name)
        self.logger.setLevel(level)

        if not self.logger.hasHandlers():
            formatter = logging.Formatter(
                "[+] [%(levelname)s] (%(asctime)s) %(message)s"
            )

            console_handler = logging.StreamHandler()
            console_handler.setFormatter(formatter)
            self.logger.addHandler(console_handler)

            path = Path(ConfigReader.get_directory_of(DirectoryType.LOG)).resolve()
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