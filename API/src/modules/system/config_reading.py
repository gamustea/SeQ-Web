"""
config_reading.py
Módulo de lectura de configuración SecOps.
Carga lazy (solo al primer acceso) desde SecOpsConfig.json o variables de entorno.
"""

import json
import os
from functools import wraps
from pathlib import Path


# =============================================================================
# ESTADO DEL MÓDULO
# =============================================================================

_configs: dict | None = None
_configs_path: Path | None = None


# =============================================================================
# DECORADOR LAZY LOAD
# =============================================================================

def _lazy_load(func):
    """Decorador que carga la configuración antes de ejecutar la función."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        global _configs, _configs_path
        if _configs is None:
            if _configs_path is None:
                this_file = Path(__file__).resolve()
                candidates = [
                    this_file.parent.parent.parent.parent / "SecOpsConfig.json",
                    this_file.parent.parent.parent.parent / "SecConfig.json",
                    this_file.parent.parent.parent / "SecOpsConfig.json",
                    this_file.parent.parent.parent / "SecConfig.json",
                    this_file.parent.parent / "SecOpsConfig.json",
                    this_file.parent.parent / "SecConfig.json",
                    this_file.parent / "SecOpsConfig.json",
                    this_file.parent / "SecConfig.json",
                ]
                for candidate in candidates:
                    if candidate.exists():
                        _configs_path = candidate
                        break
                if _configs_path is None:
                    raise FileNotFoundError("No se encontró ningún archivo de configuración.")
            with open(_configs_path, "r", encoding="utf-8") as f:
                _configs = json.load(f)
        return func(*args, **kwargs)
    return wrapper


# =============================================================================
# UTILIDADES
# =============================================================================

def reload() -> None:
    """Fuerza la recarga de la configuración desde el archivo."""
    global _configs, _configs_path
    _configs = None
    _configs_path = None


def is_loaded() -> bool:
    """Indica si la configuración ya ha sido cargada."""
    return _configs is not None


# =============================================================================
# CONFIGURACIÓN DE ENTORNO (sin fallback a JSON)
# =============================================================================

def get_ollama_config() -> tuple[str, str]:
    """Solo variables de entorno."""
    host = os.getenv("OLLAMA_HOST", "http://localhost:11434")
    model = os.getenv("OLLAMA_MODEL", "llama3.2")
    return host, model


def get_oauth_config() -> tuple[float, float, str, str]:
    """Solo variables de entorno."""
    secret = os.getenv("JWT_SECRET_KEY")
    algorithm = os.getenv("JWT_ALGORITHM")
    access = os.getenv("ACCESS_TOKEN_EXPIRY_MINUTES")
    refresh = os.getenv("REFRESH_TOKEN_EXPIRY_DAYS")

    if all([secret, algorithm, access, refresh]):
        return (float(access), float(refresh), secret, algorithm)

    raise ValueError("Faltan variables de entorno para OAuth. "
                "Asegúrate de definir JWT_SECRET_KEY, JWT_ALGORITHM, "
                "ACCESS_TOKEN_EXPIRY_MINUTES y REFRESH_TOKEN_EXPIRY_DAYS.")


def get_openvas_config() -> dict[str, str]:
    """Solo variables de entorno."""
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


# =============================================================================
# CONFIGURACIÓN DE BASE DE DATOS
# =============================================================================

@_lazy_load
def get_db_credentials() -> dict:
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

    return {
        "dialect": _configs.get("dialect", "postgresql+psycopg2"),
        "username": _configs["dbconfig"].get("username"),
        "password": _configs["dbconfig"].get("password"),
        "host": _configs["dbconfig"].get("host", "postgres"),
        "port": str(_configs["dbconfig"].get("port", "5432")),
        "dbname": _configs["dbconfig"].get("dbname")
    }


# =============================================================================
# CONFIGURACIÓN DE DIRECTORIOS
# =============================================================================

@_lazy_load
def get_directory_of(directory_type) -> str:
    dir_key = directory_type.value if hasattr(directory_type, 'value') else directory_type

    env_mapping = {
        "tempdir": "TEMP_DIR",
        "logdir": "LOG_DIR",
        "output": "OUTPUT_DIR",
        "stack": "OUTPUT_DIR",
        "resourcedir": "RESOURCE_DIR",
    }

    env_var = env_mapping.get(dir_key)
    if env_var:
        env_value = os.getenv(env_var)
        if env_value:
            return env_value

    if "." in dir_key:
        parts = dir_key.split(".")
        module_key = parts[0]
        if module_key not in _configs:
            raise ValueError(f"Módulo '{module_key}' no encontrado en la configuración.")
        module_config = _configs[module_key]
        if "directories" not in module_config:
            raise ValueError(f"Directorio '{dir_key}' no encontrado en la configuración.")
        directories = module_config["directories"]
        sub_key = parts[1]
        if sub_key not in directories:
            raise ValueError(f"Directorio '{sub_key}' no encontrado en la configuración.")
        raw_path = directories[sub_key]
    else:
        if dir_key not in _configs.get("general", {}).get("directories", {}):
            raise ValueError(f"Directorio '{dir_key}' no encontrado en la configuración.")
        raw_path = _configs["general"]["directories"][dir_key]

    path = Path(raw_path)

    if not path.is_absolute():
        app_root = Path(__file__).resolve().parent.parent.parent
        path = app_root / path

    return str(path)


# =============================================================================
# CONFIGURACIÓN DE AEGIS
# =============================================================================

@_lazy_load
def get_aegis_config() -> dict:
    return _configs.get("aegis", {})


@_lazy_load
def get_aegis_tips_amount() -> int:
    cfg = _configs.get("aegis", {})
    return int(cfg.get("tipsAmount", 7))


@_lazy_load
def get_aegis_vulnerabilities_antiquity() -> int:
    cfg = _configs.get("aegis", {})
    return int(cfg.get("vulnerabilitiesAntiquity", 5))


@_lazy_load
def get_aegis_brands() -> list[dict]:
    cfg = _configs.get("aegis", {})
    return list(cfg.get("brands", []))


@_lazy_load
def get_aegis_prompts() -> dict:
    aegis = _configs.get("aegis", {})
    return aegis.get("prompts", {})


# =============================================================================
# CONFIGURACIÓN DE SENTINEL
# =============================================================================

@_lazy_load
def get_sentinel_config() -> dict:
    return _configs.get("sentinel", {})


@_lazy_load
def get_prompts_config() -> dict:
    sentinel = _configs.get("sentinel", {})
    
    return {
        "nmap": sentinel.get("nmap", {}).get("prompts", {}),
        "nikto": sentinel.get("nikto", {}).get("prompts", {}),
        "openvas": sentinel.get("openvas", {}).get("prompts", {}),
    }


@_lazy_load
def get_tool_prompts(tool: str) -> dict:
    prompts = get_prompts_config()
    return prompts.get(tool, {})


@_lazy_load
def get_tool_color_palette(tool: str) -> dict:
    sentinel = _configs.get("sentinel", {})
    
    tool_key = tool
    if tool_key not in sentinel:
        return {}
    
    tool_config = sentinel[tool_key]
    return tool_config.get("colorPalette", {})