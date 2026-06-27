"""
config_reading.py
Módulo de lectura de configuración SecOps.
Carga lazy (solo al primer acceso) desde SecOpsConfig.json o variables de entorno.
"""

import json
import os

from enum import Enum
from functools import wraps
from pathlib import Path
from dotenv import load_dotenv
from dataclasses import dataclass

from typing import Optional

from src.modules.shared._exceptions import IllegalStateError

load_dotenv()

# =============================================================================
# ESTADO DEL MÓDULO
# =============================================================================

_configs: dict | None = None
_configs_path: Path | None = None

# =============================================================================
# ENUMERACIONES ÚTILES
# =============================================================================

class DirectoryType(Enum):
    """Enumeración de tipos de directorios disponibles"""
    TEMP               = "tempdir"
    LOG                = "logdir"

    STACK_AEGIS        = "aegis.stack"
    OUTPUT_AEGIS       = "aegis.output"

    OUTPUT_SENTINEL    = "sentinel.output"
    CSV_SENTINEL       = "sentinel.csv"
    RESOURCES_SENTINEL = "sentinel.resources"


# =============================================================================
# CLASES ÚTILES
# =============================================================================

@dataclass(frozen=True)
class AppContext():
    shutdown_time: int
    create_database: bool
    debug: bool
    host: str
    port: int


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
# CONFIGURACIÓN DE ENTORNO
# =============================================================================

def get_ollama_environment() -> tuple[str, str]:
    """Solo variables de entorno."""
    host = os.getenv("OLLAMA_HOST", "http://localhost:11434")
    model = os.getenv("OLLAMA_MODEL", "llama3.2")
    return host, model


def get_openai_environment() -> dict[str, str]:
    """Credenciales de OpenAI desde variables de entorno.

    Returns:
        dict con 'api_key', 'model' y 'base_url' (este último opcional, "").

    Raises:
        ValueError: Si falta OPENAI_API_KEY.
    """
    api_key = os.getenv("OPENAI_API_KEY")
    model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    base_url = os.getenv("OPENAI_BASE_URL", "")

    if not api_key:
        raise ValueError(
            "Falta la variable de entorno OPENAI_API_KEY. "
            "Defínela en el archivo .env junto a las credenciales de Ollama."
        )

    return {"api_key": api_key, "model": model, "base_url": base_url}


def get_oauth_config() -> tuple[float, float, Optional[str], Optional[str]]:
    """Solo variables de entorno."""
    secret      = os.getenv("JWT_SECRET_KEY")
    algorithm   = os.getenv("JWT_ALGORITHM")
    access      = os.getenv("ACCESS_TOKEN_EXPIRY_MINUTES") or ""
    refresh     = os.getenv("REFRESH_TOKEN_EXPIRY_DAYS") or ""

    if not all([secret, algorithm, access, refresh]):
        raise ValueError(
            "Faltan variables de entorno para OAuth. "
            "Asegúrate de definir JWT_SECRET_KEY, JWT_ALGORITHM, "
            "ACCESS_TOKEN_EXPIRY_MINUTES y REFRESH_TOKEN_EXPIRY_DAYS."
        )

    return (float(access), float(refresh), secret, algorithm)


def get_openvas_environment() -> dict[str, str]:
    """Solo variables de entorno."""
    hostname    = os.getenv("OPENVAS_HOST")
    port        = os.getenv("OPENVAS_PORT")
    user        = os.getenv("OPENVAS_USERNAME")
    password    = os.getenv("OPENVAS_PASSWORD")

    if all([hostname, port, user, password]):
        return {
            "hostname": hostname,
            "port": port,
            "username": user,
            "password": password
        } # type: ignore

    raise ValueError("Faltan variables de entorno para OpenVAS. "
                "Asegúrate de definir OPENVAS_HOST, OPENVAS_PORT, "
                "OPENVAS_USERNAME y OPENVAS_PASSWORD.")


def _as_bool(value: str | bool | None, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes")


def get_app_context() -> AppContext:
    shutdown_time   = os.getenv("SHUTDOWN_TIMEOUT", "30")
    create_database = os.getenv("CREATE_DATABASE", "false")
    debug           = os.getenv("DEBUG", "false")
    host            = os.getenv("HOST", "0.0.0.0")
    port            = os.getenv("PORT", "5000")

    return AppContext(
        shutdown_time   = int(shutdown_time),
        create_database = _as_bool(create_database),
        debug           = _as_bool(debug),
        host            = host,
        port            = int(port),
    )

# =============================================================================
# CONFIGURACIÓN DE BASE DE DATOS
# =============================================================================

def get_db_credentials() -> dict:
    """Devuelve credenciales de BD desde variables de entorno (.env).

    Todas las credenciales son secretos y viven exclusivamente en .env:
    POSTGRES_USER, POSTGRES_PASSWORD, POSTGRES_HOST, POSTGRES_DB, POSTGRES_PORT,
    POSTGRES_DIALECT.
    """
    user     = os.getenv("POSTGRES_USER")
    password = os.getenv("POSTGRES_PASSWORD")
    host     = os.getenv("POSTGRES_HOST", "postgres")
    database = os.getenv("POSTGRES_DB")
    port     = os.getenv("POSTGRES_PORT", "5432")
    dialect  = os.getenv("POSTGRES_DIALECT", "postgresql+psycopg2")

    if not all([user, password, database]):
        raise EnvironmentError(
            "Variables de entorno requeridas no encontradas: "
            "POSTGRES_USER, POSTGRES_PASSWORD, POSTGRES_DB"
        )

    return {
        "dialect":  dialect,
        "username": user,
        "password": password,
        "host":     host,
        "port":     port,
        "dbname":   database,
    }


# =============================================================================
# CONFIGURACIÓN DE DIRECTORIOS
# =============================================================================

def verify_directory(directory: DirectoryType) -> Path:
    dir_name = get_directory_of(directory)
    dir_path = Path(dir_name).resolve()
    dir_path.mkdir(parents=True, exist_ok=True)

    return dir_path

@_lazy_load
def get_directory_of(directory_type) -> str:
    if _configs is None:
        raise IllegalStateError("'_configs' detectado como nulo")

    dir_key = directory_type.value if hasattr(directory_type, 'value') else directory_type

    env_mapping = {
        "tempdir": "TEMP_DIR",
        "logdir": "LOG_DIR",
        "output": "OUTPUT_DIR",
        "stack": "OUTPUT_DIR",
        "sentinel.csv": "CSV_SENTINEL_DIR",
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
    if _configs is None:
        raise IllegalStateError("'_configs' detectado como nulo")

    return _configs.get("aegis", {})

@_lazy_load
def get_aegis_tips_amount() -> int:
    if _configs is None:
        raise IllegalStateError("'_configs' detectado como nulo")

    cfg = _configs.get("aegis", {})
    return int(cfg.get("tipsAmount", 7))

@_lazy_load
def get_aegis_vulnerabilities_antiquity() -> int:
    if _configs is None:
        raise IllegalStateError("'_configs' detectado como nulo")

    cfg = _configs.get("aegis", {})
    return int(cfg.get("vulnerabilitiesAntiquity", 5))

@_lazy_load
def get_aegis_brands() -> list[dict]:
    if _configs is None:
        raise IllegalStateError("'_configs' detectado como nulo")

    cfg = _configs.get("aegis", {})
    return list(cfg.get("brands", []))

@_lazy_load
def get_aegis_prompts() -> dict:
    if _configs is None:
        raise IllegalStateError(f"_configs encontrado como None")

    aegis = _configs.get("aegis", {})
    return aegis.get("prompts", {})


# =============================================================================
# CONFIGURACIÓN DE IA (scribe)
# =============================================================================

@_lazy_load
def get_ai_config() -> dict:
    """Devuelve el bloque 'ai' de SecOpsConfig.json (puede estar vacío)."""
    if _configs is None:
        raise IllegalStateError("'_configs' detectado como nulo")

    return _configs.get("ai", {})


@_lazy_load
def get_ai_strategy_for(module: str | None = None) -> str:
    """Resuelve la estrategia de IA para un módulo.

    Busca primero un override por módulo en ``ai.modules.<module>`` y, si no
    existe, devuelve ``ai.defaultStrategy`` (o 'ollama' como último recurso).

    Args:
        module: Nombre del módulo consumidor ('aegis', 'sentinel', …).

    Returns:
        Nombre de la estrategia ('ollama' | 'openai' | …).
    """
    ai_cfg = get_ai_config()
    default = ai_cfg.get("defaultStrategy", "ollama")
    if module:
        return ai_cfg.get("modules", {}).get(module, default)
    return default


# =============================================================================
# CONFIGURACIÓN DE SENTINEL
# =============================================================================

@_lazy_load
def get_sentinel_config() -> dict:
    if _configs is None:
        raise IllegalStateError("'_configs' detectado como nulo")

    return _configs.get("sentinel", {})

@_lazy_load
def get_prompts_config() -> dict:
    if _configs is None:
        raise IllegalStateError("'_configs' detectado como nulo")

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
def get_tool_color_palette(tool) -> dict:
    from src.modules.sentinel.services.reports import SentinelTool
    if _configs is None:
        raise IllegalStateError("'_configs' detectado como nulo")

    sentinel = _configs.get("sentinel", {})

    tool_key = tool
    if tool_key not in sentinel:
        return {}

    tool_config = sentinel[tool_key]
    return tool_config.get("colorPalette", {})

@_lazy_load
def are_local_ips_allowed() -> bool:
    if _configs is None:
        raise IllegalStateError("'_configs' detectado como None")

    sentinel = _configs.get("sentinel", {})
    are_allowed = sentinel.get("areLocalIpsAllowed", None)

    if are_allowed is None:
        return False
    return are_allowed is True or str(are_allowed).lower() == "true"

@_lazy_load
def get_openvas_scan_configs() -> dict[str, str]:
    configs = get_sentinel_config()
    return configs["openvas"]["toolConfigs"]["scanConfigs"]

@_lazy_load
def get_openvas_port_list() -> dict[str, str]:
    configs = get_sentinel_config()
    return configs["openvas"]["toolConfigs"]["portList"]

@_lazy_load
def is_host_reachability_check_enabled() -> bool:
    sentinel = _configs.get("sentinel", {}) if _configs else {}
    check_cfg = sentinel.get("hostReachabilityCheck", {})
    enabled = check_cfg.get("enabled", True)
    return enabled is True or str(enabled).lower() == "true"

@_lazy_load
def get_host_reachability_check_timeout() -> float:
    sentinel = _configs.get("sentinel", {}) if _configs else {}
    check_cfg = sentinel.get("hostReachabilityCheck", {})
    return float(check_cfg.get("timeout", 3.0))

@_lazy_load
def get_host_reachability_check_port() -> int:
    sentinel = _configs.get("sentinel", {}) if _configs else {}
    check_cfg = sentinel.get("hostReachabilityCheck", {})
    return int(check_cfg.get("port", 80))

@_lazy_load
def get_sentinel_csv_dir() -> str:
    return get_directory_of(DirectoryType.CSV_SENTINEL)


@_lazy_load
def get_sentinel_default_folder_name() -> str:
    """Devuelve el nombre mostrado para la carpeta virtual de escaneos sueltos."""
    if _configs is None:
        raise IllegalStateError("'_configs' detectado como nulo")

    sentinel = _configs.get("sentinel", {})
    return sentinel.get("folders", {}).get("defaultFolderName", "Sin carpeta")


@_lazy_load
def get_sentinel_history_size() -> int:
    """Número de escaneos recientes a considerar en las estadísticas históricas."""
    sentinel = _configs.get("sentinel", {}) if _configs else {}
    return int(sentinel.get("history", {}).get("maxScans", 5))


def _traceroute_cfg() -> dict:
    sentinel = _configs.get("sentinel", {}) if _configs else {}
    return sentinel.get("traceroute", {})


@_lazy_load
def get_sentinel_traceroute_cache_hours() -> float:
    """Horas que una ruta cacheada se considera válida antes de recalcularse."""
    return float(_traceroute_cfg().get("cacheHours", 24))


@_lazy_load
def get_sentinel_traceroute_max_hops() -> int:
    """Número máximo de saltos a sondear (``-m`` en traceroute)."""
    return int(_traceroute_cfg().get("maxHops", 30))


@_lazy_load
def get_sentinel_traceroute_timeout() -> float:
    """Tiempo máximo total (segundos) para el comando traceroute."""
    return float(_traceroute_cfg().get("timeout", 60))


@_lazy_load
def get_sentinel_traceroute_retry_failed_minutes() -> float:
    """Minutos que una ruta fallida (sin saltos) se cachea antes de reintentar.

    Mucho más corto que ``cacheHours``: evita re-sondear un host inalcanzable en
    cada apertura del detalle, pero permite reintentar pronto (o de inmediato con
    el botón de refresco)."""
    return float(_traceroute_cfg().get("retryFailedMinutes", 15))


# =============================================================================
# CONFIGURACIÓN COMPLETA (GET/SET)
# =============================================================================

@_lazy_load
def get_full_config() -> dict:
    """Devuelve toda la configuración."""
    if _configs is None:
        raise IllegalStateError("'_configs' detectado como nulo")

    return _configs.copy()

def save_full_config(new_config: dict) -> dict:
    """Guarda la configuración completa."""
    global _configs
    if _configs_path is None:
        raise FileNotFoundError("No se encontró ningún archivo de configuración.")
    with open(_configs_path, "w", encoding="utf-8") as f:
        json.dump(new_config, f, indent=2, ensure_ascii=False)
    _configs = new_config
    return new_config


# =============================================================================
# CONFIGURACI�N DE TASKQUEUE
# =============================================================================

@_lazy_load
def get_redis_config() -> dict:
    """Devuelve la configuración de conexión Redis.

    Valores no secretos (host, port, db, socket_connect_timeout) provienen de
    SecOpsConfig.json. El password (secreto) proviene de la variable de entorno
    REDIS_PASSWORD. Las env vars REDIS_HOST/PORT/DB sobreescriben la config si
    están presentes (útil en contenedores).
    """
    if _configs is None:
        raise IllegalStateError("'_configs' detectado como nulo")

    cfg = _configs.get("redis", {})
    host    = os.getenv("REDIS_HOST", str(cfg.get("host", "localhost")))
    port    = int(os.getenv("REDIS_PORT", str(cfg.get("port", 6379))))
    db      = int(os.getenv("REDIS_DB",   str(cfg.get("db", 0))))
    timeout = int(cfg.get("socket_connect_timeout", 2))
    password = os.getenv("REDIS_PASSWORD", "")

    return {
        "host":                  host,
        "port":                  port,
        "db":                    db,
        "socket_connect_timeout": timeout,
        "password":              password or None,
    }

@_lazy_load
def get_taskqueue_config() -> dict:
    if _configs is None:
        raise IllegalStateError("'_configs' detectado como nulo")

    cfg = _configs.get("general", {}).get("taskqueue", {})
    max_workers_env = os.getenv("TASKQUEUE_MAX_WORKERS")
    if max_workers_env is not None:
        cfg["max_workers"] = int(max_workers_env)

    return cfg

# =============================================================================
# CONFIGURACIÓN DE IRIS
# =============================================================================

@_lazy_load
def get_iris_config() -> dict:
    if _configs is None:
        raise IllegalStateError("'_configs' detectado como nulo")
    return _configs.get("iris", {})

@_lazy_load
def get_iris_legitimate_threshold() -> float:
    cfg = get_iris_config()
    return float(cfg.get("legitimate_threshold", 0))

@_lazy_load
def get_iris_suspicious_threshold() -> float:
    cfg = get_iris_config()
    return float(cfg.get("suspicious_threshold", -15))

@_lazy_load
def get_iris_min_headers() -> int:
    cfg = get_iris_config()
    return int(cfg.get("min_headers", 2))


# =============================================================================
# CONFIGURACIÓN DE BASE DE DATOS (no secretos)
# =============================================================================

@_lazy_load
def get_db_isolation_level() -> str:
    """Devuelve el isolation level de SQLAlchemy desde SecOpsConfig.json."""
    if _configs is None:
        raise IllegalStateError("'_configs' detectado como nulo")
    return _configs.get("database", {}).get("isolation_level", "READ COMMITTED")


@_lazy_load
def get_db_pool_config() -> dict:
    """Devuelve la configuración del pool de conexiones desde SecOpsConfig.json.

    Claves: pool_size, max_overflow, pool_timeout. Aplica defaults sensatos si
    faltan, de modo que el sistema arranca aunque el bloque no esté completo.
    """
    if _configs is None:
        raise IllegalStateError("'_configs' detectado como nulo")
    defaults = {"pool_size": 10, "max_overflow": 20, "pool_timeout": 30}
    db_cfg = _configs.get("database", {})
    return {
        "pool_size": int(db_cfg.get("pool_size", defaults["pool_size"])),
        "max_overflow": int(db_cfg.get("max_overflow", defaults["max_overflow"])),
        "pool_timeout": int(db_cfg.get("pool_timeout", defaults["pool_timeout"])),
    }


# =============================================================================
# CONFIGURACIÓN DE SEGURIDAD
# =============================================================================

@_lazy_load
def get_argon2_config() -> dict:
    """Devuelve los parámetros de Argon2id para hashing de contraseñas."""
    if _configs is None:
        raise IllegalStateError("'_configs' detectado como nulo")
    defaults = {"time_cost": 3, "memory_cost": 65536, "parallelism": 4}
    return {**defaults, **_configs.get("security", {}).get("argon2", {})}


# =============================================================================
# ENTORNO
# =============================================================================

def is_development() -> bool:
    """Indica si la aplicación está en modo desarrollo."""
    return os.environ.get("FLASK_ENV", "production") == "development"