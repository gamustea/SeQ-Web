"""
run.py — Punto de entrada de la API SeQ
═══════════════════════════════════════
Responsabilidades de este fiche:
    1. Crear la aplicación Flask.
    2. Configurar CORS y rate limiting.
    3. Registrar los blueprints.
    4. Instalar manejadores de error globales.
    5. Gestionar el apagado graceful.
    6. Arrancar el servidor de desarrollo si se ejecuta directamente.

En producción, Nginx sirve el frontend Vue. En desarrollo, Vite sirve
el frontend con proxy inverso al backend. La API no sirve contenido
estático.
"""

import os
import signal
import warnings

from flask                  import Flask, jsonify, request
from flask_cors             import CORS
from flask_smorest          import Api as FlaskSmorestApi
from sqlalchemy             import create_engine, text
from urllib.parse           import quote_plus

from src.modules.shared     import BaseManager, Base, limiter
from src.modules.shared._exceptions import (
    MissingParameterError,
    MissingJsonBodyError,
    SecOpsException,
    create_error_response
)
from src.modules.system     import SecOpsLogger, config_reading, system_blp
from src.modules.users      import (
    UserManager,
    oauth_blp,
    users_blp
)
from src.modules.sentinel   import sentinel_blp
from src.modules.acheron    import acheron_blp
from src.modules.aegis      import aegis_blp
from src.modules.iris       import iris_blp
from src.modules.pages      import pages_bp

import src.modules.system.config_reading as CR


APP_CONTEXT = CR.get_app_context()

_logger = SecOpsLogger(name="APIMain").get_logger()

warnings.filterwarnings("ignore", message="Multiple schemas resolved to the name")

_IS_SHUTTING_DOWN = False


def _graceful_shutdown(signum, *args) -> None:
    """
    Manejador de señales para shutdown graceful de la aplicación.

    Cancela todas las tareas en segundo plano antes de terminar
    el proceso, asegurando que los workers y subprocesses no queden huérfanos.

    Args:
        signum: Número de señal recibida (SIGTERM o SIGINT).
        *args: Argumentos adicionales (para compatibilidad con Werkzeug reloader).

    Behavior:
        1. Protege contra re-entrada: fuerza os._exit(1) si ya se está apagando.
        2. Registra la señal recibida.
        3. Detiene TaskQueue (cancela todas las tareas en todas las categorías).
        4. Detiene el scheduler de tareas programadas.
        5. Cierra las sesiones de base de datos.
        6. Termina el proceso con os._exit(0).
    """
    global _IS_SHUTTING_DOWN

    if _IS_SHUTTING_DOWN:
        _logger.warning(
            "Segunda señal recibida durante el apagado — forzando salida inmediata."
        )
        os._exit(1)

    _IS_SHUTTING_DOWN = True

    sig_name = "SIGTERM" if signum == signal.SIGTERM else "SIGINT"
    _logger.info(f"{sig_name} recibido — iniciando apagado graceful...")
    try:
        from src.modules.system.taskqueue import TaskQueue
        _logger.info("Cancelando tareas en segundo plano...")
        TaskQueue.get_instance().cancel_all()
        _logger.info("Tareas canceladas.")
    except Exception as e:
        _logger.error(f"Error cancelando tareas: {e}")

    _logger.info("[Shutdown] Deteniendo scheduler...")
    try:
        from src.modules.sentinel.services.scheduling import Scheduler
        Scheduler.stop()
    except Exception as e:
        _logger.error(f"Error deteniendo scheduler: {e}")

    _logger.info("[Shutdown] Cerrando sesiones de base de datos...")
    try:
        BaseManager.close_all_sessions()
    except Exception as e:
        _logger.error(f"Error cerrando sesiones de BD: {e}")

    _logger.info("[Shutdown] Proceso terminado.")
    os._exit(0)

def create_app(fresh_db_init: bool = False, start_scheduler: bool = True) -> Flask:
    """
    Factory de la aplicación Flask SeQ.

    Configura todos los componentes necesarios para servir la API REST.

    Args:
        fresh_db_init: Si True, reinicializa la base de datos completamente
                        (destructivo). Por defecto False.

    Returns:
        Flask: Aplicación completamente configurada y lista para servir.
    """
    from src.modules.sentinel.services.scheduling import Scheduler

    app = Flask(__name__)

    _logger.info("Inicializando la aplicación SeQ...")
    _logger.info("Inicializando CORS...")
    raw     = os.environ.get("ALLOWED_ORIGINS", "http://localhost:8080")
    origins = [o.strip() for o in raw.split(",") if o.strip()]
    origins.append("http://127.0.0.1:3000")
    CORS(app, origins=origins, supports_credentials=True)

    _logger.info("Inicializando rate limiting...")
    limiter.init_app(app)

    _logger.info("Inicializando documentación OpenAPI...")
    app.config["API_TITLE"]             = "SeQ API"
    app.config["API_VERSION"]           = "3.2"
    app.config["OPENAPI_VERSION"]       = "3.0.3"
    app.config["OPENAPI_URL_PREFIX"]    = "/api-docs"
    app.config["OPENAPI_SWAGGER_UI_PATH"] = "/swagger"
    app.config["OPENAPI_SWAGGER_UI_URL"] = "https://cdn.jsdelivr.net/npm/swagger-ui-dist/"
    flask_smorest_api = FlaskSmorestApi(app)

    _logger.info("Añadiendo endpoints...")
    flask_smorest_api.register_blueprint(system_blp,  url_prefix="/system")
    flask_smorest_api.register_blueprint(oauth_blp,   url_prefix="/oauth")
    flask_smorest_api.register_blueprint(users_blp,   url_prefix="/users")
    flask_smorest_api.register_blueprint(sentinel_blp, url_prefix="/sentinel")
    flask_smorest_api.register_blueprint(acheron_blp,  url_prefix="/acheron")
    flask_smorest_api.register_blueprint(aegis_blp,    url_prefix="/aegis")
    flask_smorest_api.register_blueprint(iris_blp,     url_prefix="/iris")
    app.register_blueprint(pages_bp,    url_prefix="/pages")

    _logger.info("Registrando manejadores de error globales...")
    _register_error_handlers(app)

    if fresh_db_init:
        _init_db()

    _logger.info("Inicializando base de datos...")
    engine = BaseManager._initialize_engine()
    Base.metadata.create_all(engine)
    BaseManager.warmup_connection()

    _logger.info("Configurando sesión por-request...")
    from src.modules.infrastructure.session import shutdown_request_session
    app.teardown_request(shutdown_request_session)

    if start_scheduler:
        _logger.info("Arrancando scheduler de tareas programadas...")
        Scheduler.start()

    _logger.info("Verificando conexion a Redis...")
    import redis as redis_lib
    try:
        redis_cfg = CR.get_redis_config()
        r = redis_lib.Redis(
            host=redis_cfg["host"],
            port=redis_cfg["port"],
            db=redis_cfg["db"],
            password=redis_cfg["password"],
            socket_connect_timeout=5,
        )
        r.ping()
        r.close()
        _logger.info("Redis conectado correctamente")
    except Exception as e:
        _logger.warning("Redis no disponible — la cola de tareas no funcionara: %s", e)

    _logger.info("Aplicación SeQ iniciada correctamente")
    return app

def _register_error_handlers(app: Flask) -> None:
    """
    Registra manejadores de errores HTTP globales para la aplicación.

    Configura respuestas JSON consistentes para los códigos de estado
    más comunes, incluyendo logging de advertencias para debugging.

    Args:
        app: Instancia de la aplicación Flask.

    Handlers:
        - 404 Not Found: Rutas que no coinciden con ningún blueprint.
        - 405 Method Not Allowed: Métodos HTTP no permitidos.
        - 429 Too Many Requests: Rate limit superado.
        - 500 Internal Server Error: Errores inesperados.
    """
    @app.errorhandler(404)
    def not_found(error):
        _logger.warning(f"Ruta no encontrada: {request.method} {request.url}")
        return jsonify({
            "error": "not_found",
            "error_description": "La ruta solicitada no existe",
            "path": request.path,
        }), 404

    @app.errorhandler(405)
    def method_not_allowed(error):
        _logger.warning(
            f"Método no permitido: {request.method} {request.url}"
        )
        return jsonify({
            "error": "method_not_allowed",
            "error_description": f"El método {request.method} no está permitido en esta ruta",
            "allowedMethods": list(error.valid_methods) if hasattr(error, "valid_methods") else [],
        }), 405

    @app.errorhandler(429) # type: ignore
    def too_many_requests():
        _logger.warning("Rate limit superado: %s", request.remote_addr)
        return jsonify({
            "error": "too_many_requests",
            "error_description": "Has superado el límite de peticiones. Espera un momento e inténtalo de nuevo.",
        }), 429

    @app.errorhandler(SecOpsException)
    def handle_secops_exception(error):
        if error.traceback:
            _logger.error(f"[{error.code.name}] {error.message}\n{error.traceback}")
        else:
            _logger.error(f"[{error.code.name}] {error.message}")
        include_debug = config_reading.is_development()
        err, code = create_error_response(error, include_debug_info=include_debug)
        return jsonify(err), code

    @app.errorhandler(MissingParameterError)
    def handle_missing_parameter(error):
        _logger.warning(f"Parámetro faltante: {error}")
        return jsonify({
            "error": "missing_parameter",
            "error_description": str(error),
        }), 400

    @app.errorhandler(MissingJsonBodyError)
    def handle_missing_json_body(error):
        _logger.warning(f"Body JSON inválido: {error}")
        return jsonify({
            "error": "invalid_json",
            "error_description": str(error),
        }), 400

    @app.errorhandler(500)
    def internal_error(error):
        _logger.error(
            f"Error interno del servidor: {error}",
            exc_info=True
        )
        return jsonify({
            "error": "internal_server_error",
            "error_description": "Ha ocurrido un error inesperado en el servidor.",
        }), 500

def _init_db() -> None:
    """
    Inicializa la base de datos completa de SeQ desde cero.

    Este proceso destructivo elimina cualquier base de datos existente
    y la recrea con la estructura y datos iniciales:

    1. Conexión a PostgreSQL con AUTOCOMMIT.
    2. Eliminación de conexiones activas a la DB.
    3. DROP DATABASE IF EXISTS + CREATE DATABASE.
    4. Conexión a la nueva DB y creación de tablas via SQLAlchemy.
    5. Inserción de usuario root por defecto.
    6. Inserción de temas iniciales de concienciación (Topics).

    Warning:
        Esta función elimina TODOS los datos existentes. Usar solo en
        desarrollo o cuando se requiera un reset completo.

    Raises:
        SQLAlchemy Error: Si falla la conexión o ejecución de SQL.

    Example:
    >>> from run import create_app
    >>> app = create_app(fresh_db_init=True)  # Crea DB limpia
    """
    db_creds = CR.get_db_credentials()

    username = db_creds["username"]
    password = db_creds["password"]
    host = db_creds["host"]
    dbname = db_creds["dbname"]
    dialect = db_creds["dialect"]
    port = db_creds["port"]

    default_db_url = f"{dialect}://{username}:{quote_plus(password)}@{host}:{port}/postgres"
    print(f"[*] Conectando a la base de datos por defecto para configurar '{dbname}'...")
    engine_postgres = create_engine(default_db_url, isolation_level="AUTOCOMMIT")

    with engine_postgres.connect() as conn:
        print(f"[*] Terminando conexiones activas a la base de datos '{dbname}'...")
        conn.execute(text(f"""
            SELECT pg_terminate_backend(pg_stat_activity.pid)
            FROM pg_stat_activity
            WHERE pg_stat_activity.datname = '{dbname}'
            AND pid <> pg_backend_pid();
        """))

        # Eliminar y recrear la base de datos
        print(f"[*] Eliminando la base de datos '{dbname}' si existe...")
        conn.execute(text(f'DROP DATABASE IF EXISTS "{dbname}";'))

        print(f"[*] Creando la base de datos '{dbname}'...")
        conn.execute(text(f'CREATE DATABASE "{dbname}";'))

    engine_postgres.dispose()

    database_url = f"{dialect}://{username}:{quote_plus(password)}@{host}:{port}/{dbname}"
    print(f"[*] Conectando a: {dialect}://{username}:***@{host}:{port}/{dbname}")
    engine = create_engine(database_url)

    # 1. Eliminar las tablas si ya existen (en lugar de borrar toda la DB)
    print("[*] Eliminando tablas existentes (si las hay)...")
    Base.metadata.drop_all(engine)

    # 2. Creación de las tablas
    print("[*] Creando tablas en PostgreSQL...")
    Base.metadata.create_all(engine)
    print("[+] ¡Tablas creadas correctamente!")

    # 3. Inserción de los datos iniciales
    print("[*] Insertando datos de prueba (User)...")
    with engine.connect() as conn:
        conn.execute(text("""
            INSERT INTO "User" (username, first_name, last_name, password_hash, password_salt, email, created_at, role)
            VALUES (
            'root',
            'Gabe',
            'Joe',
            '683ae8fa196c380db02e5d97435c6981a591693d1b695f23e769500c046c2f6a',
            'c167837c1c2a860031d861164d69bd79',
            'gjoe@seq.com',
            CURRENT_DATE,
            'role_root'
            );
        """))

        print("[*] Insertando atributos al usuario root...")
        root_attributes = UserManager.get_all_available_attributes()
        for attr in root_attributes:
            conn.execute(text(f'''
                INSERT INTO "UserAttribute" (user_id, attribute_name)
                VALUES (1, '{attr}');
            '''))

        conn.execute(text(("""
        INSERT INTO "Topic" (title) VALUES
            -- Ingeniería Social
            ('Phishing y suplantación de identidad'),
            ('Spear phishing: ataques dirigidos'),
            ('Smishing: fraude por SMS'),
            ('Vishing: fraude por llamada telefónica'),
            ('Pretexting: manipulación por contexto falso'),
            ('Baiting: señuelos físicos y digitales'),
            ('Quid pro quo: intercambio fraudulento'),
            -- Contraseñas y Autenticación
            ('Contraseñas robustas: cómo crearlas'),
            ('Gestores de contraseñas corporativos'),
            ('Autenticación de doble factor (2FA)'),
            ('Riesgos de reutilizar contraseñas'),
            ('Ataques de fuerza bruta y diccionario'),
            ('Passkeys: el futuro sin contraseñas'),
            -- Correo Electrónico
            ('Uso seguro del correo corporativo'),
            ('Cómo identificar un correo fraudulento'),
            ('Riesgos de archivos adjuntos maliciosos'),
            ('Email spoofing: correos falsificados'),
            ('BEC: fraude al CEO por correo'),
            -- Malware
            ('Ransomware: secuestro de datos'),
            ('Troyanos: software disfrazado'),
            ('Spyware: espionaje silencioso'),
            ('Adware y PUPs: software no deseado'),
            ('Keyloggers: robo de pulsaciones'),
            ('Rootkits: control oculto del sistema'),
            ('Fileless malware: ataques sin fichero'),
            -- Navegación y Web
            ('Navegación segura por Internet'),
            ('Riesgos de las extensiones de navegador'),
            ('Verificación de URLs y certificados HTTPS'),
            ('Descargas desde fuentes no confiables'),
            ('Drive-by download: infección al navegar'),
            ('Inyección SQL: riesgo en formularios web'),
            ('Cross-Site Scripting (XSS)'),
            -- Redes y Conectividad
            ('Riesgos de redes Wi-Fi públicas'),
            ('VPN: qué es y cuándo usarla'),
            ('Ataques Man-in-the-Middle (MitM)'),
            ('Seguridad en redes domésticas'),
            ('Riesgos del Bluetooth activo'),
            ('DNS spoofing: redirección maliciosa'),
            -- Dispositivos y Endpoints
            ('Actualización de software y parches'),
            ('Seguridad en dispositivos móviles'),
            ('Riesgos del BYOD en la empresa'),
            ('Bloqueo de pantalla y sesiones'),
            ('Cifrado de disco en portátiles'),
            ('Seguridad en impresoras y periféricos'),
            ('Riesgos de los dispositivos USB'),
            -- Datos e Información
            ('Borrado seguro de información'),
            ('Metadatos ocultos en documentos'),
            ('Clasificación de la información'),
            ('Política de escritorio limpio'),
            ('Fugas de información no intencionadas'),
            ('Protección de datos personales (RGPD)'),
            -- Copias de Seguridad
            ('Copias de seguridad: por qué y cómo'),
            ('Estrategia 3-2-1 de backups'),
            ('Recuperación ante desastres'),
            ('Verificación de restauraciones'),
            -- Cloud y Servicios Online
            ('Seguridad en servicios en la nube'),
            ('Riesgos de compartir documentos en cloud'),
            ('Shadow IT: apps no autorizadas'),
            ('Configuraciones inseguras en cloud'),
            ('OAuth y permisos de aplicaciones terceras'),
            -- Trabajo Remoto
            ('Teletrabajo seguro'),
            ('Riesgos del acceso remoto (RDP)'),
            ('Seguridad en videoconferencias'),
            ('Entornos de trabajo híbrido'),
            -- Amenazas Avanzadas
            ('APT: amenazas persistentes avanzadas'),
            ('Ataques a la cadena de suministro'),
            ('Zero-day: vulnerabilidades sin parche'),
            ('Lateral movement: movimiento en red interna'),
            ('Exfiltración de datos corporativos'),
            -- Concienciación General
            ('Ingeniería social en redes sociales'),
            ('Sobrexposición en redes sociales'),
            ('Fraude en compras online'),
            ('Ciberseguridad en vacaciones'),
            ('Reporte de incidentes de seguridad'),
            ('El factor humano en ciberseguridad'),
            ('Cultura de seguridad en la empresa');"""
        )))
        conn.commit()

    print("[+] ¡Datos iniciales insertados con éxito!")


if __name__ == "__main__":
    signal.signal(
        signal.SIGTERM,
        _graceful_shutdown
    )
    signal.signal(
        signal.SIGINT,
        _graceful_shutdown
    )

    app = create_app(APP_CONTEXT.create_database)
    app.run(
        debug=APP_CONTEXT.debug,
        host=APP_CONTEXT.host,
        port=APP_CONTEXT.port
    )
