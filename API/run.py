"""
run.py — Punto de entrada de la API SeQ
═══════════════════════════════════════
Responsabilidades de este fiche:
    1. Crear la aplicación Flask.
    2. Configurar CORS y rate limiting.
    3. Registrar los blueprints.
    4. Instalar manejadores de error globales.
    5. Servir la interfaz web estática.
    6. Gestionar el apagado graceful.
    7. Arrancar el servidor de desarrollo si se ejecuta directamente.

La ruta comodín de la UI se registra DESPUÉS de los blueprints para que
los endpoints de la API siempre tengan prioridad.
"""

import os
import signal

from flask                  import Flask, jsonify, request, send_from_directory
from flask_cors             import CORS
from sqlalchemy             import create_engine, text
from urllib.parse           import quote_plus

from src.modules.shared     import BaseManager, Base, limiter
from src.modules.shared._exceptions import MissingParameterError, MissingJsonBodyError, SecOpsException, create_error_response
from src.modules.system     import SecOpsLogger, config_reading
from src.modules.users      import (
    UserManager,
    oauth_bp,
    users_bp
)
from src.modules.sentinel   import sentinel_bp
from src.modules.acheron    import acheron_bp
from src.modules.aegis      import aegis_bp
from src.modules.system     import system_bp
from src.modules.pages      import pages_bp

import src.modules.system.config_reading as CR


APP_CONTEXT = CR.get_app_context()
_logger = SecOpsLogger(name="APIMain").get_logger()

_UI_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "web")
)

def _graceful_shutdown(signum, *args) -> None:
    """
    Manejador de señales para shutdown graceful de la aplicación.

    Cancela todas las tareas de escaneo en ejecución antes de terminar
    el proceso, asegurando que los escaneos no queden huérfanos.

    Args:
        signum: Número de señal recibida (SIGTERM o SIGINT).
        shutdown_time: Tiempo en el que se ha de matar el proceso
        *args: Argumentos adicionales (para compatibilidad con Werkzeug reloader).

    Behavior:
        1. Registra la señal recibida.
        2. Importa ScanManager y cancela todas las tareas en ejecución.
        3. Espera hasta SHUTDOWN_TIMEOUT segundos a que terminen.
        4. Finaliza el proceso con SIGKILL para asegurar terminación.

    Note:
        Este manejador se registra para SIGTERM y SIGINT al inicio del módulo.
    """
    sig_name = "SIGTERM" if signum == signal.SIGTERM else "SIGINT"
    _logger.info(f"{sig_name} recibido — iniciando apagado graceful...")
    try:
        from src.modules.sentinel import ScanManager
        _logger.info("Cancelando tarea(s) activa(s)...")
        ScanManager.cancel_all_running(
            logger=_logger,
            timeout=APP_CONTEXT.shutdown_time
        )
        _logger.info("Todas las tareas finalizadas.")
    except Exception as e:
        _logger.error(f"Error durante el apagado: {e}")

    _logger.info("[Shutdown] Proceso terminado.")
    import os as _os
    _os.kill(_os.getpid(), signal.SIGTERM)


def create_app(fresh_db_init: bool = False) -> Flask:
    """
    Factory de la aplicación Flask SeQ.

    Configura todos los componentes necesarios para servir la API REST
    y la interfaz web estática:

    Args:
        fresh_db_init: Si True, reinicializa la base de datos completamente
                        (destructivo). Por defecto False.

    Returns:
        Flask: Aplicación completamente configurada y lista para servir.
    """
    app = Flask(__name__)

    _logger.info("Inicializando la aplicación SeQ...")
    _logger.info("Inicializando CORS...")
    raw     = os.environ.get("ALLOWED_ORIGINS", "http://localhost:8080")
    origins = [o.strip() for o in raw.split(",") if o.strip()]
    origins.append("http://127.0.0.1:3000")
    CORS(app, origins=origins, supports_credentials=True)

    _logger.info("Inicializando rate limiting...")
    limiter.init_app(app)

    _logger.info("Añadiendo endpoints...")
    app.register_blueprint(system_bp,   url_prefix="/system")
    app.register_blueprint(oauth_bp,    url_prefix="/oauth")
    app.register_blueprint(users_bp,    url_prefix="/users")
    app.register_blueprint(sentinel_bp, url_prefix="/sentinel")
    app.register_blueprint(acheron_bp,  url_prefix="/acheron")
    app.register_blueprint(aegis_bp,    url_prefix="/aegis")
    app.register_blueprint(pages_bp,    url_prefix="/pages")
    _register_ui_route(app)

    _logger.info("Registrando manejadores de error globales...")
    _register_error_handlers(app)

    if fresh_db_init:
        _init_db()

    _logger.info("Inicializando base de datos...")
    BaseManager.warmup_connection()

    _logger.info("Aplicación SeQ iniciada correctamente")
    return app


def _register_ui_route(app: Flask) -> None:
    """
    Sirve la interfaz web estática (Interface/web/) bajo la ruta raíz.

    Reglas de resolución:
      - Si la ruta coincide con un fichero existente dentro de _UI_DIR,
        se sirve directamente (CSS, JS, imágenes, etc.).
      - Cualquier otra ruta desconocida redirige al hub principal
        (hub/index.html), lo que permite navegación client-side.

    IMPORTANTE: esta función debe llamarse DESPUÉS de register_blueprints()
    para que los endpoints de la API (/oauth/*, /sentinel/*, etc.) tengan
    prioridad sobre el comodín.
    """
    @app.route("/", defaults={"path": ""})
    @app.route("/<path:path>")
    def serve_ui(path: str):
        # No interceptar rutas de la API ni del blueprint /pages
        if path.startswith(("pages/", "oauth/", "sentinel/", "aegis/", "users/", "acheron/")):
            from flask import abort
            abort(404)

        target = os.path.join(_UI_DIR, path)
        if path and os.path.isfile(target):
            return send_from_directory(_UI_DIR, path)

        return send_from_directory(_UI_DIR, "pages/hub.html")

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
