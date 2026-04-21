"""
run.py — Punto de entrada de la API SeQ
════════════════════════════════════════
Responsabilidades de este fichero:
    1. Crear la aplicación Flask.
    2. Configurar CORS y rate limiting (via init_app del limiter de _shared).
    3. Registrar los blueprints (via endpoints.register_blueprints).
    4. Instalar manejadores de error globales.
    5. Servir la interfaz web estática (Interface/web/) bajo la ruta raíz.
    6. Gestionar el apagado graceful (SIGTERM / SIGINT).
    7. Arrancar el servidor de desarrollo si se ejecuta directamente.

Toda la lógica de rutas vive en el paquete `endpoints/`.
La ruta comodín de la UI se registra DESPUÉS de los blueprints para que
los endpoints de la API siempre tengan prioridad.
"""

import os
import signal
import sys
import time

from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
from sqlalchemy import text  

from src.endpoints import register_blueprints
from src.endpoints._shared import limiter
from src.misc import SecOpsLogger
from src.logic.managers import initialize_engine, warmup_connection


_logger = SecOpsLogger(name="APIMain").get_logger()

SHUTDOWN_TIMEOUT = 30

# Ruta absoluta al directorio de la interfaz web estática
_UI_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "Interface", "web")
)

def _graceful_shutdown(signum, frame) -> None:
    sig_name = "SIGTERM" if signum == signal.SIGTERM else "SIGINT"
    _logger.info(f"[Shutdown] {sig_name} recibido — iniciando apagado graceful...")
    try:
        from src.logic.managers import ScanManager
        _logger.info(
            f"[Shutdown] Cancelando {len(ScanManager._running_tasks)} tarea(s) activa(s)..."
        )
        ScanManager.cancel_all_running(timeout=SHUTDOWN_TIMEOUT)
        _logger.info("[Shutdown] Todas las tareas finalizadas.")
    except Exception as e:
        _logger.error(f"[Shutdown] Error durante el apagado: {e}")

    _logger.info("[Shutdown] Proceso terminado.")
    sys.exit(0)

signal.signal(signal.SIGTERM, _graceful_shutdown)
signal.signal(signal.SIGINT,  _graceful_shutdown)

def create_app(fresh_db_init = False) -> Flask:
    app = Flask(__name__)

    _logger.info("Inicializando la aplicación SeQ...")
    _logger.info("Inicializando CORS...")
    _configure_cors(app)

    _logger.info("Inicializando rate limiting...")
    _configure_rate_limiting(app)

    _logger.info("Añadiendo endpoints...")
    register_blueprints(app)
    _register_ui_route(app)

    _logger.info("Registrando manejadores de error globales...")
    _register_error_handlers(app)

    if fresh_db_init:
        _init_db()

    _logger.info("Inicializando base de datos...")
    engine = initialize_engine()
    warmup_connection()

    _logger.info("Aplicación SeQ iniciada correctamente")
    return app

def _configure_cors(app: Flask) -> None:
    raw     = os.environ.get("ALLOWED_ORIGINS", "http://localhost:8080")
    origins = [o.strip() for o in raw.split(",") if o.strip()]
    origins.append("http://127.0.0.1:3000")
    CORS(app, origins=origins, supports_credentials=True)

def _configure_rate_limiting(app: Flask) -> None:
    """
    Asocia el único Limiter de la aplicación (definido en _shared.py)
    a esta instancia de Flask.
    """ 
    limiter.init_app(app)

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
    @app.errorhandler(404)
    def not_found(error):
        _logger.warning(f"Ruta no encontrada: {request.method} {request.url}")
        return jsonify({
            "error":   "not_found",
            "message": "La ruta solicitada no existe",
            "path":    request.path,
        }), 404

    @app.errorhandler(405)
    def method_not_allowed(error):
        _logger.warning(f"Método no permitido: {request.method} {request.url}")
        return jsonify({
            "error":          "method_not_allowed",
            "message":        f"El método {request.method} no está permitido en esta ruta",
            "allowedMethods": list(error.valid_methods) if hasattr(error, "valid_methods") else [],
        }), 405

    @app.errorhandler(429)
    def too_many_requests(error):
        _logger.warning("Rate limit superado: %s", request.remote_addr)
        return jsonify({
            "error":   "too_many_requests",
            "message": "Has superado el límite de peticiones. Espera un momento e inténtalo de nuevo.",
        }), 429

    @app.errorhandler(500)
    def internal_error(error):
        _logger.error(f"Error interno del servidor: {error}", exc_info=True)
        return jsonify({
            "error":   "internal_server_error",
            "message": "Ha ocurrido un error inesperado en el servidor.",
        }), 500

def _init_db(app: Flask) -> None:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'API'))
    db_creds = ConfigReader.get_db_credentials()

    username = db_creds["username"]
    password = db_creds["password"]
    host = db_creds["host"]
    dbname = db_creds["dbname"]
    dialect = db_creds["dialect"]
    port = db_creds["port"]

    # 1. Conexión a la base de datos 'postgres' por defecto para recrear 'SeQ'
    default_db_url = f"{dialect}://{username}:{quote_plus(password)}@{host}:{port}/postgres"
    print(f"[*] Conectando a la base de datos por defecto para configurar '{dbname}'...")
    # Es necesario AUTOCOMMIT para crear y eliminar bases de datos en PostgreSQL
    engine_postgres = create_engine(default_db_url, isolation_level="AUTOCOMMIT")

    with engine_postgres.connect() as conn:
        # Cerrar conexiones activas de otros usuarios a la base de datos antes de eliminarla
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

    # 2. Conexión a la base de datos recién creada 'SeQ'
    DATABASE_URL = f"{dialect}://{username}:{quote_plus(password)}@{host}:{port}/{dbname}"
    print(f"[*] Conectando a: {dialect}://{username}:***@{host}:{port}/{dbname}")
    engine = create_engine(DATABASE_URL)

    # 1. Eliminar las tablas si ya existen (en lugar de borrar toda la DB)
    print("[*] Eliminando tablas existentes (si las hay)...")
    Base.metadata.drop_all(engine)

    # 2. Creación de las tablas
    print("[*] Creando tablas en PostgreSQL...")
    Base.metadata.create_all(engine)
    print("[+] ¡Tablas creadas correctamente!")

    # 3. Inserción de los datos iniciales
    print("[*] Insertando datos de prueba (Person y User)...")
    with engine.connect() as conn:
        # 1. Insertamos el Rol primero para satisfacer la clave foránea
        # IMPORTANTE: Si tu modelo Rol usa otra columna en lugar de 'name' (ej. 'nombre' o 'descripcion'), cámbialo aquí.
        conn.execute(text("""
            INSERT INTO "Rol" (id, name, description, hierarchy_level)
            VALUES (1, 'Admin', '', 0);
        """))

        # 2. Insertamos la Persona
        conn.execute(text("""
            INSERT INTO "Person" (first_name, last_name, alias, created_at)
            VALUES ('Gabriel', 'Musteata', 'artexian', CURRENT_DATE);
        """))
        
        # 3. Finalmente insertamos el Usuario (ahora el rol_id 1 y person_id 1 ya existen)
        conn.execute(text("""
            INSERT INTO "User" (username, password_hash, password_salt, email, person_id, rol_id)
            VALUES (
            'root',
            '683ae8fa196c380db02e5d97435c6981a591693d1b695f23e769500c046c2f6a',
            'c167837c1c2a860031d861164d69bd79',
            'gmiganescu@gmail.com',
            1,
            1
            );
        """))

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

app = create_app()

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)
