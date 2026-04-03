

from sqlalchemy import create_engine, text
from src.core.model import Base
from urllib.parse import quote_plus

import sys
import os
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'API'))


config_path = os.path.join(os.path.dirname(__file__), 'src', 'config', 'SecConfig.json')
with open(config_path, 'r') as f:
    config = json.load(f)

db = config['dbconfig']
dialect = db['dialect']
username = db['username']
password = db['password']
host = db['host']
port = db['port']
dbname = db['dbname']

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