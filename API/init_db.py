import sys
import os
import json
from urllib.parse import quote_plus

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'API'))

from sqlalchemy import create_engine, text
from src.core.model import Base

config_path = os.path.join(os.path.dirname(__file__), 'src', 'config', 'SecConfig.json')
with open(config_path, 'r') as f:
    config = json.load(f)

db = config['dbconfig']
dialect = db['dialect']      # "postgresql+psycopg2"
username = db['username']    # "SecOps"
password = db['password']    # "xK#9mP2$vQnL@7rTdZ!4"
host = db['host']            # "127.0.0.1"
port = db['port']            # 5432
dbname = db['dbname']        # "SeQ"

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
    conn.commit() 

print("[+] ¡Datos iniciales insertados con éxito!")