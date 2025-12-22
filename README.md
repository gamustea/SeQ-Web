# SecOps - Sistema de Escaneo de Seguridad

![Version](https://img.shields.io/badge/version-3.0-blue)
![Python](https://img.shields.io/badge/python-3.8%2B-brightgreen)
![License](https://img.shields.io/badge/license-MIT-green)

Sistema completo de escaneo de seguridad con API REST que integra Nmap y Nikto para análisis de vulnerabilidades en redes y aplicaciones web. Implementa autenticación OAuth 2.0, gestión de usuarios, generación de reportes PDF y una arquitectura robusta con manejo de excepciones personalizado.

## 📋 Tabla de Contenidos

- [Características Principales](#-características-principales)
- [Arquitectura del Sistema](#-arquitectura-del-sistema)
- [Requisitos](#-requisitos)
- [Instalación](#-instalación)
- [Configuración](#%EF%B8%8F-configuración)
- [Estructura del Proyecto](#-estructura-del-proyecto)
- [Modelos de Datos](#-modelos-de-datos)
- [API REST](#-api-rest)
- [Autenticación y Seguridad](#-autenticación-y-seguridad)
- [Escaneos](#-escaneos)
- [Generación de Reportes](#-generación-de-reportes)
- [Manejo de Excepciones](#-manejo-de-excepciones)
- [Ejemplos de Uso](#-ejemplos-de-uso)
- [Contribución](#-contribución)
- [Licencia](#-licencia)

## 🚀 Características Principales

### Escaneos de Seguridad
- **Nmap**: Escaneo de puertos TCP con detección de servicios
- **Nikto**: Análisis de vulnerabilidades web con clasificación automática por severidad
- Ejecución asíncrona con seguimiento de progreso en tiempo real
- Soporte para múltiples objetivos simultáneos
- Detección automática de puertos abiertos y razones de estado

### Autenticación y Autorización
- OAuth 2.0 con JWT (Access Tokens y Refresh Tokens)
- Gestión de usuarios con cifrado SHA-256 + salt único por usuario
- Control de acceso basado en sesiones por usuario
- Rate limiting (10 intentos/min en login) para prevención de ataques de fuerza bruta
- Revocación de tokens individual o total

### Gestión de Datos
- Base de datos MySQL con SQLAlchemy ORM
- Relaciones polimórficas para diferentes tipos de escaneo
- Gestión de sesiones thread-safe con scoped_session
- Manejo robusto de transacciones con rollback automático
- Pool de conexiones con pre-ping y reciclado automático

### Generación de Reportes
- Exportación a PDF con diseño personalizado por tipo de escaneo
- Tablas interactivas con información detallada de puertos e incidentes
- Estrategia de diseño modular (Strategy Pattern)
- Exportación en base64 para integración con frontends
- Paletas de colores específicas por tipo de escaneo

### Validación y Seguridad
- Validación de IPs: individual, CIDR (/24), rangos (192.168.1.1-10), wildcards (192.168.1.*)
- Validación de puertos con expansión automática (1-1000, 80,443)
- Sistema de excepciones personalizado con códigos de error estandarizados
- Logging completo con niveles configurables y rotación de archivos
- CORS configurado para permitir acceso desde frontends

## 🏗️ Arquitectura del Sistema

```
SecOps/
├── API/
│   ├── src/
│   │   ├── core/              # Modelos y excepciones
│   │   │   ├── model.py       # Modelos SQLAlchemy (15 clases)
│   │   │   └── exceptions.py  # Sistema de excepciones (30+ clases)
│   │   ├── logic/             # Lógica de negocio
│   │   │   ├── managers.py    # Gestores (UserManager, NmapScanManager, etc.)
│   │   │   ├── secrets.py     # Cifrado SHA-256 y salt
│   │   │   └── tasking/
│   │   │       └── tasks.py   # Tareas asíncronas de escaneo
│   │   ├── misc/              # Utilidades
│   │   │   ├── validation.py  # Validadores de IP y puertos
│   │   │   ├── conversion.py  # Conversores XML/JSON
│   │   │   ├── documents.py   # Generación de PDFs con ReportLab
│   │   │   ├── logging.py     # Sistema de logs centralizado
│   │   │   ├── configread.py  # Lectura de configuración JSON
│   │   │   └── directorychecker.py # Verificación de directorios
│   │   └── config/
│   │       └── SecConfig.json # Configuración del sistema
│   └── run.py                 # API REST Flask (30+ endpoints)
└── README.md
```

### Capas del Sistema

1. **Capa de Presentación**: API REST con Flask, CORS y Rate Limiting
2. **Capa de Lógica**: Managers con transacciones thread-safe y tareas asíncronas
3. **Capa de Datos**: ORM con SQLAlchemy, relaciones polimórficas y cascade delete
4. **Capa de Utilidades**: Validación, logging, conversión XML/JSON y generación PDF

## 📦 Requisitos

### Software Requerido
- Python 3.8+
- MySQL 5.7+ / MariaDB 10.3+
- Nmap 7.80+ (herramienta de línea de comandos)
- Nikto 2.1.6+ (herramienta de línea de comandos)

### Dependencias Python
```txt
Flask==2.3.0
Flask-CORS==4.0.0
Flask-Limiter==3.3.1
SQLAlchemy==2.0.0
PyMySQL==1.0.3
python-nmap==0.7.1
xmltodict==0.13.0
PyJWT==2.8.0
reportlab==4.0.0
```

Instalar dependencias:
```bash
pip install -r requirements.txt
```

## 🔧 Instalación

### 1. Clonar el Repositorio
```bash
git clone https://github.com/tu-usuario/secops.git
cd secops
```

### 2. Crear Entorno Virtual
```bash
python -m venv venv
source venv/bin/activate  # En Windows: venv\Scripts\activate
```

### 3. Instalar Dependencias
```bash
pip install -r requirements.txt
```

### 4. Configurar Base de Datos
```sql
CREATE DATABASE secops_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'secops_user'@'localhost' IDENTIFIED BY 'tu_contraseña_segura';
GRANT ALL PRIVILEGES ON secops_db.* TO 'secops_user'@'localhost';
FLUSH PRIVILEGES;
```

### 5. Inicializar Base de Datos
```python
from src.core.model import Base
from src.logic.managers import initialize_engine
from sqlalchemy import create_engine

# Inicializar engine
initialize_engine()

# Crear tablas
engine = create_engine("mysql+pymysql://secops_user:password@localhost/secops_db")
Base.metadata.create_all(engine)
```

### 6. Ejecutar la Aplicación
```bash
cd API
python run.py
```

La API estará disponible en `http://localhost:5000`

## ⚙️ Configuración

### Archivo SecConfig.json

#### Configuración de Base de Datos
```json
"dbconfig": {
  "username": "usuario_db",
  "password": "contraseña_db",
  "host": "localhost",
  "dbname": "nombre_bd"
}
```

#### Directorios del Sistema
```json
"directories": {
  "tempdir": "/tmp/secops/temp",     // Archivos XML temporales de escaneos
  "logdir": "/var/log/secops",        // Archivos de log (secops.log)
  "resultdir": "/tmp/secops/results", // PDFs generados
  "resourcedir": "./resources"        // Imágenes y plantillas
}
```

#### Configuración OAuth
```json
"oauth": {
  "access_token_expiry_minutes": 30,    // Duración del access token (30 min)
  "refresh_token_expiry_days": 30,      // Duración del refresh token (30 días)
  "jwt_secret_key": "clave_secreta",    // ⚠️ CAMBIAR EN PRODUCCIÓN
  "jwt_algorithm": "HS256"               // Algoritmo de firma JWT
}
```

## 📂 Estructura del Proyecto

### Módulos Principales

#### `model.py` - Modelos de Datos (19,952 caracteres)
Define 15 clases de modelos SQLAlchemy con relaciones complejas:
- **Person**: Información personal (first_name, last_name, email, created_at)
- **User**: Credenciales (username único, password_hash, password_salt, person_id)
- **Scan**: Clase base polimórfica (id, target, started_at, status, user_id, scan_type)
- **FinishedScan**: Timestamp de finalización (id, finished_at)
- **NmapScan**: Hereda de Scan (target_ports, open_ports_relation)
- **NiktoScan**: Hereda de Scan (incidents many-to-many)
- **Port**: Puertos únicos (id, protocol como "80/tcp")
- **OpenPort**: Asociación con atributos (port_id, nmap_scan_id, reason)
- **NiktoIncident**: Vulnerabilidades (osvdb_id, method, url, description, severity, ip_address, port, references, discovered_at)
- **AccessToken** / **RefreshToken**: Tokens OAuth con expiración

#### `managers.py` - Gestión de Lógica (59,301 caracteres)
Implementa 7 managers principales con arquitectura thread-safe:

**BaseManager**
- Gestión automática de sesiones con scoped_session
- Métodos seguros: `_safe_commit()`, `_safe_rollback()`
- Logging integrado por clase
- Cierre automático de sesiones propias

**UserManager**
- `sign_in_user(username, password, email)`: Registro con validación de persona existente
- `verify_credentials(username, password)`: Autenticación con salt
- `get_user_by_username()` / `get_user_by_id()`
- `update_user_password()`: Cambio de contraseña con nuevo salt
- `sign_in_person()`: Registro de personas
- `get_person_by_email()` / `get_all_people()`

**OAuthTokenManager**
- `create_access_token(user_id, username)`: JWT con expiración de 30 min
- `create_refresh_token(user_id)`: JWT con expiración de 30 días
- `verify_access_token(token)`: Validación con blacklist
- `verify_refresh_token(token)`: Renovación de tokens
- `revoke_access_token()` / `revoke_all_user_tokens()`

**NmapScanManager**
- `run_scan(target_host, target_ports, timeout)`: Inicia escaneo asíncrono
- `get_scan_progress(scan_id)`: Progreso en tiempo real (0-100%)
- `get_scan_status(scan_id)`: Estados (pending, running, completed, failed, timeout)
- `is_scan_finished(scan_id)`: Verificación de finalización
- `get_scan_by_id()` / `get_scans_for_user()`
- Persistencia automática de Port y OpenPort

**NiktoScanManager**
- `run_scan(target, timeout)`: Escaneo web asíncrono
- Clasificación automática de severidad (CRITICAL, HIGH, MEDIUM, LOW, INFO)
- Persistencia de NiktoIncident con referencias CVE
- Manejo de múltiples incidencias XML

**Función `assign_severity_to_nikto_incident()`**
Sistema inteligente de clasificación con patrones:
- **CRITICAL**: .env, .git/, phpinfo, SQL dumps, shells, RCE
- **HIGH**: CVE, XSS, CSRF, path traversal, SSL débil, credenciales por defecto
- **MEDIUM**: directory listing, headers faltantes, cookies inseguras, CORS misconfiguration
- **LOW**: server banners, métodos HTTP, páginas por defecto
- **INFO**: Información sin riesgo directo

#### `tasks.py` - Tareas Asíncronas (10,836 caracteres)
Clases abstractas y concretas para escaneos:

**_Task (Clase Base Abstracta)**
- Ejecución con subprocess.Popen y threading
- Captura de progreso con regex en stdout
- Estados: PENDING, RUNNING, COMPLETED, FAILED, CANCELLED, TIMEOUT
- Métodos: `scan()`, `wait(timeout)`, `cancel()`, `is_finished()`

**NmapScanTask**
```python
# Comando ejecutado:
nmap -sT -p 1-1000 -oX output.xml 192.168.1.1 --stats-every 1s

# Procesamiento con python-nmap
scanner.analyse_nmap_xml_scan(xml_data)
```

**NiktoScanTask**
```python
# Comando ejecutado:
nikto -h http://target.com -o output.xml -Format xml -nointeractive -maxtime 180
```

#### `validation.py` - Validación de Entradas (10,419 caracteres)
Validadores robustos con expansión automática:

**PortValidator**
- Formatos: `"80"`, `"80,443"`, `"1-1000"`, `"-1000"`, `"1000-"`, `"80,443-8080"`
- Validación: rango 1-65535, orden ascendente, no solapamiento
- Retorna: `(bool, List[int], str)` con lista expandida

**IPValidator**
- Formatos: `"192.168.1.1"`, `"192.168.1.0/24"`, `"192.168.1.1-10"`, `"192.168.1.*"`
- Soporte: CIDR, rangos por octeto, wildcards, listas separadas por comas
- Función `expandir_rango_octetos()`: Expande rangos complejos como `"192.168.1-2.1-5"`
- Retorna: `(bool, List[str], str)` con lista de IPs únicas

#### `exceptions.py` - Sistema de Excepciones (27,104 caracteres)
Jerarquía completa con 30+ excepciones personalizadas:

**Enums**
```python
class ErrorCode(Enum):
    UNKNOWN_ERROR = 1000
    VALIDATION_ERROR = 1100
    DATABASE_ERROR = 1200
    SCAN_ERROR = 1300
    # ... 20+ códigos más
```

**SecOpsException (Clase Base)**
- Captura automática de stack trace
- Serialización a JSON: `to_dict(include_traceback=False)`
- Atributos: code, severity, details, original_exception, user_message
- Mensajes diferenciados para usuarios técnicos y finales

**Excepciones Principales**
- **ValidationError**: PortValidationError, IPValidationError, URLValidationError, MissingParameterError
- **DatabaseError**: EntityNotFoundError, EntityAlreadyExistsError, DatabaseConnectionError
- **ScanError**: ScanNotFoundError, ScanExecutionError, ScanTimeoutError, MaxConcurrentScansError
- **AuthenticationError**: InvalidCredentialsError, UserNotFoundError, ExistingUserError, UserBindingError
- **ParsingError**: XMLParsingError, JSONParsingError

#### `documents.py` - Generación de PDFs (34,747 caracteres)
Implementación del Strategy Pattern con ReportLab:

**PDFCreator**
- Constructor con estrategia: `PDFCreator(NmapPrintingStrategy(scan))`
- `print_pdf()`: Genera PDF en directorio de resultados
- Plantilla con header, footer, logo y página numerada

**NmapPrintingStrategy**
- Paleta de colores: azul océano (#014F86)
- Tabla de información del escaneo
- Tabla de puertos abiertos con alternancia de colores
- Formato: `Puerto | Protocolo | Razón`

**NiktoPrintingStrategy**
- Paleta de colores: naranja/salmón (#C75B12)
- Resumen de severidad con colores por nivel
- Incidentes ordenados por severidad
- CondPageBreak para evitar cortes de incidentes
- Formato completo: OSVDB ID, método, URL, descripción, referencias

#### `conversion.py` - Conversores (3,415 caracteres)
**JSONManager**
- `convert_multi_niktoscan_xml_to_json()`: Parser XML de Nikto con regex
- `convert_json_to_individual_nmap_data()`: Extrae hostname, comando, puertos
- `convert_json_to_individual_nikto_data()`: Procesa items individuales o arrays

#### `logging.py` - Sistema de Logs (1,201 caracteres)
**SecOpsLogger**
- Formato: `[+] (timestamp) mensaje [LEVEL]`
- Handlers: console + file (secops.log)
- Creación automática de directorios

#### `configread.py` - Lectura de Configuración (2,335 caracteres)
**ConfigReader**
- `get_db_credentials()`: Credenciales de MySQL
- `get_directory_of(DirectoryType)`: Rutas de temp, log, result, resource
- `get_oauth_config()`: Configuración JWT

#### `secrets.py` - Cifrado (1,882 caracteres)
**Encoder**
- `generate_salt()`: 16 bytes aleatorios (32 hex)
- `hash_password_with_salt()`: SHA-256(salt + password)
- `verify_password()`: Comparación segura

#### `run.py` - API REST (51,985 caracteres)
Flask API con 30+ endpoints organizados:

**Características**
- CORS habilitado para frontends
- Rate limiting: 200/día, 50/hora, 10/min en login
- Decoradores: `@require_oauth_token`, `@require_authentication` (legacy)
- Logging completo de requests
- Manejo global de errores (404, 405, 500)

## 💾 Modelos de Datos

### Diagrama de Relaciones

```
Person (1) ──< (1) User (1) ──< (*) Scan ──< (1) FinishedScan
                │                  │
                │                  ├── NmapScan (*)──<(*) Port (vía OpenPort)
                │                  │
                │                  └── NiktoScan (*)──<(*) NiktoIncident
                │
                ├──< (*) AccessToken
                └──< (*) RefreshToken
```

### Tablas de Asociación

**TargetPort** (many-to-many simple)
```sql
port_id → Port.id
nmap_scan_id → NmapScan.id
```

**OpenPort** (many-to-many con atributos)
```sql
port_id → Port.id
nmap_scan_id → NmapScan.id
reason: VARCHAR(255)  -- Ej: "syn-ack", "echo-reply"
```

**ScanIncident** (many-to-many simple)
```sql
nikto_scan_id → NiktoScan.id
nikto_incident_id → NiktoIncident.id
```

### Campos Destacados

**User**
- `password_hash`: SHA-256(salt + password)
- `password_salt`: 32 caracteres hex únicos por usuario
- Relaciones cascade: scans, tokens, refresh_tokens

**Scan (Polimórfico)**
- `scan_type`: Discriminador ("nmap", "nikto")
- `status`: "pending", "running", "completed", "failed", "cancelled", "timeout"
- Herencia: `__mapper_args__ = {"polymorphic_identity": "nmap"}`

**NiktoIncident**
- `severity`: Calculado automáticamente con 100+ patrones
- `osvdb_id`: Referencia a OSVDB (Open Source Vulnerability Database)
- `references`: CVE, documentación, enlaces externos

## 🔌 API REST

### Base URL
```
http://localhost:5000
```

### Autenticación

Todos los endpoints requieren header OAuth (excepto públicos):
```http
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGci...
```

### Endpoints OAuth 2.0

#### 1. Obtener Tokens (Password Grant)
```http
POST /oauth/token
Content-Type: application/json

{
  "X-Grant-Type": "password",
  "X-Username": "usuario",
  "X-Password": "contraseña"
}
```

**Respuesta 200 OK:**
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGci...",
  "token_type": "Bearer",
  "expires_in": 1800,
  "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGci..."
}
```

#### 2. Renovar Access Token (Refresh Token Grant)
```http
POST /oauth/token
Content-Type: application/json

{
  "X-Grant-Type": "refresh_token",
  "X-Refresh-Token": "eyJ0eXAiOiJKV1QiLCJhbGci..."
}
```

**Respuesta 200 OK:**
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGci...",
  "token_type": "Bearer",
  "expires_in": 1800
}
```

#### 3. Revocar Token Actual
```http
POST /oauth/revoke
Authorization: Bearer <token>
```

**Respuesta 200 OK:**
```json
{
  "message": "Token revoked successfully"
}
```

#### 4. Revocar Todos los Tokens del Usuario
```http
POST /oauth/revoke-all
Authorization: Bearer <token>
```

**Respuesta 200 OK:**
```json
{
  "message": "All tokens revoked successfully"
}
```

### Endpoints de Usuarios

#### 1. Registrar Persona
```http
POST /users/sign-up-person
X-First-Name: Juan
X-Last-Name: Pérez
X-Email: juan.perez@example.com
```

**Respuesta 201 Created:**
```json
{
  "message": "Persona registrada exitosamente",
  "personId": 1,
  "firstName": "Juan",
  "lastName": "Pérez",
  "email": "juan.perez@example.com"
}
```

#### 2. Registrar Usuario
```http
POST /users/sign-up
X-Username: juanperez
X-Password: MiContraseñaSegura123!
X-Email: juan.perez@example.com
```

**Respuesta 201 Created:**
```json
{
  "message": "Usuario registrado exitosamente",
  "userId": 1,
  "username": "juanperez",
  "email": "juan.perez@example.com"
}
```

**Error 409 Conflict (usuario existente):**
```json
{
  "error": "UserAlreadyExistsError",
  "code": 1605,
  "message": "El usuario ya existe.",
  "timestamp": "2025-12-22T18:45:00.123456"
}
```

#### 3. Verificar Credenciales (LEGACY)
```http
GET /users/check-credentials
X-Username: juanperez
X-Password: MiContraseñaSegura123!
```

**Respuesta 200 OK:**
```json
{
  "message": "Credenciales válidas",
  "isValid": true,
  "userId": 1,
  "username": "juanperez"
}
```

#### 4. Cambiar Contraseña
```http
PUT /users/change-password
Authorization: Bearer <token>
X-New-Password: NuevaContraseñaSegura456!
```

**Respuesta 200 OK:**
```json
{
  "message": "Contraseña cambiada exitosamente. Por favor, inicia sesión de nuevo.",
  "userId": 1,
  "username": "juanperez"
}
```

### Endpoints de Escaneo Nmap

#### 1. Iniciar Escaneo Nmap
```http
POST /sentinel/nmap/start
Authorization: Bearer <token>
X-Target-Host: 192.168.1.1
X-Target-Ports: 1-1000
```

**Ejemplos de targets válidos:**
- IP individual: `192.168.1.1`
- CIDR: `192.168.1.0/24`
- Rango: `192.168.1.1-10`
- Wildcard: `192.168.1.*`
- Lista: `192.168.1.1,192.168.1.5,192.168.1.10`

**Ejemplos de puertos válidos:**
- Individual: `80`
- Lista: `80,443,8080`
- Rango: `1-1000`
- Combinado: `80,443-445,8000-9000`
- Desde 1: `-1000`
- Hasta 65535: `1000-`

**Respuesta 201 Created:**
```json
{
  "message": "Escaneo(s) Nmap iniciado(s) correctamente",
  "scanIds": [15, 16, 17],
  "target": {
    "hosts": ["192.168.1.1", "192.168.1.2", "192.168.1.3"],
    "ports": "1-1000"
  },
  "totalScans": 3,
  "user": "juanperez"
}
```

### Endpoints de Escaneo Nikto

#### 1. Iniciar Escaneo Nikto
```http
POST /sentinel/nikto/start
Authorization: Bearer <token>
X-Target: http://testphp.vulnweb.com
```

**Query Parameters opcionales:**
- `timeout`: Tiempo máximo en segundos (default: 180)

**Respuesta 201 Created:**
```json
{
  "message": "Escaneo Nikto iniciado correctamente",
  "scanId": 18,
  "target": "http://testphp.vulnweb.com",
  "timeout": 180,
  "user": "juanperez"
}
```

### Endpoints de Estado y Progreso

#### 1. Verificar si un Escaneo Finalizó
```http
GET /sentinel/is-finished?id=15
Authorization: Bearer <token>
```

**Respuesta 200 OK (finalizado):**
```json
{
  "message": "El escaneo con id 15 está terminado",
  "scanId": 15,
  "isFinished": true,
  "scanType": "nmap"
}
```

**Respuesta 200 OK (en progreso):**
```json
{
  "message": "El escaneo con id 15 no está terminado",
  "scanId": 15,
  "isFinished": false,
  "scanType": "nmap"
}
```

#### 2. Obtener Estado de un Escaneo
```http
GET /sentinel/scan-status?id=15
Authorization: Bearer <token>
```

**Respuesta 200 OK:**
```json
{
  "message": "Estado del escaneo con id 15: running",
  "scanId": 15,
  "status": "running",
  "scanType": "nmap"
}
```

**Estados posibles:** `pending`, `running`, `completed`, `failed`, `cancelled`, `timeout`

### Endpoints de Consulta de Resultados

#### 1. Obtener Todos los Escaneos del Usuario
```http
GET /sentinel/results?type=all
Authorization: Bearer <token>
```

**Query Parameters:**
- `type`: `nmap`, `nikto`, o `all` (default: `all`)

**Respuesta 200 OK:**
```json
{
  "message": "Escaneos obtenidos correctamente",
  "filter": "all",
  "count": 5,
  "results": [
    {
      "id": 15,
      "scanType": "nmap",
      "target": "192.168.1.1",
      "startedAt": "2025-12-22T18:30:00.123456",
      "openPorts": [
        {"port": "22/tcp", "reason": "syn-ack"},
        {"port": "80/tcp", "reason": "syn-ack"}
      ],
      "totalOpenPorts": 2
    },
    {
      "id": 18,
      "scanType": "nikto",
      "target": "http://testphp.vulnweb.com",
      "startedAt": "2025-12-22T19:00:00.123456",
      "incidents": [
        {
          "osvdbId": "3268",
          "method": "GET",
          "url": "http://testphp.vulnweb.com/admin/",
          "description": "Admin panel found",
          "discoveredAt": "2025-12-22T19:05:00.123456"
        }
      ],
      "totalIncidents": 15
    }
  ],
  "user": "juanperez"
}
```

#### 2. Obtener un Escaneo Específico
```http
GET /sentinel/results/15
Authorization: Bearer <token>
```

**Respuesta 200 OK (Nmap):**
```json
{
  "message": "Escaneo obtenido correctamente",
  "result": {
    "id": 15,
    "scanType": "nmap",
    "target": "192.168.1.1",
    "startedAt": "2025-12-22T18:30:00.123456",
    "openPorts": [
      {"port": "22/tcp", "reason": "syn-ack"},
      {"port": "80/tcp", "reason": "syn-ack"},
      {"port": "443/tcp", "reason": "syn-ack"}
    ],
    "totalOpenPorts": 3
  },
  "user": "juanperez"
}
```

**Respuesta 200 OK (Nikto):**
```json
{
  "message": "Escaneo obtenido correctamente",
  "result": {
    "id": 18,
    "scanType": "nikto",
    "target": "http://testphp.vulnweb.com",
    "startedAt": "2025-12-22T19:00:00.123456",
    "incidents": [
      {
        "osvdbId": "3268",
        "method": "GET",
        "url": "http://testphp.vulnweb.com/admin/",
        "description": "Admin panel accessible without authentication",
        "discoveredAt": "2025-12-22T19:05:00.123456"
      }
    ],
    "totalIncidents": 15
  },
  "user": "juanperez"
}
```

### Endpoints de Generación de PDFs

#### 1. Generar y Descargar PDF
```http
GET /sentinel/generate-pdf?id=15
Authorization: Bearer <token>
```

**Respuesta 200 OK:**
- Content-Type: `application/pdf`
- Content-Disposition: `attachment; filename="nmap_scan_15.pdf"`
- Body: PDF binario para descarga directa

#### 2. Generar PDF en Base64
```http
GET /sentinel/generate-pdf-base64?id=15
Authorization: Bearer <token>
```

**Respuesta 200 OK:**
```json
{
  "message": "PDF generado exitosamente",
  "scanId": 15,
  "scanType": "nmap",
  "filename": "nmap_scan_15.pdf",
  "pdfBase64": "JVBERi0xLjQKJeLjz9MKMyAwIG9iago8PC9UeXBlL...",
  "contentType": "application/pdf",
  "user": "juanperez"
}
```

### Endpoint de Prueba

#### Say Hello (Sin autenticación)
```http
GET /say-hello
```

**Respuesta 200 OK:**
```json
{
  "message": "You did it! You reached an endpoint!",
  "status": "ok",
  "version": "3.0-oauth"
}
```

## 🔐 Autenticación y Seguridad

### Flujo OAuth 2.0

```
┌─────────┐                                     ┌─────────┐
│ Cliente │                                     │   API   │
└────┬────┘                                     └────┬────┘
     │                                               │
     │  POST /oauth/token (username + password)      │
     │──────────────────────────────────────────────>│
     │                                               │
     │  access_token + refresh_token                 │
     │<──────────────────────────────────────────────│
     │                                               │
     │  Request con Authorization: Bearer <token>    │
     │──────────────────────────────────────────────>│
     │                                               |
     │  Respuesta con datos                          │
     │<──────────────────────────────────────────────│
     │                                               │
     │  (Access token expira en 30 min)              │
     │                                               │
     │  POST /oauth/token (refresh_token)            │
     │──────────────────────────────────────────────>│
     │                                               │
     │  Nuevo access_token                           │
     │<──────────────────────────────────────────────│
```

### Estructura del JWT

**Access Token Payload:**
```json
{
  "sub": "1",              // User ID
  "username": "juanperez",
  "type": "access",
  "exp": 1703268000,       // Unix timestamp (30 min desde creación)
  "iat": 1703266200        // Unix timestamp (creación)
}
```

**Refresh Token Payload:**
```json
{
  "sub": "1",              // User ID
  "type": "refresh",
  "exp": 1705858200,       // Unix timestamp (30 días desde creación)
  "iat": 1703266200        // Unix timestamp (creación)
}
```

### Cifrado de Contraseñas

```python
# Registro de usuario
salt = os.urandom(16).hex()                    # 32 caracteres hex
password_hash = hashlib.sha256((salt + password).encode()).hexdigest()

# Verificación
computed_hash = hashlib.sha256((stored_salt + provided_password).encode()).hexdigest()
is_valid = computed_hash == stored_hash
```

### Rate Limiting

```python
# Límites globales
200 requests/day
50 requests/hour

# Límites específicos
/oauth/token: 10 requests/minute  # Prevención de fuerza bruta
```

### Seguridad de Tokens

- **Revocación**: Blacklist en base de datos con `revoked_at`
- **Expiración**: Validación automática en cada request
- **Renovación**: Refresh tokens para obtener nuevos access tokens
- **Limpieza**: Tokens revocados se pueden limpiar periódicamente

## 🔍 Escaneos

### Escaneo Nmap

#### Proceso Completo

1. **Validación de entrada**
   ```python
   IPValidator.validate("192.168.1.0/24")  # → ["192.168.1.1", ..., "192.168.1.254"]
   PortValidator.validate("80,443-445")    # → [80, 443, 444, 445]
   ```

2. **Creación de registro en BD**
   ```python
   scan = NmapScan(target="192.168.1.1", user_id=1, status="pending")
   ```

3. **Ejecución asíncrona**
   ```bash
   nmap -sT -p 1-1000 -oX /tmp/nmap_scan_192.168.1.1_1703266200.xml 192.168.1.1 --stats-every 1s
   ```

4. **Captura de progreso**
   ```
   About 12.34% done
   About 25.67% done
   About 50.00% done
   About 75.00% done
   About 100.00% done
   ```

5. **Procesamiento de resultados**
   ```python
   scanner = PortScanner()
   results = scanner.analyse_nmap_xml_scan(xml_data)

   # Extracción de puertos abiertos
   for port, data in results['scan'][target]['tcp'].items():
       OpenPort(
           port_id=port_obj.id,
           nmap_scan_id=scan.id,
           reason=data['reason']  # "syn-ack", "echo-reply", etc.
       )
   ```

6. **Marcado como finalizado**
   ```python
   FinishedScan(id=scan.id, finished_at=datetime.now())
   ```

#### Formatos de Puerto Soportados

```python
# Individual
"80" → [80]

# Lista
"80,443,8080" → [80, 443, 8080]

# Rango
"1-1000" → [1, 2, 3, ..., 1000]

# Desde 1
"-1000" → [1, 2, 3, ..., 1000]

# Hasta 65535
"1000-" → [1000, 1001, ..., 65535]

# Combinado
"80,443-445,8000-9000" → [80, 443, 444, 445, 8000, 8001, ..., 9000]
```

### Escaneo Nikto

#### Proceso Completo

1. **Validación de target**
   ```python
   if not target.startswith(('http://', 'https://')):
       raise URLValidationError(...)
   ```

2. **Creación de registro en BD**
   ```python
   scan = NiktoScan(target="http://example.com", user_id=1, status="pending")
   ```

3. **Ejecución asíncrona**
   ```bash
   nikto -h http://example.com -o /tmp/nikto_scan.xml -Format xml -nointeractive -maxtime 180
   ```

4. **Procesamiento de XML**
   ```python
   # Nikto puede generar múltiples documentos XML
   pattern = re.compile(r'(<niktoscan.*?</niktoscan>)', re.DOTALL)
   matches = pattern.findall(content)

   for match in matches:
       doc_dict = xmltodict.parse(match)
   ```

5. **Clasificación de severidad**
   ```python
   # Patrones automáticos
   if ".env" in incident.description:
       incident.severity = "CRITICAL"
   elif "xss" in incident.description:
       incident.severity = "HIGH"
   elif "directory listing" in incident.description:
       incident.severity = "MEDIUM"
   # ... 100+ patrones más
   ```

6. **Persistencia de incidentes**
   ```python
   for incident_data in incidents:
       incident = NiktoIncident(
           osvdb_id=incident_data.get('id'),
           method=incident_data.get('method'),
           url=incident_data.get('uri'),
           description=incident_data.get('description'),
           severity=calculated_severity,
           discovered_at=datetime.now()
       )
       scan.incidents.append(incident)
   ```

#### Clasificación de Severidad

**CRITICAL** (Exposición directa de datos sensibles)
- Variables de entorno: `.env`, `.env.production`
- Repositorios Git: `.git/`, `.git/config`
- Información de sistema: `phpinfo`, `config.php`
- Bases de datos: `.sql`, `backup.sql`, `dump.sql`
- Credenciales: `passwd`, `shadow`, `id_rsa`
- Shells: `webshell`, `backdoor`
- RCE: `remote code execution`, `command injection`
- SQLi crítico: `sql injection`

**HIGH** (Vulnerabilidades explotables)
- Versiones desactualizadas con CVE conocidos
- XSS: `cross site scripting`, `xss`
- CSRF: `csrf`, `cross-site request forgery`
- Path traversal: `directory traversal`, `../`
- File inclusion: `lfi`, `rfi`
- SSL/TLS débil: `ssl v2`, `ssl v3`, `poodle`, `heartbleed`
- Credenciales por defecto: `admin/admin`
- Métodos HTTP peligrosos: `PUT`, `DELETE` permitidos

**MEDIUM** (Problemas de configuración)
- Directory listing: `directory indexing`, `indexes`
- Headers faltantes: `x-frame-options`, `content-security-policy`
- Información expuesta: `stack trace`, `error message`
- Cookies inseguras: `cookie without httponly`
- CORS mal configurado
- Paneles de admin expuestos: `phpmyadmin`, `adminer`

**LOW** (Información del servidor)
- Server banners: `x-powered-by`, `server header`
- Métodos HTTP: `OPTIONS`, `HEAD`
- Páginas por defecto: `welcome page`, `it works`
- IP interna expuesta

**INFO** (Sin riesgo directo)
- Información general: `the site uses`, `appears to be`
- Cookies creadas
- Timestamps de inicio/fin

### Estados de Escaneo

```python
class TaskStatus(Enum):
    PENDING = "pending"       # Esperando para iniciar
    RUNNING = "running"       # En ejecución activa
    COMPLETED = "completed"   # Completado exitosamente
    FAILED = "failed"         # Falló con error
    CANCELLED = "cancelled"   # Cancelado por usuario/sistema
    TIMEOUT = "timeout"       # Excedió tiempo límite
```

### Cancelación de Escaneos

```python
# Desde el manager
nmap_manager.cancel_scan(scan_id)

# Internamente
if self._proc and self._proc.poll() is None:
    self._proc.terminate()
    self.status = TaskStatus.CANCELLED
```

## 📄 Generación de Reportes

### Arquitectura Strategy Pattern

```python
# Estrategia abstracta
class _PrintingStrategy(ABC):
    @abstractmethod
    def append_body(self, scan, styles, elements): pass
    @abstractmethod
    def get_filename_suffix(self) -> str: pass
    @abstractmethod
    def get_picture_name(self, dark: bool) -> str: pass
    @abstractmethod
    def get_report_title(self) -> str: pass

# Estrategias concretas
class NmapPrintingStrategy(_PrintingStrategy): ...
class NiktoPrintingStrategy(_PrintingStrategy): ...

# Uso
pdf_creator = PDFCreator(NmapPrintingStrategy(scan))
pdf_path = pdf_creator.print_pdf()
```

### Estructura del PDF

#### Header
```
┌────────────────────────────────────────┐
│ [Logo SecOps]  Análisis de Seguridad   │
│                                         │
│ Página 1 de 5                           │
└────────────────────────────────────────┘
```

#### Body (Nmap)
```
Informe de Escaneo Nmap
═══════════════════════════════════════

┌─────────────────────────────────────┐
│ ID del Escaneo:      15             │
│ Fecha de inicio:     22/12/2025     │
│ Total de Puertos:    25             │
└─────────────────────────────────────┘

Puertos Abiertos Detectados
───────────────────────────────────────

┌───┬───────────┬────────────┐
│ # │  Puerto   │ Protocolo  │
├───┼───────────┼────────────┤
│ 1 │ 22        │ TCP        │
│ 2 │ 80        │ TCP        │
│ 3 │ 443       │ TCP        │
└───┴───────────┴────────────┘
```

#### Body (Nikto)
```
Informe de Escaneo Nikto
═══════════════════════════════════════

┌─────────────────────────────────────┐
│ ID del Escaneo:      18             │
│ Objetivo:            example.com    │
│ Fecha de Inicio:     22/12/2025     │
│ Total de Incidentes: 47             │
└─────────────────────────────────────┘

Resumen de Severidad
───────────────────────────────────────

┌───────────────┬──────────┐
│  Severidad    │ Cantidad │
├───────────────┼──────────┤
│  CRITICAL     │    3     │
│  HIGH         │    8     │
│  MEDIUM       │   15     │
│  LOW          │   18     │
│  INFO         │    3     │
└───────────────┴──────────┘

Incidentes de Seguridad Detectados
───────────────────────────────────────

┌─────────────────────────────────────┐
│ [CRITICAL] OSVDB-3268               │
├─────────────────────────────────────┤
│ Método:      GET                    │
│ URL:         /admin/                │
│ Descripción: Admin panel accessible │
│              without authentication │
└─────────────────────────────────────┘
```

### Paletas de Colores

**Nmap (Azul Océano)**
```python
BLACK   = "#121212"  # Negro neutro
DARK    = "#01375A"  # Azul océano oscuro
MAIN    = "#014F86"  # Azul océano
SECONDARY = "#555B6E"  # Gris azulado
LIGHT   = "#4A90E2"  # Azul claro
WHITE   = "#E1E8F0"  # Blanco azulado
```

**Nikto (Naranja/Salmón)**
```python
BLACK   = "#4B2500"  # Marrón oscuro
DARK    = "#8E3D0A"  # Naranja oscuro
MAIN    = "#C75B12"  # Naranja
SECONDARY = "#FA8072"  # Salmón
LIGHT   = "#F9B49A"  # Salmón claro
WHITE   = "#FFF5F0"  # Blanco cálido
```

### Características del PDF

- **Tamaño**: A4 (210 x 297 mm)
- **Fuentes**: Helvetica, Helvetica-Bold
- **Tablas**: Alternancia de colores por fila
- **CondPageBreak**: Evita cortes de incidentes entre páginas
- **Paginación**: Numeración automática en footer
- **Logos**: Personalización por tipo de escaneo

## ⚠️ Manejo de Excepciones

### Arquitectura del Sistema

```python
SecOpsException (Base)
├── ValidationError
│   ├── PortValidationError
│   ├── IPValidationError
│   ├── URLValidationError
│   └── MissingParameterError
├── DatabaseError
│   ├── EntityNotFoundError
│   ├── EntityAlreadyExistsError
│   ├── DatabaseConnectionError
│   └── TransactionError
├── ScanError
│   ├── ScanNotFoundError
│   ├── ScanAlreadyRunningError
│   ├── ScanExecutionError
│   ├── ScanTimeoutError
│   └── MaxConcurrentScansError
├── ReportError
│   ├── ReportGenerationError
│   └── ReportNotFoundError
├── ConfigurationError
│   └── MissingConfigError
├── AuthenticationError
│   ├── InvalidCredentialsError
│   ├── UserNotFoundError
│   ├── ExistingUserError
│   └── UserBindingError
├── AuthorizationError
└── ParsingError
    ├── XMLParsingError
    └── JSONParsingError
```

### Respuesta de Error API

```json
{
  "error": "ValidationError",
  "code": 1101,
  "message": "El campo 'X-Target-Ports' no es válido: El puerto 70000 está fuera del rango permitido",
  "timestamp": "2025-12-22T19:45:00.123456",
  "details": {
    "field": "X-Target-Ports",
    "value": "70000",
    "expected": "Formato: '80', '80,443', '1-1000', '80,443-8080'"
  }
}
```

### Códigos de Error

```python
# Generales (1000-1099)
UNKNOWN_ERROR = 1000
INTERNAL_SERVER_ERROR = 1001

# Validación (1100-1199)
VALIDATION_ERROR = 1100
INVALID_PORT_SPEC = 1101
INVALID_IP_SPEC = 1102
INVALID_URL = 1103
MISSING_PARAMETER = 1105

# Base de datos (1200-1299)
DATABASE_ERROR = 1200
ENTITY_NOT_FOUND = 1201
ENTITY_ALREADY_EXISTS = 1202
DATABASE_CONNECTION_ERROR = 1203
TRANSACTION_ERROR = 1204

# Escaneos (1300-1399)
SCAN_ERROR = 1300
SCAN_NOT_FOUND = 1301
SCAN_ALREADY_RUNNING = 1302
SCAN_EXECUTION_ERROR = 1304
SCAN_TIMEOUT = 1305
MAX_CONCURRENT_SCANS = 1306

# Reportes (1400-1499)
REPORT_ERROR = 1400
REPORT_GENERATION_ERROR = 1401

# Configuración (1500-1599)
CONFIGURATION_ERROR = 1500
MISSING_CONFIG = 1501

# Autenticación (1600-1699)
AUTHENTICATION_ERROR = 1600
INVALID_CREDENTIALS = 1602
USER_NOT_FOUND = 1603
TOKEN_EXPIRED = 1604
USER_ALREADY_EXISTS = 1605
UNBINDABLE_USER = 1606

# Parsing (1700-1799)
PARSING_ERROR = 1700
XML_PARSING_ERROR = 1701
JSON_PARSING_ERROR = 1702
```

### Niveles de Severidad

```python
class ErrorSeverity(Enum):
    LOW = "low"          # Errores de usuario, validación
    MEDIUM = "medium"    # Errores de lógica, autenticación
    HIGH = "high"        # Errores de base de datos, transacciones
    CRITICAL = "critical" # Errores de conexión, configuración
```

### Uso en Código

```python
# Lanzar excepción
raise ValidationError(
    field="X-Target-Ports",
    message="Puerto fuera de rango",
    value="70000",
    expected="1-65535"
)

# Captura y respuesta
try:
    # ... código
except ValidationError as e:
    error_dict, status_code = create_error_response(e, include_debug_info=False)
    return jsonify(error_dict), status_code
```

## 💡 Ejemplos de Uso

### Flujo Completo: Registro y Escaneo

```bash
# 1. Registrar persona
curl -X POST http://localhost:5000/users/sign-up-person \
  -H "X-First-Name: María" \
  -H "X-Last-Name: García" \
  -H "X-Email: maria.garcia@example.com"

# 2. Registrar usuario
curl -X POST http://localhost:5000/users/sign-up \
  -H "X-Username: mariagarcia" \
  -H "X-Password: MiPassword123!" \
  -H "X-Email: maria.garcia@example.com"

# 3. Obtener tokens OAuth
curl -X POST http://localhost:5000/oauth/token \
  -H "Content-Type: application/json" \
  -d '{
    "X-Grant-Type": "password",
    "X-Username": "mariagarcia",
    "X-Password": "MiPassword123!"
  }'

# Respuesta:
# {
#   "access_token": "eyJ0eXAiOiJKV1Qi...",
#   "token_type": "Bearer",
#   "expires_in": 1800,
#   "refresh_token": "eyJ0eXAiOiJKV1Qi..."
# }

# 4. Iniciar escaneo Nmap
curl -X POST http://localhost:5000/sentinel/nmap/start \
  -H "Authorization: Bearer eyJ0eXAiOiJKV1Qi..." \
  -H "X-Target-Host: 192.168.1.0/24" \
  -H "X-Target-Ports: 20-25,80,443,8080-8090"

# Respuesta:
# {
#   "message": "Escaneo(s) Nmap iniciado(s) correctamente",
#   "scanIds": [20, 21, 22, ...],
#   "totalScans": 254
# }

# 5. Verificar estado (cada 5 segundos)
curl -X GET "http://localhost:5000/sentinel/scan-status?id=20" \
  -H "Authorization: Bearer eyJ0eXAiOiJKV1Qi..."

# Respuesta (en progreso):
# {
#   "message": "Estado del escaneo con id 20: running",
#   "scanId": 20,
#   "status": "running"
# }

# 6. Verificar si finalizó
curl -X GET "http://localhost:5000/sentinel/is-finished?id=20" \
  -H "Authorization: Bearer eyJ0eXAiOiJKV1Qi..."

# Respuesta:
# {
#   "message": "El escaneo con id 20 está terminado",
#   "scanId": 20,
#   "isFinished": true
# }

# 7. Obtener resultados
curl -X GET "http://localhost:5000/sentinel/results/20" \
  -H "Authorization: Bearer eyJ0eXAiOiJKV1Qi..."

# 8. Generar PDF
curl -X GET "http://localhost:5000/sentinel/generate-pdf?id=20" \
  -H "Authorization: Bearer eyJ0eXAiOiJKV1Qi..." \
  -o nmap_scan_20.pdf

# 9. Iniciar escaneo Nikto
curl -X POST "http://localhost:5000/sentinel/nikto/start?timeout=300" \
  -H "Authorization: Bearer eyJ0eXAiOiJKV1Qi..." \
  -H "X-Target: http://testphp.vulnweb.com"

# 10. Obtener todos los escaneos
curl -X GET "http://localhost:5000/sentinel/results?type=all" \
  -H "Authorization: Bearer eyJ0eXAiOiJKV1Qi..."
```

### Ejemplo con Python

```python
import requests
import time

BASE_URL = "http://localhost:5000"

# 1. Obtener token
response = requests.post(f"{BASE_URL}/oauth/token", json={
    "X-Grant-Type": "password",
    "X-Username": "mariagarcia",
    "X-Password": "MiPassword123!"
})
tokens = response.json()
access_token = tokens["access_token"]

headers = {"Authorization": f"Bearer {access_token}"}

# 2. Iniciar escaneo
response = requests.post(
    f"{BASE_URL}/sentinel/nmap/start",
    headers={
        **headers,
        "X-Target-Host": "192.168.1.1",
        "X-Target-Ports": "1-1000"
    }
)
scan_data = response.json()
scan_id = scan_data["scanIds"][0]
print(f"Escaneo iniciado: ID {scan_id}")

# 3. Esperar a que termine (polling cada 5 segundos)
while True:
    response = requests.get(
        f"{BASE_URL}/sentinel/is-finished",
        params={"id": scan_id},
        headers=headers
    )
    data = response.json()

    if data["isFinished"]:
        print("Escaneo finalizado!")
        break
    else:
        print("Escaneo en progreso...")
        time.sleep(5)

# 4. Obtener resultados
response = requests.get(
    f"{BASE_URL}/sentinel/results/{scan_id}",
    headers=headers
)
results = response.json()
print(f"Puertos abiertos: {results['result']['totalOpenPorts']}")
for port in results['result']['openPorts']:
    print(f"  - {port['port']} ({port['reason']})")

# 5. Descargar PDF
response = requests.get(
    f"{BASE_URL}/sentinel/generate-pdf",
    params={"id": scan_id},
    headers=headers
)
with open(f"scan_{scan_id}.pdf", "wb") as f:
    f.write(response.content)
print(f"PDF guardado: scan_{scan_id}.pdf")
```

### Ejemplo con JavaScript (Fetch)

```javascript
const BASE_URL = 'http://localhost:5000';

// 1. Obtener token
async function login(username, password) {
  const response = await fetch(`${BASE_URL}/oauth/token`, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      'X-Grant-Type': 'password',
      'X-Username': username,
      'X-Password': password
    })
  });
  const data = await response.json();
  return data.access_token;
}

// 2. Iniciar escaneo Nikto
async function startNiktoScan(token, target) {
  const response = await fetch(`${BASE_URL}/sentinel/nikto/start`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'X-Target': target
    }
  });
  const data = await response.json();
  return data.scanId;
}

// 3. Verificar estado
async function checkStatus(token, scanId) {
  const response = await fetch(
    `${BASE_URL}/sentinel/scan-status?id=${scanId}`,
    {headers: {'Authorization': `Bearer ${token}`}}
  );
  const data = await response.json();
  return data.status;
}

// 4. Obtener resultados
async function getResults(token, scanId) {
  const response = await fetch(
    `${BASE_URL}/sentinel/results/${scanId}`,
    {headers: {'Authorization': `Bearer ${token}`}}
  );
  return await response.json();
}

// 5. Uso
(async () => {
  const token = await login('mariagarcia', 'MiPassword123!');
  console.log('Token obtenido');

  const scanId = await startNiktoScan(token, 'http://testphp.vulnweb.com');
  console.log(`Escaneo iniciado: ${scanId}`);

  // Polling
  let status;
  do {
    await new Promise(resolve => setTimeout(resolve, 10000)); // 10 seg
    status = await checkStatus(token, scanId);
    console.log(`Estado: ${status}`);
  } while (status !== 'completed');

  const results = await getResults(token, scanId);
  console.log(`Total incidentes: ${results.result.totalIncidents}`);
  results.result.incidents.forEach(inc => {
    console.log(`  [${inc.method}] ${inc.url}`);
    console.log(`    ${inc.description}`);
  });
})();
```

## 🤝 Contribución

### Guía de Contribución

1. **Fork del repositorio**
   ```bash
   git clone https://github.com/tu-usuario/secops.git
   cd secops
   git checkout -b feature/nueva-funcionalidad
   ```

2. **Estructura de commits**
   ```
   tipo(alcance): descripción corta

   Descripción detallada del cambio

   Tipo: feat, fix, docs, style, refactor, test, chore
   Alcance: api, models, managers, validation, etc.
   ```

3. **Estándares de código**
   - PEP 8 para Python
   - Type hints en todas las funciones públicas
   - Docstrings con formato Google
   - Logging apropiado (info, warning, error)

4. **Tests**
   ```bash
   pytest tests/
   ```

5. **Pull Request**
   - Descripción clara del cambio
   - Tests que cubren la nueva funcionalidad
   - Documentación actualizada

### Roadmap

- [ ] Soporte para escaneos OpenVAS
- [ ] WebSocket para progreso en tiempo real
- [ ] Dashboard web con estadísticas
- [ ] Exportación a JSON/CSV
- [ ] Programación de escaneos recurrentes
- [ ] Notificaciones por email
- [ ] Integración con SIEM
- [ ] API GraphQL

## 📄 Licencia

Este proyecto está licenciado bajo la Licencia MIT - ver el archivo LICENSE para más detalles.

```
MIT License

Copyright (c) 2025 SecOps Team

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---


**Desarrollado con ❤️ por el equipo SecOps**
