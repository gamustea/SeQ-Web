# SecOps API - Sistema de Escaneo de Vulnerabilidades

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![Flask](https://img.shields.io/badge/Flask-2.0+-green.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

**SecOps API** es una API REST construida con Flask que integra herramientas de seguridad como **Nmap**, **Nikto** y **OpenVAS** para realizar análisis de vulnerabilidades automatizados. Proporciona autenticación OAuth 2.0, gestión de usuarios y generación de reportes en PDF.

---

## 📋 Características

### 🔒 Seguridad y Autenticación
- **OAuth 2.0** con JWT para autenticación
- Tokens de acceso y refresco
- Hashing seguro de contraseñas con SHA-256 + salt
- Rate limiting para prevenir ataques de fuerza bruta
- Sistema de roles y permisos

### 🛡️ Herramientas de Escaneo Integradas
- **Nmap**: Escaneo de puertos y detección de servicios
- **Nikto**: Análisis de vulnerabilidades web
- **OpenVAS**: Evaluación completa de vulnerabilidades con GMP

### 📊 Gestión de Resultados
- Almacenamiento en base de datos MySQL/MariaDB
- Clasificación automática de severidad (CRITICAL, HIGH, MEDIUM, LOW, INFO)
- Seguimiento del progreso de escaneos en tiempo real
- Historial completo de escaneos por usuario

### 📄 Generación de Reportes
- Exportación de resultados en PDF profesional
- Reportes personalizados según tipo de escaneo
- Paleta de colores específica por herramienta
- Información detallada de vulnerabilidades con CVE, CVSS y soluciones

---

## 🏗️ Arquitectura del Proyecto

```
SecOps-API/
├── src/
│   ├── core/
│   │   ├── model.py           # Modelos ORM (SQLAlchemy)
│   │   └── exceptions.py      # Sistema de excepciones personalizado
│   ├── logic/
│   │   ├── managers.py        # Gestores de escaneo y usuarios
│   │   ├── tasks.py           # Tareas asíncronas de escaneo
│   │   ├── processors.py      # Procesadores de resultados
│   │   ├── documents.py       # Generación de reportes PDF
│   │   └── secrets.py         # Utilidades criptográficas
│   ├── misc/
│   │   ├── validation.py      # Validación de IPs, puertos, URLs
│   │   ├── logging.py         # Sistema de logging
│   │   ├── configread.py      # Lectura de configuración
│   │   └── conversion.py      # Conversión JSON/XML
│   └── run.py                 # API Flask y endpoints
└── config.ini                 # Configuración de la aplicación
```

---

## 🚀 Instalación

### Requisitos Previos

- **Python 3.9+**
- **MySQL/MariaDB**
- **Nmap** (instalado en el sistema)
- **Nikto** (instalado en el sistema)
- **OpenVAS/GVM** (servidor configurado)

### Instalación de Dependencias

```bash
# Clonar el repositorio
git clone https://github.com/tu-usuario/secops-api.git
cd secops-api

# Crear entorno virtual
python3 -m venv venv
source venv/bin/activate  # En Windows: venv\Scripts\activate

# Instalar dependencias
pip install -r requirements.txt
```

### Configuración de la Base de Datos

```bash
# Acceder a MySQL
mysql -u root -p

# Crear base de datos
CREATE DATABASE secops_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

# Crear usuario (recomendado)
CREATE USER 'secops_user'@'localhost' IDENTIFIED BY 'tu_contraseña_segura';
GRANT ALL PRIVILEGES ON secops_db.* TO 'secops_user'@'localhost';
FLUSH PRIVILEGES;
```

### Configuración de `config.ini`

```ini
[database]
username = secops_user
password = tu_contraseña_segura
host = localhost
db_name = secops_db

[oauth]
access_token_expire_minutes = 30
refresh_token_expire_days = 7
jwt_secret_key = tu_clave_secreta_muy_larga_y_aleatoria
jwt_algorithm = HS256

[openvas]
hostname = localhost
port = 9390
username = admin
password = admin
scan_config = daba56c8-73ec-11df-a475-002264764cea
port_list_id = 33d0cd82-57c6-11e1-8ed1-406186ea4fc5

[directories]
temp = /tmp/secops
reports = /var/secops/reports
logs = /var/log/secops
```

### Ejecutar la Aplicación

```bash
# Modo desarrollo
python run.py

# Modo producción con Gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 run:app
```

---

## 📖 Uso de la API

### Autenticación

#### Obtener Token de Acceso

```bash
curl -X POST http://localhost:5000/oauth/token \
  -H "Content-Type: application/json" \
  -d '{
    "X-Grant-Type": "password",
    "X-Username": "usuario",
    "X-Password": "contraseña"
  }'
```

**Respuesta:**

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 1800,
  "refresh_token": "dGhpc19pc19hX3JlZnJlc2hfdG9rZW4..."
}
```

#### Renovar Token

```bash
curl -X POST http://localhost:5000/oauth/token \
  -H "Content-Type: application/json" \
  -d '{
    "X-Grant-Type": "refresh_token",
    "X-Refresh-Token": "tu_refresh_token"
  }'
```

---

### Gestión de Usuarios

#### Registrar Usuario

```bash
curl -X POST http://localhost:5000/sentinel/user \
  -H "Content-Type: application/json" \
  -d '{
    "username": "nuevo_usuario",
    "password": "contraseña_segura",
    "first_name": "Nombre",
    "last_name": "Apellido",
    "alias": "alias_unico",
    "email": "usuario@ejemplo.com"
  }'
```

---

### Escaneos

Todos los endpoints de escaneo requieren el header `Authorization: Bearer <access_token>`.

#### Escaneo Nmap

```bash
curl -X POST http://localhost:5000/sentinel/nmap-scan \
  -H "Authorization: Bearer tu_access_token" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "192.168.1.1",
    "ports": "1-1000"
  }'
```

**Respuesta:**

```json
{
  "message": "Escaneo Nmap iniciado exitosamente",
  "scanId": 42,
  "target": "192.168.1.1",
  "ports": "1-1000"
}
```

#### Escaneo Nikto

```bash
curl -X POST http://localhost:5000/sentinel/nikto-scan \
  -H "Authorization: Bearer tu_access_token" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "http://ejemplo.com"
  }'
```

#### Escaneo OpenVAS

```bash
curl -X POST http://localhost:5000/sentinel/openvas-scan \
  -H "Authorization: Bearer tu_access_token" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "192.168.1.100"
  }'
```

---

### Consultar Estado de Escaneo

```bash
curl -X GET "http://localhost:5000/sentinel/scan-status?id=42" \
  -H "Authorization: Bearer tu_access_token"
```

**Respuesta:**

```json
{
  "message": "Estado del escaneo con id 42: running",
  "scanId": 42,
  "status": "running",
  "scanType": "nmap",
  "progress": 65
}
```

---

### Obtener Resultados

```bash
curl -X GET "http://localhost:5000/sentinel/scan-results?id=42" \
  -H "Authorization: Bearer tu_access_token"
```

---

### Generar Reporte PDF

```bash
curl -X GET "http://localhost:5000/sentinel/generate-report?id=42" \
  -H "Authorization: Bearer tu_access_token" \
  --output reporte_42.pdf
```

---

## 🗄️ Modelo de Datos

### Entidades Principales

- **User**: Usuarios del sistema con credenciales OAuth
- **Person**: Información personal de usuarios
- **Scan**: Clase base polimórfica para escaneos
  - **NmapScan**: Escaneos de puertos
  - **NiktoScan**: Escaneos web
  - **OpenVASScan**: Evaluaciones de vulnerabilidades
- **Host**: Información de hosts escaneados
- **Port**: Puertos y servicios detectados
- **OpenPort**: Relación entre escaneos Nmap y puertos abiertos
- **NiktoIncident**: Incidentes detectados por Nikto
- **OpenVASVulnerability**: Vulnerabilidades de OpenVAS con CVSS
- **FinishedScan**: Registro de finalización de escaneos

---

## 🔧 Características Técnicas

### Manejo de Errores

El sistema utiliza excepciones personalizadas con códigos de error estructurados:

- **1000-1099**: Errores generales
- **1100-1199**: Errores de validación
- **1200-1299**: Errores de base de datos
- **1300-1399**: Errores de escaneo
- **1400-1499**: Errores de reportes
- **1600-1699**: Errores de autenticación

### Logging

Sistema de logging multinivel con rotación automática:

```python
from src.misc.logging import SecOpsLogger

logger = SecOpsLogger(name="MiModulo").get_logger()
logger.info("Mensaje informativo")
logger.error("Error crítico", exc_info=True)
```

### Validación de Entrada

```python
from src.misc.validation import PortValidator, IPValidator

# Validar puertos
PortValidator.validate("80,443,8000-9000")

# Validar IPs
IPValidator.validate("192.168.1.1")
IPValidator.validate("192.168.1.0/24")
```

---

## 🧪 Testing

```bash
# Ejecutar tests unitarios
python -m pytest tests/

# Con cobertura
python -m pytest --cov=src tests/
```

---

## 🛡️ Consideraciones de Seguridad

1. **Nunca expongas la API directamente a Internet sin un proxy reverso (Nginx, Apache)**
2. **Usa HTTPS en producción** con certificados válidos
3. **Cambia las claves secretas** en `config.ini` a valores aleatorios largos
4. **Configura firewall** para restringir acceso a puertos de escaneo
5. **Ejecuta escaneos solo en redes autorizadas**
6. **Implementa rate limiting** adicional a nivel de proxy
7. **Revisa permisos de archivos** especialmente en directorios de reportes

---

## 📝 Notas Legales

⚠️ **IMPORTANTE**: Esta herramienta debe usarse **únicamente** en entornos autorizados. El escaneo no autorizado de sistemas es **ilegal** en la mayoría de jurisdicciones.

- Obtén **permiso por escrito** antes de escanear cualquier red
- Usa sitios de prueba legales como:
  - `scanme.nmap.org`
  - `testphp.vulnweb.com`
  - Plataformas de bug bounty autorizadas

El autor no se hace responsable del mal uso de esta herramienta.

---

## 🤝 Contribuciones

Las contribuciones son bienvenidas. Por favor:

1. Fork el proyecto
2. Crea una rama de características (`git checkout -b feature/nueva-funcionalidad`)
3. Commit tus cambios (`git commit -m 'Añade nueva funcionalidad'`)
4. Push a la rama (`git push origin feature/nueva-funcionalidad`)
5. Abre un Pull Request

---

## 📄 Licencia

Este proyecto está bajo la Licencia MIT. Consulta el archivo `LICENSE` para más detalles.

---

## 👤 Autor

**Gabriel** - Ingeniero en Informática especializado en Ciberseguridad

- GitHub: [@tu-usuario](https://github.com/tu-usuario)
- LinkedIn: [Tu Perfil](https://linkedin.com/in/tu-perfil)

---

## 🙏 Agradecimientos

- **Nmap Project** - https://nmap.org
- **Nikto** - https://github.com/sullo/nikto
- **OpenVAS/Greenbone** - https://www.greenbone.net
- **Flask Team** - https://flask.palletsprojects.com
- **SQLAlchemy** - https://www.sqlalchemy.org

---

## 📚 Documentación Adicional

- [Guía de Instalación Detallada](docs/INSTALLATION.md)
- [API Reference Completa](docs/API.md)
- [Arquitectura del Sistema](docs/ARCHITECTURE.md)
- [Guía de Contribución](CONTRIBUTING.md)

---

**¿Encontraste un bug?** Por favor abre un [issue](https://github.com/tu-usuario/secops-api/issues) con detalles sobre cómo reproducirlo.

**¿Tienes preguntas?** Revisa la sección [FAQ](docs/FAQ.md) o contacta al equipo de desarrollo.
