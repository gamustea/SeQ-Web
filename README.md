# SecOps API

<div align="center">

![SecOps](https://img.shields.io/badge/SecOps-API-blue?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.12-green?style=for-the-badge&logo=python)
![Flask](https://img.shields.io/badge/Flask-3.0-black?style=for-the-badge&logo=flask)
![SQLAlchemy](https://img.shields.io/badge/SQLAlchemy-2.0-red?style=for-the-badge)

**API REST para gestión y automatización de escaneos de seguridad con Nmap y Nikto**

</div>

## 📖 Descripción

**SecOps API** es una API REST construida con Flask que permite gestionar y automatizar escaneos de seguridad utilizando herramientas como **Nmap** y **Nikto**. El sistema incluye autenticación por usuario, gestión multiusuario, generación de reportes en PDF y un frontend web interactivo.

### 🎯 Casos de Uso

- **Auditorías de seguridad automatizadas**: Programa escaneos periódicos de tu infraestructura
- **Gestión centralizada**: Administra todos tus escaneos desde una única API
- **Multiusuario**: Cada usuario tiene acceso solo a sus propios escaneos
- **Reportes profesionales**: Genera PDFs con los resultados de los escaneos
- **Integración con otras herramientas**: API REST fácil de integrar en tus pipelines de CI/CD

---

## ✨ Características

### Core Features

- ✅ **API REST completa** con Flask
- ✅ **Autenticación basada en headers** (X-Username, X-Password)
- ✅ **Sistema multiusuario** con aislamiento de datos
- ✅ **Escaneos Nmap**: Puertos, hosts, rangos de IPs
- ✅ **Escaneos Nikto**: Análisis de vulnerabilidades web
- ✅ **Generación de reportes PDF** con diseño profesional
- ✅ **Base de datos SQLAlchemy** con ORM completo
- ✅ **Sistema de excepciones personalizado** con códigos de error
- ✅ **Logging estructurado** para trazabilidad
- ✅ **CORS habilitado** para desarrollo frontend

### Gestión de Escaneos

- 📊 **Historial completo** de escaneos por usuario
- 🔄 **Estado en tiempo real** de escaneos en progreso
- 📄 **Exportación a PDF** de resultados
- 🎯 **Validación de inputs** (IPs, puertos, URLs)
- ⚡ **Ejecución asíncrona** de escaneos
- 🔍 **Filtrado por tipo** (Nmap, Nikto, todos)

### Seguridad

- 🔐 **Autenticación requerida** en todos los endpoints
- 👥 **Aislamiento por usuario** (cada usuario ve solo sus datos)
- 🛡️ **Validación exhaustiva** de parámetros
- 📝 **Logs de auditoría** por usuario
- ⚠️ **Manejo robusto de errores** con mensajes amigables

## 🎮 Uso

### Iniciar el servidor

```bash
cd API
python run.py
```

La API estará disponible en `http://localhost:5000`

### Uso desde línea de comando (curl)

```bash
# Iniciar escaneo Nmap
curl -X POST http://localhost:5000/scans/nmap/start \
  -H "X-Username: root" \
  -H "X-Password: root" \
  -H "X-Target-Host: 192.168.1.1" \
  -H "X-Target-Ports: 80,443"

# Verificar estado
curl -X GET http://localhost:5000/is-finished?id=1 \
  -H "X-Username: root" \
  -H "X-Password: root"

# Obtener resultados
curl -X GET http://localhost:5000/scans/results \
  -H "X-Username: root" \
  -H "X-Password: root"
```

---

## 📚 API Reference

### Base URL

```
http://localhost:5000
```

### Autenticación

Todos los endpoints (excepto `/say-hello`) requieren autenticación mediante headers:

```http
X-Username: tu_usuario
X-Password: tu_contraseña
```

**Respuesta de error de autenticación:**

```json
{
  "error": "InvalidCredentialsError",
  "code": 1602,
  "message": "Usuario o contraseña incorrectos.",
  "timestamp": "2025-12-12T17:00:00.000Z"
}
```

---

### Endpoints de Escaneo

#### 🔵 Iniciar Escaneo Nmap

```http
POST /scans/nmap/start
```

**Headers requeridos:**
```http
X-Username: root
X-Password: root
X-Target-Host: 192.168.1.1
X-Target-Ports: 80,443
```

**Formatos de host soportados:**
- IP única: `192.168.1.1`
- Rango CIDR: `192.168.1.0/24`
- Rango de IPs: `192.168.1.1-10`

**Formatos de puertos soportados:**
- Puerto único: `80`
- Lista: `80,443,8080`
- Rango: `1-1000`
- Combinado: `80,443,8000-9000`

**Respuesta exitosa (201):**
```json
{
  "message": "Escaneo(s) Nmap iniciado(s) correctamente",
  "scanIds": [1, 2, 3],
  "target": {
    "hosts": ["192.168.1.1", "192.168.1.2"],
    "ports": "80,443"
  },
  "totalScans": 3,
  "user": "root"
}
```

**Errores posibles:**
- `400` - Parámetros inválidos
- `401` - Autenticación fallida
- `500` - Error interno

---

#### 🔵 Iniciar Escaneo Nikto

```http
POST /scans/nikto/start?timeout=180
```

**Headers requeridos:**
```http
X-Username: root
X-Password: root
X-Target: http://example.com
```

**Query Parameters:**
- `timeout` (opcional): Tiempo máximo en segundos (default: 180)

**Respuesta exitosa (201):**
```json
{
  "message": "Escaneo Nikto iniciado correctamente",
  "scanId": 1,
  "target": "http://example.com",
  "timeout": 180,
  "user": "root"
}
```

---

### Endpoints de Consulta

#### 🟢 Verificar Estado de Escaneo

```http
GET /is-finished?id=1
```

**Headers requeridos:**
```http
X-Username: root
X-Password: root
```

**Respuesta (200):**
```json
{
  "message": "El escaneo con id 1 está terminado",
  "scanId": 1,
  "isFinished": true,
  "scanType": "nmap"
}
```

---

#### 🟢 Obtener Todos los Escaneos

```http
GET /scans/results?type=all
```

**Headers requeridos:**
```http
X-Username: root
X-Password: root
```

**Query Parameters:**
- `type` (opcional): `nmap`, `nikto`, o `all` (default: `all`)

**Respuesta (200):**
```json
{
  "message": "Escaneos obtenidos correctamente",
  "filter": "all",
  "count": 2,
  "user": "root",
  "results": [
    {
      "id": 1,
      "scanType": "nmap",
      "target": "192.168.1.1",
      "targetedPorts": ["80/tcp", "443/tcp"],
      "startedAt": "2025-12-12T17:00:00",
      "openPorts": [
        {
          "port": "80/tcp",
          "reason": "syn-ack"
        }
      ],
      "totalOpenPorts": 1
    },
    {
      "id": 2,
      "scanType": "nikto",
      "target": "http://example.com",
      "startedAt": "2025-12-12T17:05:00",
      "incidents": [
        {
          "osvdbId": "12345",
          "method": "GET",
          "url": "/admin",
          "description": "Admin panel found",
          "discoveredAt": "2025-12-12T17:06:00"
        }
      ],
      "totalIncidents": 1
    }
  ]
}
```

---

#### 🟢 Obtener Escaneo Específico

```http
GET /scans/results/{scan_id}
```

**Headers requeridos:**
```http
X-Username: root
X-Password: root
```

**Respuesta (200):**
```json
{
  "message": "Escaneo obtenido correctamente",
  "user": "root",
  "result": {
    "id": 1,
    "scanType": "nmap",
    "target": "192.168.1.1",
    "startedAt": "2025-12-12T17:00:00",
    "openPorts": [...],
    "totalOpenPorts": 5
  }
}
```

**Errores posibles:**
- `404` - Escaneo no encontrado

---

### Endpoints de Reportes

#### 🟡 Descargar PDF

```http
GET /scans/generate-pdf?id=1
```

**Headers requeridos:**
```http
X-Username: root
X-Password: root
```

**Respuesta (200):**
- **Content-Type:** `application/pdf`
- **Descarga directa** del archivo PDF

**Errores posibles:**
- `404` - Escaneo no encontrado
- `400` - Escaneo no finalizado
- `500` - Error generando PDF

---

#### 🟡 Obtener PDF en Base64

```http
GET /scans/generate-pdf-base64?id=1
```

**Headers requeridos:**
```http
X-Username: root
X-Password: root
```

**Respuesta (200):**
```json
{
  "message": "PDF generado exitosamente",
  "scanId": 1,
  "scanType": "nmap",
  "filename": "nmap_scan_1.pdf",
  "pdfBase64": "JVBERi0xLjQKJeLjz9MKMSAwIG9iago8PC9UeXBlL...",
  "contentType": "application/pdf",
  "user": "root"
}
```

---

### Endpoint de Prueba

#### 🟣 Hello World

```http
GET /say-hello
```

**No requiere autenticación**

**Respuesta (200):**
```json
{
  "message": "You did it! You reached an endpoint!",
  "status": "ok",
  "version": "2.0-multiuser"
}
```

---

## 🛡️ Sistema de Excepciones

La API utiliza un sistema de excepciones personalizado con códigos de error estandarizados.

### Códigos de Error

| Rango | Categoría | Ejemplos |
|-------|-----------|----------|
| 1000-1099 | Errores generales | Error interno, no implementado |
| 1100-1199 | Validación | Parámetro inválido, falta parámetro |
| 1200-1299 | Base de datos | Entidad no encontrada, error de conexión |
| 1300-1399 | Escaneo | Escaneo no encontrado, error de ejecución |
| 1400-1499 | Reportes | Error generando PDF |
| 1500-1599 | Configuración | Configuración faltante |
| 1600-1699 | Autenticación | Credenciales inválidas, token expirado |
| 1700-1799 | Parsing | Error parseando XML/JSON |

### Estructura de Respuesta de Error

```json
{
  "error": "ValidationError",
  "code": 1100,
  "message": "Los datos proporcionados no son válidos.",
  "timestamp": "2025-12-12T17:00:00.000Z",
  "details": {
    "field": "ports",
    "value": "invalid",
    "expected": "Formato: '80', '80,443', '1-1000'"
  }
}
```

### Excepciones Comunes

#### MissingParameterError (1105)
```json
{
  "error": "MissingParameterError",
  "code": 1105,
  "message": "El parámetro 'X-Username' es obligatorio."
}
```

#### InvalidCredentialsError (1602)
```json
{
  "error": "InvalidCredentialsError",
  "code": 1602,
  "message": "Usuario o contraseña incorrectos."
}
```

#### ScanNotFoundError (1301)
```json
{
  "error": "ScanNotFoundError",
  "code": 1301,
  "message": "El escaneo #123 no existe.",
  "details": {
    "scan_id": 123
  }
}
```

---

## 🖥️ Frontend

### Características del Frontend

- ✅ **Interfaz limpia** y responsive
- ✅ **Formularios de escaneo** para Nmap y Nikto
- ✅ **Historial de escaneos** con actualización manual
- ✅ **Verificación de estado** individual por escaneo
- ✅ **Descarga de PDFs** con un clic
- ✅ **Feedback visual** (loading states, mensajes de error/éxito)

### Estructura de Archivos

```
frontend/
├── index.html          # Estructura HTML
├── scan-launcher.js    # Lógica de la aplicación
└── styles.css          # Estilos (no incluido en este proyecto)
```

### Configuración del Frontend

En `scan-launcher.js`, ajusta las constantes:

```javascript
const API_BASE_URL = 'http://127.0.0.1:5000';
const USERNAME = 'root';
const PASSWORD = 'root';
```

### Funciones Principales

```javascript
// Iniciar escaneo Nmap
document.getElementById('nmapScanForm').addEventListener('submit', ...)

// Iniciar escaneo Nikto
document.getElementById('niktoScanForm').addEventListener('submit', ...)

// Cargar historial
loadScanHistory()

// Verificar estado
checkScanStatus(scanId)

// Descargar PDF
window.downloadPDF(scanId)
```

---

## 📝 Ejemplos

### Ejemplo 1: Escaneo Nmap de un Servidor Web

```bash
curl -X POST http://localhost:5000/scans/nmap/start \
  -H "X-Username: admin" \
  -H "X-Password: admin123" \
  -H "X-Target-Host: example.com" \
  -H "X-Target-Ports: 80,443,8080"
```

### Ejemplo 2: Escaneo Nikto con Timeout Personalizado

```bash
curl -X POST "http://localhost:5000/scans/nikto/start?timeout=300" \
  -H "X-Username: admin" \
  -H "X-Password: admin123" \
  -H "X-Target: https://example.com"
```

### Ejemplo 3: Obtener Solo Escaneos Nmap

```bash
curl -X GET "http://localhost:5000/scans/results?type=nmap" \
  -H "X-Username: admin" \
  -H "X-Password: admin123"
```

### Ejemplo 4: Descargar PDF con Python

```python
import requests

response = requests.get(
    'http://localhost:5000/scans/generate-pdf',
    params={'id': 1},
    headers={
        'X-Username': 'admin',
        'X-Password': 'admin123'
    }
)

with open('scan_report.pdf', 'wb') as f:
    f.write(response.content)
```

### Ejemplo 5: Integración con JavaScript

```javascript
async function startNmapScan(host, ports) {
    const response = await fetch('http://localhost:5000/scans/nmap/start', {
        method: 'POST',
        headers: {
            'X-Username': 'admin',
            'X-Password': 'admin123',
            'X-Target-Host': host,
            'X-Target-Ports': ports
        }
    });

    const data = await response.json();
    console.log('Escaneo iniciado:', data.scanIds);
    return data;
}

startNmapScan('192.168.1.1', '80,443');
```

---

## 🔧 Solución de Problemas

### Error: "Object is already attached to session"

**Causa:** Conflicto de sesiones de SQLAlchemy entre UserManager y ScanManagers.

**Solución:** Asegúrate de que `verify_credentials()` devuelve solo el `user_id`:

```python
def verify_credentials(self, username: str, password: str) -> tuple[bool, Optional[int]]:
    user = self.db_manager.get_user_by_username(username)
    if not user or user.password != password:
        return False, None

    user_id = user.id
    self.db_manager.session.expunge(user)
    return True, user_id
```

### Error: "Nmap not found"

**Causa:** Nmap no está instalado o no está en el PATH.

**Solución:**
```bash
# Ubuntu/Debian
sudo apt install nmap

# macOS
brew install nmap

# Verificar
which nmap
```

### Error: "Port already in use"

**Causa:** El puerto 5000 ya está siendo usado.

**Solución:** Cambia el puerto en `run.py`:
```python
app.run(debug=True, port=5001)
```

### Error de CORS en el navegador

**Causa:** Frontend y API en diferentes puertos.

**Solución:** CORS ya está habilitado. Si persiste, especifica el origen:
```python
from flask_cors import CORS
CORS(app, resources={r"/*": {"origins": "http://localhost:8000"}})
```

### PDF no se descarga

**Causa:** Escaneo no finalizado o error en generación.

**Solución:**
1. Verifica que el escaneo esté terminado: `GET /is-finished?id=X`
2. Revisa los logs del servidor
3. Verifica que ReportLab esté instalado: `pip install reportlab`

---

## 🙏 Agradecimientos

- [Flask](https://flask.palletsprojects.com/) - Framework web
- [SQLAlchemy](https://www.sqlalchemy.org/) - ORM
- [Nmap](https://nmap.org/) - Scanner de red
- [Nikto](https://cirt.net/Nikto2) - Scanner web
- [ReportLab](https://www.reportlab.com/) - Generación de PDFs