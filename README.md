# SecOps Scanner Platform

Plataforma unificada de gestión de auditorías de seguridad que integra **Nmap** y **Nikto** a través de una API REST moderna. Permite lanzar escaneos asíncronos, consultar resultados y generar reportes PDF ejecutivos con arquitectura modular basada en Flask.

## 🎯 Características principales

### Escaneo de puertos con Nmap
- Gestión asíncrona de múltiples escaneos simultáneos.
- Soporte para especificaciones avanzadas de objetivos:
  - IPs individuales: `192.168.1.1`
  - Notación CIDR: `192.168.1.0/24`
  - Rangos por octeto: `192.168.1.1-10` o `192.168.1-2.1-10`
  - Wildcards: `192.168.1.*`
- Especificación flexible de puertos: `80,443`, `1-1000`, `-1000`, `8080-`.
- Validación estricta de formato inspirada en sintaxis Nmap.

### Escaneo de vulnerabilidades con Nikto
- Detección automatizada de vulnerabilidades web.
- Configuración de timeouts personalizados.
- Catalogación de incidentes con referencias OSVDB.
- Tracking temporal de descubrimientos.

### Generación de reportes
- `PDFCreator` con estrategias de impresión específicas por tipo de escaneo (Nmap, Nikto).
- Exportación en formato binario (descarga directa).
- Exportación en Base64 (visualización embebida en front-end).
- Diseño orientado a reportes ejecutivos con metadatos completos.

### Interfaz web interactiva
- Dashboard visual (`index.html`) con animación de terminal en tiempo real (`terminal-animation.js`).
- Formularios validados para lanzar escaneos (`scan-launcher.js`).
- Historial de auditorías con estados actualizables.
- Descarga directa de reportes PDF.
- Diseño sencillo y extensible.

## 🏗️ Arquitectura del proyecto

```text
SecOpsScanner/
├── APIMain.py                 # API Flask principal
├── index.html                 # Dashboard web
├── terminal-animation.js      # Animaciones de terminal
├── scan-launcher.js           # Lógica de formularios y llamadas a la API
├── requirements.txt           # Dependencias Python
└── src/
    ├── persistence/           # Gestión de base de datos
    │   ├── UserDBManager
    │   └── ScanDBManager
    ├── scanning/              # Managers de escaneo
    │   ├── NmapScanManager
    │   └── NiktoScanManager
    ├── misc/
    │   ├── documents/         # Generación de PDFs (PDFCreator, estrategias)
    │   └── logging/           # Sistema de logs (SecOpsLogger)
    └── model/                 # Modelos de dominio (Scan, puertos, incidentes, etc.)
```

## 📡 API Reference (resumen)

### Endpoints generales

#### `GET /say-hello`
Endpoint de health check para verificar disponibilidad de la API.

Respuesta de ejemplo:
```json
{
  "message": "You did it! You reached an endpoint!",
  "status": "ok"
}
```

#### `GET /is-finished?id={scan_id}`
Verifica el estado de finalización de un escaneo (Nmap o Nikto).

Parámetros:
- `id` (query): ID del escaneo.

Respuesta de ejemplo:
```json
{
  "message": "El escaneo con id 104 está terminado",
  "existe": true
}
```

### Endpoints de escaneo

#### `POST /scans/nmap/start`
Inicia un escaneo Nmap.

Headers requeridos:
- `X-Target-Host`: Host o rango de IPs a escanear.
- `X-Target-Ports`: Puertos a escanear.

Ejemplo:
```bash
curl -X POST http://localhost:5000/scans/nmap/start \
  -H "X-Target-Host: 192.168.1.0/24" \
  -H "X-Target-Ports: 22,80,443-8080"
```

Respuesta de ejemplo:
```json
{
  "message": "Escaneo Nmap iniciado correctamente",
  "scanId": [104, 105, 106],
  "target": {
    "host": "192.168.1.0/24",
    "ports": "22,80,443-8080"
  }
}
```

#### `POST /scans/nikto/start?timeout={seconds}`
Inicia un escaneo Nikto.

Headers requeridos:
- `X-Target`: URL objetivo del escaneo.

Query parameters:
- `timeout` (opcional): tiempo máximo en segundos (por defecto: 180).

Ejemplo:
```bash
curl -X POST http://localhost:5000/scans/nikto/start?timeout=300 \
  -H "X-Target: http://example.com"
```

Respuesta de ejemplo:
```json
{
  "message": "Escaneo Nikto iniciado correctamente",
  "scanId": 42,
  "target": "http://example.com",
  "timeout": 300
}
```

### Endpoints de reportes

#### `GET /scans/generate-pdf?id={scan_id}`
Genera y descarga un PDF del escaneo.

Parámetros:
- `id` (query): ID del escaneo.

Respuesta: archivo PDF (`application/pdf`) para descarga directa.

#### `GET /scans/generate-pdf-base64?id={scan_id}`
Genera un PDF en formato Base64.

Respuesta de ejemplo:
```json
{
  "message": "PDF generado exitosamente",
  "scanId": "104",
  "scanType": "nmap",
  "filename": "nmap_scan_104.pdf",
  "pdfBase64": "JVBERi0xLjQKJ...",
  "contentType": "application/pdf"
}
```

### Endpoints de resultados

#### `GET /scans/results?type={scan_type}`
Obtiene todos los escaneos del usuario.

Query parameters:
- `type` (opcional): `nmap`, `nikto` o `all` (por defecto: `all`).

Respuesta de ejemplo:
```json
{
  "message": "Escaneos obtenidos correctamente",
  "filter": "all",
  "count": 15,
  "results": [
    {
      "id": 104,
      "scanType": "nmap",
      "target": "192.168.1.10",
      "targetedPorts": ["22/tcp", "80/tcp"],
      "startedAt": "2025-11-28T20:15:30",
      "openPorts": [
        {
          "port": "22/tcp",
          "reason": "syn-ack"
        }
      ],
      "totalOpenPorts": 1
    }
  ]
}
```

#### `GET /scans/results/{scan_id}`
Obtiene los detalles de un escaneo específico (Nmap o Nikto).

## 🚀 Instalación y puesta en marcha

### Requisitos previos

- Python 3.8 o superior.
- Nmap instalado en el sistema.
- Nikto instalado en el sistema.
- Base de datos configurada (por ejemplo SQLite / PostgreSQL / MySQL).
- Navegador moderno para la interfaz web.

### Pasos de instalación

1. Clonar el repositorio:
```bash
git clone https://github.com/tu-usuario/secops-scanner.git
cd secops-scanner
```

2. Crear entorno virtual:
```bash
python -m venv venv
source venv/bin/activate  # En Windows: venv\Scripts\activate
```

3. Instalar dependencias:
```bash
pip install -r requirements.txt
```

4. Configurar la base de datos:
```bash
# Ajustar la cadena de conexión en src/persistence/config.py o variables de entorno
python -m src.persistence.init_db
```

5. Iniciar la API Flask:
```bash
python APIMain.py
```

6. Servir la interfaz web:
```bash
# Opción simple
python -m http.server 8000
# Navegar a:
# http://localhost:8000/index.html
```

## 🔒 Validaciones de entrada

### Validación de puertos (Nmap)
- Rango permitido: 1–65535.
- Puertos y rangos en orden ascendente.
- Sin solapamiento de rangos.
- Soporte de:
  - Puertos individuales: `80`
  - Listas separadas por comas: `80,443,8080`
  - Rangos: `1-1000`
  - Rangos abiertos: `-1000`, `1000-`

### Validación de IPs / targets
- IP individual: `192.168.1.1`.
- CIDR: `192.168.1.0/24`.
- Rangos por octeto: `192.168.1.1-10`, `192.168.1-2.1-10`.
- Wildcards: `192.168.1.*` (expandido a `192.168.1.0-255`).
- Eliminación de duplicados respetando el orden de entrada.

## 📊 Logging y manejo de errores

### Logging
- Se utiliza `SecOpsLogger` para logging centralizado.
- Niveles: DEBUG, INFO, WARNING, ERROR, CRITICAL.
- Timestamps con formato legible y consistentes.
- Logs específicos por endpoint y tipo de escaneo.

### Manejo de errores
Los endpoints devuelven códigos HTTP estándar:
- `200` – Operación correcta.
- `201` – Recurso creado (inicio de escaneo, generación de reporte).
- `400` – Error de validación de parámetros de entrada.
- `404` – Recurso / escaneo no encontrado.
- `500` – Error interno del servidor.

Las respuestas de error incluyen un mensaje humano-legible y, en algunos casos, detalles adicionales para depuración.

## 🧪 Testing (recomendado)

Estructura sugerida:
```text
tests/
├── __init__.py
├── test_validators.py       # Tests para validar_puertos_nmap(), validar_ips_nmap()
├── test_endpoints.py        # Tests para endpoints de la API
├── test_pdf_generation.py   # Tests para PDFCreator
└── integration/
    └── test_full_scan.py    # Tests end-to-end
```

Ejemplos:
```bash
# Ejecutar tests unitarios
pytest tests/

# Con cobertura
pytest --cov=src tests/
```

## 🔧 Configuración adicional recomendada

- Archivo `.env` para configuración sensible (claves, URLs de BBDD, rutas a Nmap/Nikto).
- Archivo `.gitignore` para excluir `venv`, PDFs generados, logs, etc.
- Dockerfile y `docker-compose.yml` para despliegue reproducible.
- Integración de CI (GitHub Actions u otro) para ejecutar tests en cada push.

## 👥 Contribución

1. Haz un fork del repositorio.
2. Crea una rama de feature: `git checkout -b feature/MiFeature`.
3. Haz commits claros: `git commit -m "Add MiFeature"`.
4. Sube la rama: `git push origin feature/MiFeature`.
5. Abre un Pull Request describiendo los cambios.

## 📜 Licencia

Este proyecto se distribuye bajo una licencia CC BY-NC

---

> ⚠️ Uso responsable: Esta herramienta está pensada para entornos de auditoría y pruebas de penetración autorizadas. No debe utilizarse contra sistemas para los que no se tenga permiso explícito.
