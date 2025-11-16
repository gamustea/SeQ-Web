# 📡 Documentación de Endpoints de la API

## URL Base
```
http://localhost:5000
```

---

## Endpoints Generales

### Verificar Estado de la API

**Endpoint:** `GET /api/say-hello`

**Descripción:** Verifica que la API está funcionando correctamente.

**Ejemplo de solicitud:**
```bash
curl -X GET http://localhost:5000/api/say-hello
```

**Respuesta exitosa (200):**
```json
{
  "message": "You did it! You reached an endpoint!",
  "status": "ok"
}
```

---

## Escaneos Nmap

### Iniciar Escaneo Nmap

**Endpoint:** `POST /api/scans/nmap/start`

**Descripción:** Inicia un nuevo escaneo Nmap en un host específico.

**Headers requeridos:**
- `host` (string): Host o dirección IP a escanear
- `ports` (string): Puertos a escanear (ejemplo: "80,443" o "1-1000")

**Ejemplo de solicitud:**
```bash
curl -X POST http://localhost:5000/api/scans/nmap/start \
  -H "host: 192.168.1.1" \
  -H "ports: 80,443,8080"
```

**Respuesta exitosa (201):**
```json
{
  "message": "Escaneo Nmap iniciado correctamente",
  "scanId": 1,
  "target": {
    "host": "192.168.1.1",
    "ports": "80,443,8080"
  }
}
```

**Errores posibles:**
- `400`: Faltan headers requeridos o formato inválido
- `500`: Error interno al iniciar el escaneo

---

### Obtener Todos los Escaneos Nmap

**Endpoint:** `GET /api/scans/nmap/results`

**Descripción:** Obtiene la lista completa de escaneos Nmap realizados por el usuario.

**Ejemplo de solicitud:**
```bash
curl -X GET http://localhost:5000/api/scans/nmap/results
```

**Respuesta exitosa (200):**
```json
{
  "message": "Escaneos obtenidos correctamente",
  "count": 2,
  "results": [
    {
      "id": 1,
      "target": "192.168.1.1",
      "targetedPorts": ["80/tcp", "443/tcp"],
      "startedAt": "2025-11-16T14:30:00",
      "openPorts": [
        {
          "port": "80/tcp",
          "reason": "syn-ack"
        }
      ],
      "totalOpenPorts": 1
    }
  ]
}
```

---

### Obtener Escaneo Nmap por ID

**Endpoint:** `GET /api/scans/nmap/results/<scan_id>`

**Descripción:** Obtiene los detalles de un escaneo Nmap específico.

**Parámetros de ruta:**
- `scan_id` (integer): ID del escaneo

**Ejemplo de solicitud:**
```bash
curl -X GET http://localhost:5000/api/scans/nmap/results/1
```

**Respuesta exitosa (200):**
```json
{
  "message": "Escaneo obtenido correctamente",
  "result": {
    "id": 1,
    "target": "192.168.1.1",
    "targetedPorts": ["80/tcp", "443/tcp"],
    "startedAt": "2025-11-16T14:30:00",
    "openPorts": [
      {
        "port": "80/tcp",
        "reason": "syn-ack"
      }
    ],
    "totalOpenPorts": 1
  }
}
```

**Errores posibles:**
- `404`: Escaneo no encontrado
- `500`: Error interno del servidor

---

### Generar PDF de Escaneo Nmap

**Endpoint:** `GET /api/scans/nmap/generate-pdf`

**Descripción:** Genera y descarga un informe PDF del escaneo Nmap.

**Query Parameters:**
- `id` (integer, requerido): ID del escaneo

**Ejemplo de solicitud:**
```bash
curl -X GET "http://localhost:5000/api/scans/nmap/generate-pdf?id=1" \
  --output nmap_scan_1.pdf
```

**Respuesta exitosa (200):**
- Archivo PDF descargable

**Errores posibles:**
- `400`: Falta el parámetro 'id' o formato inválido
- `404`: Escaneo no encontrado
- `500`: Error al generar el PDF

---

### Generar PDF de Escaneo Nmap (Base64)

**Endpoint:** `GET /api/scans/nmap/generate-pdf-base64`

**Descripción:** Genera un PDF del escaneo Nmap y lo devuelve en formato base64.

**Query Parameters:**
- `id` (integer, requerido): ID del escaneo

**Ejemplo de solicitud:**
```bash
curl -X GET "http://localhost:5000/api/scans/nmap/generate-pdf-base64?id=1"
```

**Respuesta exitosa (200):**
```json
{
  "message": "PDF generado exitosamente",
  "scanId": "1",
  "filename": "nmap_scan_1.pdf",
  "pdfBase64": "JVBERi0xLjQKJeLjz9MKM...",
  "contentType": "application/pdf"
}
```

---

## Escaneos Nikto

### Iniciar Escaneo Nikto

**Endpoint:** `POST /api/scans/nikto/start`

**Descripción:** Inicia un nuevo escaneo de vulnerabilidades Nikto.

**Headers requeridos:**
- `target` (string): URL objetivo del escaneo

**Query Parameters opcionales:**
- `timeout` (integer): Tiempo máximo de ejecución en segundos (default: 180)

**Ejemplo de solicitud:**
```bash
curl -X POST "http://localhost:5000/api/scans/nikto/start?timeout=300" \
  -H "target: https://example.com"
```

**Respuesta exitosa (201):**
```json
{
  "message": "Escaneo Nikto iniciado correctamente",
  "scanId": 1,
  "target": "https://example.com",
  "timeout": 300
}
```

**Errores posibles:**
- `400`: Falta header 'target' o formato inválido
- `500`: Error al iniciar el escaneo

---

### Obtener Todos los Escaneos Nikto

**Endpoint:** `GET /api/scans/nikto/results`

**Descripción:** Obtiene la lista completa de escaneos Nikto realizados.

**Ejemplo de solicitud:**
```bash
curl -X GET http://localhost:5000/api/scans/nikto/results
```

**Respuesta exitosa (200):**
```json
{
  "message": "Escaneos obtenidos correctamente",
  "count": 1,
  "results": [
    {
      "id": 1,
      "target": "https://example.com",
      "startedAt": "2025-11-16T15:00:00",
      "incidents": [
        {
          "osvdbId": "12345",
          "method": "GET",
          "url": "/admin",
          "description": "Admin panel found without authentication",
          "discoveredAt": "2025-11-16T15:05:00"
        }
      ],
      "totalIncidents": 1
    }
  ]
}
```

---

### Obtener Escaneo Nikto por ID

**Endpoint:** `GET /api/scans/nikto/results/<scan_id>`

**Descripción:** Obtiene los detalles de un escaneo Nikto específico.

**Parámetros de ruta:**
- `scan_id` (integer): ID del escaneo

**Ejemplo de solicitud:**
```bash
curl -X GET http://localhost:5000/api/scans/nikto/results/1
```

**Respuesta exitosa (200):**
```json
{
  "message": "Escaneo obtenido correctamente",
  "result": {
    "id": 1,
    "target": "https://example.com",
    "startedAt": "2025-11-16T15:00:00",
    "incidents": [
      {
        "osvdbId": "12345",
        "method": "GET",
        "url": "/admin",
        "description": "Admin panel found without authentication",
        "discoveredAt": "2025-11-16T15:05:00"
      }
    ],
    "totalIncidents": 1
  }
}
```

**Errores posibles:**
- `404`: Escaneo no encontrado
- `500`: Error interno del servidor

---

### Generar PDF de Escaneo Nikto

**Endpoint:** `GET /api/scans/nikto/generate-pdf`

**Descripción:** Genera y descarga un informe PDF del escaneo Nikto.

**Query Parameters:**
- `id` (integer, requerido): ID del escaneo

**Ejemplo de solicitud:**
```bash
curl -X GET "http://localhost:5000/api/scans/nikto/generate-pdf?id=1" \
  --output nikto_scan_1.pdf
```

**Respuesta exitosa (200):**
- Archivo PDF descargable

---

### Generar PDF de Escaneo Nikto (Base64)

**Endpoint:** `GET /api/scans/nikto/generate-pdf-base64`

**Descripción:** Genera un PDF del escaneo Nikto y lo devuelve en formato base64.

**Query Parameters:**
- `id` (integer, requerido): ID del escaneo

**Ejemplo de solicitud:**
```bash
curl -X GET "http://localhost:5000/api/scans/nikto/generate-pdf-base64?id=1"
```

**Respuesta exitosa (200):**
```json
{
  "message": "PDF generado exitosamente",
  "scanId": "1",
  "filename": "nikto_scan_1.pdf",
  "pdfBase64": "JVBERi0xLjQKJeLjz9MKM...",
  "contentType": "application/pdf"
}
```

---

## 🔄 Endpoints Unificados (Recomendados)

Los siguientes endpoints detectan automáticamente el tipo de escaneo (Nmap o Nikto) basándose en el ID proporcionado.

### Obtener Todos los Escaneos

**Endpoint:** `GET /api/scans/results`

**Descripción:** Obtiene todos los escaneos (Nmap y Nikto) con opción de filtrado.

**Query Parameters opcionales:**
- `type` (string): Tipo de escaneo - valores: `nmap`, `nikto`, `all` (default: `all`)

**Ejemplos de solicitud:**
```bash
# Obtener todos los escaneos
curl -X GET http://localhost:5000/api/scans/results

# Obtener solo escaneos Nmap
curl -X GET "http://localhost:5000/api/scans/results?type=nmap"

# Obtener solo escaneos Nikto
curl -X GET "http://localhost:5000/api/scans/results?type=nikto"
```

**Respuesta exitosa (200):**
```json
{
  "message": "Escaneos obtenidos correctamente",
  "filter": "all",
  "count": 3,
  "results": [
    {
      "id": 1,
      "scanType": "nmap",
      "target": "192.168.1.1",
      "startedAt": "2025-11-16T14:30:00",
      "totalOpenPorts": 2
    },
    {
      "id": 2,
      "scanType": "nikto",
      "target": "https://example.com",
      "startedAt": "2025-11-16T15:00:00",
      "totalIncidents": 5
    }
  ]
}
```

---

### Obtener Escaneo por ID (Unificado)

**Endpoint:** `GET /api/scans/results/<scan_id>`

**Descripción:** Obtiene un escaneo específico detectando automáticamente si es Nmap o Nikto.

**Parámetros de ruta:**
- `scan_id` (integer): ID del escaneo

**Ejemplo de solicitud:**
```bash
curl -X GET http://localhost:5000/api/scans/results/1
```

**Respuesta exitosa (200):**
```json
{
  "message": "Escaneo obtenido correctamente",
  "result": {
    "id": 1,
    "scanType": "nmap",
    "target": "192.168.1.1",
    "startedAt": "2025-11-16T14:30:00",
    "openPorts": [
      {
        "port": "80/tcp",
        "reason": "syn-ack"
      }
    ],
    "totalOpenPorts": 2
  }
}
```

**Errores posibles:**
- `404`: Escaneo no encontrado
- `500`: Error interno del servidor

---

### Generar PDF (Unificado)

**Endpoint:** `GET /api/scans/generate-pdf`

**Descripción:** Genera un PDF detectando automáticamente el tipo de escaneo (Nmap o Nikto).

**Query Parameters:**
- `id` (integer, requerido): ID del escaneo

**Ejemplo de solicitud:**
```bash
curl -X GET "http://localhost:5000/api/scans/generate-pdf?id=1" \
  --output scan_report.pdf
```

**Respuesta exitosa (200):**
- Archivo PDF descargable

**Errores posibles:**
- `400`: Falta el parámetro 'id' o formato inválido
- `404`: Escaneo no encontrado
- `500`: Error al generar el PDF

---

### Generar PDF Base64 (Unificado)

**Endpoint:** `GET /api/scans/generate-pdf-base64`

**Descripción:** Genera un PDF en base64 detectando automáticamente el tipo de escaneo.

**Query Parameters:**
- `id` (integer, requerido): ID del escaneo

**Ejemplo de solicitud:**
```bash
curl -X GET "http://localhost:5000/api/scans/generate-pdf-base64?id=1"
```

**Respuesta exitosa (200):**
```json
{
  "message": "PDF generado exitosamente",
  "scanId": "1",
  "scanType": "nmap",
  "filename": "nmap_scan_1.pdf",
  "pdfBase64": "JVBERi0xLjQKJeLjz9MKM...",
  "contentType": "application/pdf"
}
```

**Errores posibles:**
- `400`: Falta el parámetro 'id' o formato inválido
- `404`: Escaneo no encontrado
- `500`: Error al generar el PDF

---

## 🔒 Códigos de Estado HTTP

| Código | Descripción |
|--------|-------------|
| 200 | OK - Solicitud exitosa |
| 201 | Created - Recurso creado exitosamente |
| 400 | Bad Request - Parámetros inválidos o faltantes |
| 404 | Not Found - Recurso no encontrado |
| 405 | Method Not Allowed - Método HTTP no permitido |
| 500 | Internal Server Error - Error interno del servidor |

---

## 📝 Notas Importantes

1. **Autenticación**: Actualmente la API no requiere autenticación, pero se recomienda implementarla en producción.

2. **Formatos de fecha**: Todas las fechas se devuelven en formato ISO 8601 (ejemplo: `2025-11-16T14:30:00`).

3. **Límites**: No hay límites de rate limiting configurados actualmente.

4. **Timeout**: Los escaneos Nikto tienen un timeout configurable (default: 180 segundos).

5. **PDFs con consentimiento**: Los PDFs generados incluyen una sección de conformidad y consentimiento del usuario antes del footer, indicando que el usuario ha dado su consentimiento para escanear el sitio web y asume las consecuencias.

6. **Endpoints unificados**: Se recomienda usar los endpoints unificados (`/api/scans/results` y `/api/scans/generate-pdf`) en lugar de los específicos por tipo, ya que ofrecen mayor flexibilidad y simplifican la integración.

---

## 🚀 Ejemplos de Uso Completo

### Flujo de trabajo típico para Nmap

```bash
# 1. Iniciar un escaneo Nmap
curl -X POST http://localhost:5000/api/scans/nmap/start \
  -H "host: 192.168.1.1" \
  -H "ports: 80,443,8080"

# Respuesta: {"scanId": 1, ...}

# 2. Obtener los resultados del escaneo
curl -X GET http://localhost:5000/api/scans/results/1

# 3. Generar el PDF del informe
curl -X GET "http://localhost:5000/api/scans/generate-pdf?id=1" \
  --output informe_escaneo.pdf
```

### Flujo de trabajo típico para Nikto

```bash
# 1. Iniciar un escaneo Nikto
curl -X POST "http://localhost:5000/api/scans/nikto/start?timeout=300" \
  -H "target: https://example.com"

# Respuesta: {"scanId": 2, ...}

# 2. Obtener los resultados del escaneo
curl -X GET http://localhost:5000/api/scans/results/2

# 3. Generar el PDF del informe
curl -X GET "http://localhost:5000/api/scans/generate-pdf?id=2" \
  --output informe_nikto.pdf
```

### Obtener todos los escaneos y filtrar

```bash
# Ver todos los escaneos
curl -X GET http://localhost:5000/api/scans/results

# Ver solo escaneos Nmap
curl -X GET "http://localhost:5000/api/scans/results?type=nmap"

# Ver solo escaneos Nikto
curl -X GET "http://localhost:5000/api/scans/results?type=nikto"
```

---

## 📧 Soporte

Para reportar problemas o sugerencias, contacta al equipo de desarrollo.

---

**Versión de la documentación:** 1.0  
**Última actualización:** 16 de noviembre de 2025
