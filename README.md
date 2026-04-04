# SeQ — Security Operations Platform

**SeQ** es una plataforma de operaciones de seguridad compuesta por tres módulos principales:

- **Sentinel** — API REST de escaneo de vulnerabilidades (operativo).
- **Acheron** — Sistema de gestión de secretos cifrados mediante Vaults (operativo, en expansión).
- **Aegis** — Módulo de concienciación en ciberseguridad y vigilancia de vulnerabilidades, basado en IA local (en desarrollo avanzado).

---

## Índice

- [Requisitos previos](#requisitos-previos)
- [Instalación](#instalación)
- [Módulo Sentinel — Escaneo de Vulnerabilidades](#módulo-sentinel--escaneo-de-vulnerabilidades)
  - [Autenticación OAuth 2.0](#autenticación-oauth-20)
  - [Gestión de usuarios](#gestión-de-usuarios)
  - [Escaneo con Nmap](#escaneo-con-nmap)
  - [Escaneo con Nikto](#escaneo-con-nikto)
  - [Escaneo con OpenVAS](#escaneo-con-openvas)
  - [Consulta de resultados](#consulta-de-resultados)
  - [Generación de informes PDF](#generación-de-informes-pdf)
- [Módulo Aegis — Concienciación y alertas](#módulo-aegis--concienciación-y-alertas)
- [Módulo Acheron — Vault](#módulo-acheron--vault)
- [Infraestructura Docker](#infraestructura-docker)
- [Estructura del proyecto](#estructura-del-proyecto)
- [Stack tecnológico](#stack-tecnológico)

---

## Requisitos previos

Antes de ejecutar el proyecto, asegúrate de tener instalado:

- Python 3.10+
- PostgreSQL
- Nmap (`sudo apt install nmap`)
- Nikto (`sudo apt install nikto`)
- OpenVAS / Greenbone Vulnerability Manager (GVM)
- Docker y Docker Compose (para levantar los servicios de infraestructura)
- (Opcional, para Aegis) **Ollama** con al menos un modelo de lenguaje compatible con tool calling (por ejemplo, `llama3.1`)

Instala las dependencias de Python:

```bash
pip install -r REQUIREMENTS.txt
```

---

## Instalación

```bash
git clone https://github.com/gamustea/SeQ.git
cd SeQ/API
python init_db.py   # Inicializa el esquema de la base de datos
python run.py
```

La API arranca en `http://0.0.0.0:5000` por defecto.

---

## Módulo Sentinel — Escaneo de Vulnerabilidades

Sentinel es la API REST central del proyecto. Permite lanzar y gestionar escaneos de seguridad sobre hosts y redes, consultar sus resultados y exportarlos como informes PDF. Todos los endpoints (salvo registro y autenticación) requieren un token OAuth 2.0 válido.

### Autenticación OAuth 2.0

El sistema implementa el flujo OAuth 2.0 con `grant_type: password` y soporte de refresh tokens (JWT firmados con PyJWT).

#### Obtener token de acceso

```http
POST /oauth/token
Content-Type: application/json

{
  "grantType": "password",
  "username": "usuario",
  "password": "contraseña"
}
```

**Respuesta:**
```json
{
  "access_token": "<jwt>",
  "token_type": "Bearer",
  "expires_in": 1800,
  "refresh_token": "<token>"
}
```

#### Renovar token

```http
POST /oauth/token
Content-Type: application/json

{
  "grantType": "refresh_token",
  "refresh_token": "<token>"
}
```

#### Revocar tokens

| Endpoint | Descripción |
|---|---|
| `POST /oauth/revoke` | Revoca el token actual |
| `POST /oauth/revoke-all` | Revoca todos los tokens del usuario (cierre de sesión global) |

> ⚠️ Todos los endpoints protegidos requieren el header: `Authorization: Bearer <access_token>`

---

### Gestión de usuarios

| Método | Endpoint | Descripción |
|---|---|---|
| `POST` | `/users/sign-up` | Registro de nuevo usuario (username, password, email, alias) |
| `POST` | `/users/sign-up-person` | Registro de persona sin credenciales (firstName, lastName, alias) |
| `PUT` | `/users/change-password` | Cambio de contraseña (invalida todos los tokens activos) |

---

### Escaneo con Nmap

Nmap realiza descubrimiento de puertos abiertos en hosts o rangos de red. Soporta múltiples hosts simultáneos (CIDR o lista).

#### Iniciar escaneo

```http
POST /sentinel/nmap/start
Authorization: Bearer <token>
Content-Type: application/json

{
  "target": "192.168.1.0/24",
  "ports": "80,443,22,8080"
}
```

**Respuesta:**
```json
{
  "message": "Escaneo(s) Nmap iniciado(s) correctamente",
  "scanIds": [1, 2, 3],
  "target": { "hosts": ["192.168.1.1", "..."], "ports": "80,443,22,8080" },
  "totalScans": 3
}
```

**Resultado de un escaneo Nmap:**
```json
{
  "id": 1,
  "scanType": "nmap",
  "target": "192.168.1.1",
  "startedAt": "2025-11-01T10:00:00",
  "openPorts": [
    { "port": "80/tcp", "reason": "syn-ack", "product": "nginx", "version": "1.18" }
  ],
  "totalOpenPorts": 1
}
```

---

### Escaneo con Nikto

Nikto realiza análisis de vulnerabilidades web sobre servidores HTTP/HTTPS, detectando configuraciones inseguras, cabeceras faltantes y rutas sensibles expuestas.

#### Iniciar escaneo

```http
POST /sentinel/nikto/start
Authorization: Bearer <token>
Content-Type: application/json

{
  "target": "http://example.com",
  "timeout": 180
}
```

**Resultado de un escaneo Nikto:**
```json
{
  "id": 5,
  "scanType": "nikto",
  "target": "http://example.com",
  "incidents": [
    {
      "osvdbId": "OSVDB-3268",
      "method": "GET",
      "url": "/images/",
      "description": "Directory indexing found",
      "severity": "MEDIUM",
      "discoveredAt": "2025-11-01T10:05:00"
    }
  ],
  "totalIncidents": 1
}
```

---

### Escaneo con OpenVAS

OpenVAS realiza análisis completos de vulnerabilidades con base en la base de datos NVT (Network Vulnerability Tests) de Greenbone, asignando puntuaciones CVSS a cada hallazgo.

#### Iniciar escaneo

```http
POST /sentinel/openvas/start
Authorization: Bearer <token>
Content-Type: application/json

{
  "target": "192.168.1.100",
  "scanConfig": "full_fast"
}
```

> Configuraciones disponibles: `full_fast`, `full_deep`, `full_ultimate`.  
> OpenVAS solo acepta **un host** por escaneo.

**Resultado de un escaneo OpenVAS:**
```json
{
  "id": 10,
  "scanType": "openvas",
  "target": "192.168.1.100",
  "totalVulnerabilities": 12,
  "severityBreakdown": {
    "critical": 1,
    "high": 3,
    "medium": 5,
    "low": 2,
    "info": 1
  },
  "vulnerabilities": [
    {
      "nvtOid": "1.3.6.1.4.1.25623.1.0.10330",
      "name": "OpenSSL < 1.1.1",
      "severityScore": 9.8,
      "severityClass": "Critical",
      "cveIds": ["CVE-2020-1967"],
      "solution": "Actualizar OpenSSL a la última versión estable."
    }
  ]
}
```

---

### Consulta de resultados

| Método | Endpoint | Descripción |
|---|---|---|
| `GET` | `/sentinel/results?type=all` | Lista todos los escaneos del usuario (filtrable por `nmap`, `nikto`, `openvas`) |
| `GET` | `/sentinel/results/<id>` | Detalle completo de un escaneo por ID |
| `GET` | `/sentinel/scan-status?id=<id>` | Estado actual del escaneo (`pending`, `running`, `done`, `cancelled`) |
| `GET` | `/sentinel/is-finished?id=<id>` | Comprobación rápida de si el escaneo ha finalizado |
| `POST` | `/sentinel/scans/<id>/cancel` | Cancela un escaneo en estado `pending` o `running` |

---

### Generación de informes PDF

Una vez finalizado un escaneo, se puede exportar como informe PDF estructurado.

| Método | Endpoint | Descripción |
|---|---|---|
| `GET` | `/sentinel/generate-pdf?id=<id>` | Descarga directa del PDF |
| `GET` | `/sentinel/generate-pdf-base64?id=<id>` | Devuelve el PDF codificado en Base64 (útil para apps móviles) |

Los informes adaptan su formato al tipo de escaneo (Nmap, Nikto u OpenVAS) mediante el patrón Strategy.

---

## Módulo Aegis — Concienciación y alertas

> 🧠 **Aegis** amplía SeQ más allá del escaneo técnico: genera contenido de concienciación en ciberseguridad para empleados y acompaña cada píldora con un resumen de vulnerabilidades recientes relevantes.

### ¿Qué hace Aegis?

- **Píldoras de concienciación** en formato Markdown (`.md`) generadas por un modelo de IA local vía Ollama.
- Contenido adaptado al contexto del cliente (sector, tecnologías usadas, tono, audiencia, etc.) mediante parámetros `tweaks`.
- **Alertas de vulnerabilidades recientes** combinando:
  - Feed de avisos de INCIBE-CERT.
  - CVEs recientes obtenidos de la API pública de CIRCL / NVD.
- Todo el contenido se guarda como documentos propios del usuario (`AegisDocument`) y se accede vía API.

### Endpoints principales

Todos los endpoints Aegis requieren autenticación OAuth (`Authorization: Bearer <access_token>`).

#### Iniciar generación de una píldora

```http
POST /aegis/generate
Authorization: Bearer <token>
Content-Type: application/json

{
  "topicId": 1,
  "tweaks": {
    "company": "Empresa Demo S.A.",
    "sector": "financiero",
    "language": "es",
    "tone": "formal",
    "associatedBrands": ["Microsoft", "Cisco"],
    "audienceLevel": "mixed",
    "mentionContact": "ciberseguridad@empresa.com"
  }
}
```

**Respuesta (asíncrona):**
```json
{
  "message": "Generación Aegis iniciada",
  "documentId": 42,
  "status": "pending"
}
```

Aegis genera el contenido en segundo plano usando hilos, sin bloquear la API.

#### Consultar estado de una píldora

```http
GET /aegis/status?id=42
Authorization: Bearer <token>
```

**Respuesta:**
```json
{
  "id": 42,
  "title": "[título generado]",
  "status": "done",
  "generatedAt": "2026-03-08T16:30:00Z",
  "topicId": 1
}
```

> 🔐 Un usuario solo puede consultar el estado de sus propios documentos. Si intenta acceder a un `id` que no existe o que pertenece a otro usuario, la API responde con `404` genérico.

#### Descargar la píldora como Markdown

```http
GET /aegis/download_as_md?id=42
Authorization: Bearer <token>
```

Devuelve el fichero `.md` como descarga (`Content-Type: text/markdown`). El cuerpo incluye:

- La píldora principal redactada por el modelo de IA.
- Una sección adicional con **vulnerabilidades y avisos de seguridad** formateados en Markdown.

---

## Módulo Acheron — Vault

> 🔐 **Acheron** es el sistema de gestión de secretos cifrados de SeQ. La API REST del vault está **operativa**. Las interfaces móvil y web están en desarrollo.

Acheron permite a cada usuario gestionar un vault cifrado con credenciales (`Account`) y tarjetas de crédito (`CreditCard`), con soporte de **vault de recuperación** (`isRecovery`).

### Endpoints

Todos los endpoints requieren autenticación OAuth (`Authorization: Bearer <access_token>`).

#### Vault

| Método | Endpoint | Descripción |
|---|---|---|
| `GET` | `/acheron/vault` | Obtener el vault del usuario |
| `POST` | `/acheron/vault` | Crear o reemplazar el vault completo (upsert) |
| `PATCH` | `/acheron/storables` | Actualizar en bulk uno o varios Storables |

> El parámetro de query `?isRecovery=true` permite operar sobre el vault de recuperación en lugar del principal.

#### Storables (objetos del vault)

| Método | Endpoint | Descripción |
|---|---|---|
| `POST` | `/vaults/storables` | Añadir un `Account` o `CreditCard` al vault |
| `DELETE` | `/vaults/storables` | Eliminar un Storable por `internalId` |

#### Ejemplo: añadir una cuenta

```http
POST /vaults/storables
Authorization: Bearer <token>
Content-Type: application/json

{
  "kind": "account",
  "title": "GitHub",
  "username": "usuario",
  "domain": "github.com",
  "password": "secreto",
  "isRecovery": false
}
```

**Respuesta:**
```json
{
  "message": "Storable created",
  "storableId": 7,
  "internalId": "ACC-001",
  "vaultId": 1,
  "isRecovery": false,
  "kind": "account"
}
```

#### Ejemplo: añadir una tarjeta de crédito

```http
POST /vaults/storables
Authorization: Bearer <token>
Content-Type: application/json

{
  "kind": "creditcard",
  "title": "Visa Personal",
  "cardHolderName": "Gabriel Musteata",
  "cardNumber": "4111111111111111",
  "expirationDate": "12/27",
  "postalCode": "26360",
  "cvv": "123",
  "isRecovery": false
}
```

### Componentes

| Componente | Tecnología | Estado |
|---|---|---|
| `AcheronAPI` | Python / Flask (endpoints y lógica de vault) | ✅ Operativo |
| `AcheronMobile` | Android / Kotlin + Jetpack Compose | 🔨 En desarrollo |
| `AcheronWeb` | Web (interfaz de escritorio) | 🔨 En desarrollo |
| `AcheronCore` | Java (lógica de cifrado y modelo de dominio) | 🔨 En desarrollo |

---

## Infraestructura Docker

El directorio `API/docker/` contiene los archivos Docker Compose para levantar los servicios de apoyo necesarios:

```bash
# Levantar OpenVAS / GVM
cd API/docker/openvas
docker-compose up -d

# Levantar PostgreSQL
cd API/docker/postgres
docker-compose up -d

# Levantar Ollama (IA local para Aegis)
cd API/docker/ollama
docker-compose up -d
```

---

## Estructura del proyecto

```
SeQ/
├── API/                        # API REST Flask (Sentinel + Aegis + Acheron)
│   ├── run.py                  # Punto de entrada de la aplicación
│   ├── init_db.py              # Inicialización del esquema de base de datos
│   ├── docker/
│   │   ├── openvas/            # Docker Compose para OpenVAS/GVM
│   │   ├── postgres/           # Docker Compose para PostgreSQL
│   │   └── ollama/             # Docker Compose para Ollama (IA local)
│   └── src/
│       ├── core/               # Modelos ORM y excepciones
│       │   └── model/          # acheron.py, sentinel.py, aegis_model.py, general.py
│       ├── endpoints/          # Blueprints Flask por módulo
│       │   ├── sentinel.py     # Endpoints de escaneo
│       │   ├── aegis_endpoints.py
│       │   ├── acheron.py      # Endpoints del vault (operativo)
│       │   ├── oauth.py
│       │   ├── users.py
│       │   └── health.py       # Health check
│       ├── logic/              # Managers y lógica de negocio
│       │   ├── managers/       # sentinel.py, acheron.py, aegis_managers.py, general.py
│       │   ├── tasks.py        # Tareas asíncronas (escaneos, generación Aegis)
│       │   ├── processors.py   # Procesadores de resultados (patrón Strategy)
│       │   └── secrets.py      # Gestión de secretos de aplicación
│       └── misc/               # Logging y utilidades
├── Interface/
│   ├── AcheronMobile/          # App Android (Kotlin) — Vault
│   │   └── AcheronCore/        # Lógica de dominio del vault (Java)
│   ├── AcheronWeb/             # Interfaz web del vault
│   └── index.html              # Portal de entrada
├── seq-landing/                # Landing page del proyecto
├── shared/
│   └── resources/              # Recursos compartidos
└── REQUIREMENTS.txt
```

---

## Stack tecnológico

| Capa | Tecnología |
|---|---|
| API Backend | Python 3, Flask 3.0, SQLAlchemy 2.0 |
| Base de datos | PostgreSQL (psycopg2) |
| Autenticación | OAuth 2.0 + JWT (PyJWT) |
| Escaneo de puertos | Nmap + python-nmap |
| Escaneo web | Nikto |
| Análisis de vulnerabilidades | OpenVAS / GVM |
| Generación de PDFs | ReportLab + Pillow |
| Concienciación y generación de contenido | Ollama (IA local) + prompts especializados |
| Obtención de vulnerabilidades recientes | Feeds de INCIBE-CERT + API pública CIRCL/NVD |
| App móvil | Android / Kotlin |
| Lógica de vault | Java + Lombok |
| Rate limiting | Flask-Limiter |
| Infraestructura | Docker + Docker Compose |
