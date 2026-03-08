# SeQ — Security Operations Platform

**SeQ** es una plataforma de operaciones de seguridad compuesta por tres módulos principales:

- **Sentinel** — API REST de escaneo de vulnerabilidades (operativo).
- **Acheron** — Sistema de gestión de secretos cifrados mediante Vaults (en desarrollo).
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
- [Módulo Acheron — Vault (En desarrollo)](#módulo-acheron--vault-en-desarrollo)
- [Estructura del proyecto](#estructura-del-proyecto)
- [Stack tecnológico](#stack-tecnológico)

---

## Requisitos previos

Antes de ejecutar el proyecto, asegúrate de tener instalado:

- Python 3.10+
- MySQL
- Nmap (`sudo apt install nmap`)
- Nikto (`sudo apt install nikto`)
- OpenVAS / Greenbone Vulnerability Manager (GVM)
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

## Módulo Acheron — Vault (En desarrollo)

> 🚧 **Este módulo está actualmente en desarrollo activo.**

**Acheron** es el sistema de gestión de secretos cifrados de SeQ. Su objetivo es proporcionar a los usuarios un almacén seguro (Vault) donde guardar credenciales, tarjetas de crédito y otros datos sensibles, con cifrado en cliente antes de almacenarse.

### Componentes planificados

| Componente | Tecnología | Estado |
|---|---|---|
| `AcheronCore` | Java (lógica de cifrado y modelo de dominio) | 🔨 En desarrollo |
| `AcheronMobile` | Android / Kotlin + Jetpack Compose | 🔨 En desarrollo |
| `AcheronWeb` | Web (interfaz de escritorio) | 🔨 En desarrollo |

### Funcionalidades previstas

- **Vault cifrado**: Almacén de objetos sensibles (`Account`, `CreditCard`, etc.) cifrados mediante estrategias de cifrado simétricas (`VaultEncryptingStrategy`).
- **Control de acceso**: Compartición de objetos del vault con otros usuarios del sistema mediante listas de control de acceso (ACL).
- **Identificación única**: Cada objeto del vault recibe un ID compuesto por un código de tipo (e.g., `ACC`, `CDC`) y un número secuencial.
- **Integración con la API**: Los vaults se conectarán con el backend de Sentinel para autenticación unificada vía OAuth 2.0.

---

## Estructura del proyecto

```
SeQ/
├── API/                        # API REST Flask (Sentinel + Aegis)
│   ├── run.py                  # Punto de entrada y definición de endpoints
│   └── src/
│       ├── core/               # Modelos ORM y excepciones
│       ├── logic/              # Managers (Nmap, Nikto, OpenVAS, Aegis), documentos y procesadores
│       ├── config/             # Configuración de la aplicación
│       └── misc/               # Logging y validación
├── Interface/
│   ├── AcheronMobile/          # App Android (Kotlin) — Vault
│   │   └── AcheronCore/        # Lógica de dominio del vault (Java)
│   ├── AcheronWeb/             # Interfaz web del vault
│   └── index.html              # Portal de entrada
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
