# SeQ — Security Operations Platform

**SeQ** es una plataforma de operaciones de seguridad compuesta por cuatro módulos principales, con interfaces web y móvil:

- **Sentinel** — API REST de escaneo de vulnerabilidades con análisis de IA (operativo).
- **Iris** — Análisis de cabeceras de correo para detección de phishing mediante reglas (operativo).
- **Acheron** — Sistema de gestión de secretos cifrados mediante Vaults (operativo, en expansión).
- **Aegis** — Módulo de concienciación en ciberseguridad y alertas de vulnerabilidades, potenciado por IA local (operativo).
- **SeQ Web** — Interfaz web SPA (Vue 3 + Vite + Pinia) para interactuar con todos los módulos.
- **AcheronMobile** — App Android/Kotlin con módulo de cifrado AcheronCore (Java).
- **SeQ Hub** — Dashboard central con acceso rápido a todos los módulos.

---

## Índice

- [SeQ — Security Operations Platform](#seq--security-operations-platform)
  - [Índice](#índice)
  - [Requisitos previos](#requisitos-previos)
  - [Instalación](#instalación)
  - [Módulo Sentinel — Escaneo de Vulnerabilidades](#módulo-sentinel--escaneo-de-vulnerabilidades)
    - [Autenticación OAuth 2.0](#autenticación-oauth-20)
      - [Obtener token de acceso](#obtener-token-de-acceso)
      - [Renovar token](#renovar-token)
      - [Revocar tokens](#revocar-tokens)
    - [Gestión de usuarios](#gestión-de-usuarios)
    - [Escaneo con Nmap](#escaneo-con-nmap)
      - [Iniciar escaneo](#iniciar-escaneo)
    - [Escaneo con Nikto](#escaneo-con-nikto)
      - [Iniciar escaneo](#iniciar-escaneo-1)
    - [Escaneo con OpenVAS](#escaneo-con-openvas)
      - [Iniciar escaneo](#iniciar-escaneo-2)
    - [Generación de informes PDF con IA](#generación-de-informes-pdf-con-ia)
      - [Generar PDF con análisis de IA](#generar-pdf-con-análisis-de-ia)
      - [Prompts especializados](#prompts-especializados)
    - [Consulta de resultados](#consulta-de-resultados)
    - [Generación de informes PDF](#generación-de-informes-pdf)
  - [Módulo Aegis — Concienciación y alertas](#módulo-aegis--concienciación-y-alertas)
    - [¿Qué hace Aegis?](#qué-hace-aegis)
    - [Endpoints principales](#endpoints-principales)
      - [Iniciar generación de una píldora](#iniciar-generación-de-una-píldora)
      - [Consultar estado de una píldora](#consultar-estado-de-una-píldora)
      - [Descargar la píldora como Markdown](#descargar-la-píldora-como-markdown)
      - [Otros endpoints Aegis](#otros-endpoints-aegis)
      - [Arquitectura de IA en Aegis](#arquitectura-de-ia-en-aegis)
  - [Módulo Iris — Análisis Anti-Phishing](#módulo-iris--análisis-anti-phishing)
    - [Endpoints](#endpoints)
    - [Iniciar un análisis](#iniciar-un-análisis)
    - [Consultar estado](#consultar-estado)
    - [Informe completo](#informe-completo)
    - [Reglas de análisis](#reglas-de-análisis)
    - [Validación de entrada](#validación-de-entrada)
    - [Frontend web](#frontend-web)
  - [Módulo Acheron — Vault](#módulo-acheron--vault)
    - [Endpoints](#endpoints-1)
      - [Vault](#vault)
      - [Storables (objetos del vault)](#storables-objetos-del-vault)
      - [Ejemplo: añadir una cuenta](#ejemplo-añadir-una-cuenta)
      - [Ejemplo: añadir una tarjeta de crédito](#ejemplo-añadir-una-tarjeta-de-crédito)
    - [Componentes](#componentes)
  - [Web Frontend — SeQ Hub](#web-frontend--seq-hub)
    - [Dashboard Hub (`/hub`)](#dashboard-hub-hub)
  - [Infraestructura Docker](#infraestructura-docker)
    - [Servicios principales](#servicios-principales)
    - [Levantamiento de servicios](#levantamiento-de-servicios)
    - [Configuración de Ollama](#configuración-de-ollama)
  - [Estructura del proyecto](#estructura-del-proyecto)
  - [Stack tecnológico](#stack-tecnológico)
  - [Quick Start](#quick-start)
  - [Notas Importantes](#notas-importantes)

---

## Requisitos previos

> **Plataforma:** la API de SeQ asume un entorno **Linux**. Las herramientas de escaneo
> (Nmap, Nikto y OpenVAS/Greenbone) son nativas de Linux —OpenVAS ni siquiera corre nativo en
> Windows— por lo que la API debe ejecutarse en **Linux nativo, dentro de WSL, o vía Docker**.
> En Windows, ejecuta el entrypoint dentro de WSL (`wsl` → `cd .../API && python run.py`) o usa
> `docker compose`.

Antes de ejecutar el proyecto, asegúrate de tener instalado:

- Python 3.10+
- PostgreSQL
- Nmap (`sudo apt install nmap`)
- Nikto (`sudo apt install nikto`)
- OpenVAS / Greenbone Vulnerability Manager (GVM)
- Docker y Docker Compose (para levantar los servicios de infraestructura)
- (Opcional, para Aegis) **Ollama** con al menos un modelo de lenguaje compatible con tool calling (por ejemplo, `llama3.2`)

Instala las dependencias de Python:

```bash
pip install -r requirements.txt
```

---

## Instalación

```bash
git clone https://github.com/gamustea/SeQ.git
cd SeQ/API
# Configurar CREATE_DATABASE=True en API/.env para inicializar la BD
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

### Generación de informes PDF con IA

Sentinel integra análisis de inteligencia artificial mediante **Ollama** para todos los tipos de escaneo (Nmap, Nikto, OpenVAS). Los informes PDF pueden incluir un análisis ejecutivo generado por IA que proporciona:

- **Resumen ejecutivo** contextualizado.
- **Nivel de riesgo calibrado** (CRÍTICO/ALTO/MEDIO/BAJO/INFORMATIVO).
- **Análisis técnico** detallado por controles de seguridad.
- **Recomendaciones priorizadas** con acciones específicas.
- **Conclusiones** con siguientes pasos recomendados.

#### Generar PDF con análisis de IA

```http
GET /sentinel/generate-pdf?id=<id>&aiReport=true
Authorization: Bearer <token>
```

El parámetro `aiReport=true` activa la generación del análisis IA. El proceso:

1. **Preprocesamiento**: Los hallazgos se agrupan por controles de seguridad (no por cantidad de hallazgos individuales).
2. **Prompt ingeniería**: Se usa un system prompt especializado que aplica el principio "Controls, Not Counts":
   - 10 vulnerabilidades de XSS = UN control (output encoding) con deficiencias.
   - El riesgo lo determina el TIPO de control afectado, no el número de hallazgos.
3. **Generación**: Ollama genera el análisis en JSON estructurado.
4. **Renderizado**: El análisis se inserta en el PDF con el formato estandarizado.

#### Prompts especializados

Los prompts están centralizados en `SecOpsConfig.json` y se accede a través de `CR`:

| Escáner | Sistema de prompts |
|---|---|
| **Nmap** | Evalúa superficie de ataque, distingue puertos abiertos de vulnerabilidades confirmadas. |
| **Nikto** | Analiza controles de seguridad web (transport, session, client protection). |
| **OpenVAS** | Agrupa vulnerabilidades por controles (input validation, authentication, cryptography). |

Cada prompt enforcing:
- Nunca inventar CVEs o vulnerabilidades.
- Preferir subestimación a sobreestimación.
- Distinguir entre hardening ausente y protección crítica ausente.

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

> ⚡ **Estado: Operativo** — Aegis genera píldoras de concienciación mediante IA local (Ollama), combina alertas de vulnerabilidades y exporta contenido en múltiples formatos.

### ¿Qué hace Aegis?

- **Píldoras de concienciación** en formato Markdown (`.md`) generadas por un modelo de IA local vía Ollama.
- Contenido adaptado al contexto del cliente (sector, tecnologías usadas, tono, audiencia, etc.) mediante parámetros `tweaks`.
- **Alertas de vulnerabilidades recientes** combinando:
  - Feed de avisos de INCIBE-CERT.
  - CVEs recientes obtenidos de la API pública de CIRCL / NVD.
- Todo el contenido se guarda como documentos propios del usuario (`AegisDocument`) y se accede vía API.
- **Exportación múltiple**: Markdown, HTML, PDF, o email formateado.

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

Devuelve el ficheгro `.md` como descarga (`Content-Type: text/markdown`). El cuerpo incluye:

- La píldora principal redactada por el modelo de IA.
- Una sección adicional con **vulnerabilidades y avisos de seguridad** formateados en Markdown.

#### Otros endpoints Aegis

| Método | Endpoint | Descripción |
|---|---|---|
| `GET` | `/aegis/topics` | Lista todos los topics disponibles |
| `GET` | `/aegis/documents` | Lista documentos del usuario |
| `GET` | `/aegis/documents/<id>` | Detalle de un documento |
| `GET` | `/aegis/download_as_html?id=<id>` | Exporta como HTML formateado |
| `GET` | `/aegis/download_as_pdf?id=<id>` | Exporta como PDF |
| `DELETE` | `/aegis/documents/<id>` | Elimina un documento |

#### Arquitectura de IA en Aegis

Aegis usa prompts especializados centralizados en `SecOpsConfig.json` y se accede a través de `CR`. El sistema prompt incluye generación exclusiva en JSON válido, intro extensiva (mínimo 1500 caracteres), subtítulo creativo y original, y tips accionables con enlaces verificados.

---

## Módulo Iris — Análisis Anti-Phishing

> 🕵️ **Iris** analiza cabeceras de correo electrónico para detectar intentos de phishing mediante un sistema de reglas atómicas. Cada regla evalúa un aspecto concreto de las cabeceras y devuelve una puntuación; la suma determina un veredicto final (Legitimate / Suspicious / Phishing).

Las cabeceras se envían en texto plano a la API, que las procesa en segundo plano mediante **SeQueue** (cola de tareas asíncrona). El usuario puede consultar el estado del análisis y, una vez completado, obtener un informe detallado con la puntuación de cada regla y recomendaciones.

### Endpoints

| Método | Endpoint | Permiso | Descripción |
|---|---|---|---|
| `POST` | `/iris/analyze` | `IRIS_CREATE` | Enviar cabeceras para análisis (opcional: `title`) |
| `GET` | `/iris/status?id={{id}}` | `IRIS_READ` | Estado y progreso del análisis |
| `GET` | `/iris/results?page=&per_page=` | `IRIS_READ` | Lista paginada de análisis del usuario |
| `GET` | `/iris/results/{{id}}` | `IRIS_READ` | Informe completo con reglas, scores y veredicto |
| `POST` | `/iris/analyze/{{id}}/cancel` | `IRIS_UPDATE` | Cancelar un análisis en curso |
| `DELETE` | `/iris/results/{{id}}` | `IRIS_DELETE` | Eliminar un análisis |

### Iniciar un análisis

```http
POST /iris/analyze
Authorization: Bearer <token>
Content-Type: application/json

{
  "title": "Correo sospechoso de Amazon",
  "headers": "Received: from mail.evil.com (10.0.0.1)\nFrom: \"Amazon\" <no-reply@amaz0n-secure.com>\nReply-To: phisher@evil.com\nDKIM-Signature: v=1; a=rsa-sha256; d=amaz0n-secure.com;\nAuthentication-Results: spf=fail; dkim=fail; dmarc=fail"
}
```

**Respuesta (asíncrona):**
```json
{
  "message": "Analisis de cabeceras iniciado correctamente",
  "analysisId": 42,
  "status": "pending"
}
```

### Consultar estado

```http
GET /iris/status?id=42
Authorization: Bearer <token>
```

**Respuesta (en ejecución):**
```json
{
  "analysisId": 42,
  "status": "running",
  "progress": 60
}
```

### Informe completo

```http
GET /iris/results/42
Authorization: Bearer <token>
```

```json
{
  "analysisId": 42,
  "title": "Correo sospechoso de Amazon",
  "status": "finished",
  "totalScore": -35,
  "verdict": "Phishing",
  "rules": [
    { "ruleName": "SPF", "category": "authentication", "score": -20, "verdict": "fail", "recommendation": "..." },
    { "ruleName": "DKIM", "category": "authentication", "score": -15, "verdict": "fail", "recommendation": "..." },
    { "ruleName": "Reply-To check", "category": "header_analysis", "score": -10, "verdict": "fail", "recommendation": "..." }
  ],
  "recommendations": [
    "El servidor de envío no está autorizado por el registro SPF...",
    "La dirección Reply-To apunta a un dominio diferente al remitente..."
  ]
}
```

### Reglas de análisis

Iris ejecuta **8 reglas atómicas** registradas mediante decorador (`@iris_rules.register`), cada una en su propio archivo dentro de `rules/`:

| Regla | Categoría | Score máx | Score mín |
|---|---|---|---|
| SPF | authentication | +15 | -20 |
| DKIM | authentication | +15 | -15 |
| DMARC | authentication | +15 | -20 |
| Reply-To check | header_analysis | +3 | -10 |
| Return-Path mismatch | header_analysis | 0 | -8 |
| Message-ID check | header_analysis | 0 | -4 |
| Content-Type check | header_analysis | 0 | -2 |
| From header check | header_analysis | 0 | -10 |

Los umbrales de veredicto se configuran en `SecOpsConfig.json`:
```json
"iris": {
  "legitimate_threshold": 30,
  "suspicious_threshold": -10,
  "min_headers": 2
}
```

### Validación de entrada

Antes de crear un análisis, Iris verifica que el texto contenga al menos `min_headers` líneas con formato de cabecera (`Clave: Valor`). Si no supera esta validación, la API responde con un error 400.

### Frontend web

La interfaz de Iris (`/iris`) sigue un layout de **strip horizontal + contenido completo**, diferenciándose de Sentinel (scroll vertical) y Aegis (tres paneles). Incluye:

- **Strip de historial**: pestañas horizontales con scroll para cada análisis, con título (si se proporcionó), score y veredicto.
- **Hover card**: al pasar el ratón sobre un ítem del strip, aparece una card con el título completo, fecha, puntuación y veredicto.
- **Formulario de entrada**: textarea monoespaciada para pegar cabeceras + campo de título opcional.
- **Visor de informe**: tarjetas expandibles por regla, sección de recomendaciones y cabeceras originales colapsables.
- **Polling automático cada 2s** mientras el análisis está en ejecución.
- **Eliminación**: desde el strip (con confirmación inline) o desde el visor del informe.

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

## Web Frontend — SeQ Hub

La interfaz web SPA (Vue 3 + Vite + Pinia + Vue Router) cuenta con un **hub central** rediseñado como dashboard de operaciones de seguridad:

### Dashboard Hub (`/hub`)

- **Layout partido 2/3 + 1/3**: Columna izquierda con hero `[ SeQ ]`; columna derecha con fichas de módulos scrolleables.
- **Terminal de comandos**: Panel con efecto glass morphism (`backdrop-filter: blur(16px)`) y borde neón dorado. Reproduce escaneos reales (nikto, nmap, openvas) con typewriter y highlight sintáctico de JSON. Indicador LIVE pulsante en la barra de título.
- **Fondo animado**: Orbes de color con blur 150px, rejilla hexagonal SVG, partículas flotantes, scan-lines CRT y granulado SVG — todo con animación CSS.
- **Módulos glass**: Fichas con `backdrop-filter: blur(12px)`, borde izquierdo neón de 3px por módulo (verde Sentinel, azul Aegis, naranja Iris, púrpura Acheron). Hover con elevación y glow expansivo.
- **Quick-stats**: Acceso directo al repositorio GitHub del proyecto y versión del sistema.
- **Perfil**: Avatar circular fijo en esquina superior derecha, dropdown glass con perfil, rutas de administración y cierre de sesión.
- **Tipografía**: Syne (display), Sora (body), JetBrains Mono (terminal).
- **Responsive**: Colapsa a columna única en ≤1024px, scroll de página normal en móvil.

---

## Infraestructura Docker

El archivo `docker-compose.yml` en la raíz del repositorio orquesta todos los servicios mediante dos perfiles:

- **`dev`**: Infraestructura únicamente (PostgreSQL, Ollama, OpenVAS). Para desarrollo local con la API ejecutándose en Python.
- **`container`**: Infraestructura + contenedores de la API y frontend web. Para despliegue completo.

### Servicios principales

| Servicio | Puerto | Descripción |
|---|---|---|
| **PostgreSQL** | 15432 | Base de datos principal |
| **OpenVAS/GVM** | 9390, 9392 | Escáner de vulnerabilidades (API Greenbone y UI web) |
| **Ollama** | 11434 | IA local para Sentinel y Aegis |

### Levantamiento de servicios

```bash
# Solo infraestructura (desarrollo local)
docker compose --profile dev up -d

# Despliegue completo (API + frontend web + infraestructura)
docker compose --profile container up -d
```

### Configuración de Ollama

Para IA en Sentinel y Aegis, se requiere Ollama con un modelo compatible (por defecto `llama3.2`):

```bash
# Desde el contenedor Ollama
docker exec -it OllamaSeQ ollama pull llama3.2

# O directamente en el host si Ollama está instalado
ollama pull llama3.2
```

Las variables de entorno para la API se configuran en `API/.env`:

```
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=llama3.2
```

> **Nota**: OpenVAS puede tardar ~15 minutos en iniciar la primera vez (descarga de plugins NVT). Verifica el estado en `http://localhost:9392`.

---

## Estructura del proyecto

```
SeQ/
├── API/                          # API REST Flask
│   ├── run.py                    # Punto de entrada
│   ├── Dockerfile                # Imagen Docker de la API
│   ├── requirements.txt          # Dependencias Python
│   ├── SecOpsConfig.json        # Configuración y prompts de IA
│   └── src/
│       └── modules/
│           ├── users/            # Usuarios, OAuth 2.0 + JWT
│           ├── shared/           # Componentes compartidos
│           ├── sentinel/         # Escaneo: Nmap, Nikto, OpenVAS
│           ├── iris/             # Análisis anti-phishing de cabeceras
│           ├── aegis/            # Píldoras de concienciación
│           ├── acheron/          # Vault de secretos cifrados
│           ├── pages/            # UI estática
│           ├── system/           # Configuración y logging
│           └── infrastructure/   # Utilidades internas
├── web/                          # Frontend web
│   ├── Dockerfile                # Imagen Docker del frontend
│   ├── nginx.conf                # Configuración Nginx (producción)
│   └── app/                      # Vue 3 SPA (Vite + Pinia + Vue Router)
├── mobile/                       # App móvil
│   └── AcheronMobile/            # Android/Kotlin + AcheronCore (Java)
├── docker-compose.yml            # Orquestación de servicios
├── .github/workflows/            # CI/CD
│   ├── sync-docs.yml             # Generación de docs (pdoc)
│   └── static.yml                # Deploy a GitHub Pages
└── .env                          # Variables de entorno (no commitear)
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
| Concienciación y generación de contenido | Ollama (IA local, llama3.2) + prompts especializados |
| Obtención de vulnerabilidades recientes | INCIBE-CERT + API pública CIRCL/NVD |
| Análisis anti-phishing | Iris (reglas atómicas con registro por decorador) |
| Frontend web | Vue 3 (Vite + Pinia + Vue Router) |
| App móvil | Android / Kotlin + Jetpack Compose |
| Lógica de vault | AcheronCore (Java) |
| Rate limiting | Flask-Limiter |
| Infraestructura | Docker + Docker Compose |

---

## Quick Start

```bash
# Levantar infraestructura (BD, Ollama, OpenVAS)
docker compose --profile dev up -d

# Arrancar API
cd API && python run.py
# → http://0.0.0.0:5000
```

---

## Notas Importantes

- `.env` contiene credenciales — **NO hacer commit**
- `API/src/data/` está en `.gitignore` (outputs de escaneos)
- OpenVAS tarda ~15min en iniciar la primera vez (descarga NVT feed)
- PostgreSQL usa el puerto **15432** (no el estándar 5432) en desarrollo local
- La documentación se genera automáticamente en la rama `docs` y se despliega a GitHub Pages