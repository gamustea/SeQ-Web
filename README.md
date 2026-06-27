<!-- prettier-ignore -->
<div align="center">

<img src="./web/resources/images/images/seq/SeQ-BgN.png" alt="SeQ" height="120" />

# SeQ — Security Operations Platform

Plataforma modular de operaciones de seguridad: escaneo de vulnerabilidades, análisis anti-phishing, vault de secretos cifrado y concienciación potenciada por IA local.

[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org)
[![Flask 3.0](https://img.shields.io/badge/Flask-3.0-000?style=flat-square)](https://flask.palletsprojects.com)
[![Vue 3](https://img.shields.io/badge/Vue-3-42b883?style=flat-square&logo=vuedotjs&logoColor=white)](https://vuejs.org)
[![Kotlin](https://img.shields.io/badge/Android-Kotlin-7F52FF?style=flat-square&logo=kotlin&logoColor=white)](https://kotlinlang.org)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15432-4169E1?style=flat-square&logo=postgresql&logoColor=white)](https://www.postgresql.org)
[![Ollama](https://img.shields.io/badge/Ollama-llama3.2-ff7000?style=flat-square)](https://ollama.com)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=flat-square&logo=docker&logoColor=white)](https://www.docker.com)
[![API v3.2](https://img.shields.io/badge/API-3.2-2496ED?style=flat-square)](#)

[Visión general](#visión-general) · [Arquitectura](#arquitectura) · [Módulos](#módulos) · [Quick start](#quick-start) · [Autenticación](#autenticación) · [API](#referencia-de-la-api) · [Docker](#docker) · [Stack](#stack-tecnológico)

</div>

---

## Visión general

**SeQ** es una plataforma monolítica de operaciones de seguridad compuesta por cuatro módulos y dos interfaces (web y móvil) que conviven en un solo repositorio. La API REST (Flask) orquesta escaneos y análisis asíncronos sobre colas **RQ + Redis**, mientras que la IA local (Ollama) genera informes, píldoras de concienciación y veredictos contextualizados.

> [!IMPORTANT]
> La API asume un entorno **Linux**. Las herramientas de escaneo (Nmap, Nikto y OpenVAS/Greenbone) son nativas de Linux. En Windows, ejecuta el entrypoint dentro de WSL (`wsl` → `cd API && python run.py`) o usa `docker compose`.

### Características

- **Escaneo de vulnerabilidades** con Nmap, Nikto y OpenVAS, programables vía APScheduler.
- **Informes PDF con IA** (principio *Controls, Not Counts*) generados por Ollama de forma asíncrona.
- **Análisis anti-phishing** de cabeceras de correo mediante 8 reglas atómicas puntuables.
- **Gestión de secretos cifrados** en cliente (AcheronCore, Java) con sync granular vía API y app Android.
- **Concienciación en ciberseguridad** (Aegis) con píldoras en Markdown + alertas de INCIBE-CERT / CIRCL / NVD.
- **Cola de tareas persistente** (RQ): trabajos que sobreviven a reinicios de la API, workers en procesos aislados, cancelación cooperativa.
- **OAuth 2.0 + JWT** con `jti`, refresh tokens, revocación global y hash Argon2id de contraseñas.

## Arquitectura

```
                ┌─────────────────────────────────────────────────────────┐
                │                    SeQ API (Flask)                      │
                │  system · oauth · users · sentinel · acheron · iris ·   │
                │                     aegis · pages                       │
                │                                                         │
   Web SPA ───► │  APScheduler ──► TaskQueue (RQ + Redis) ──► RQ Workers  │ ──► Nmap / Nikto / OpenVAS
  (Vue 3)       │                       ▲                                 │ ──► Ollama (llama3.2) / OpenAI
                │                       │                                 │ ──► INCIBE-CERT · CIRCL · NVD
  Android  ───► │                       │                                 │
  (Kotlin)      │                  PostgreSQL (15432)                     │
                └─────────────────────────────────────────────────────────┘
```

```
SeQ/
├── API/        # Backend Flask (punto de entrada a la API REST)
├── web/        # SPA Vue 3 (Vite + Pinia)
├── mobile/     # AcheronMobile (Android/Kotlin) + AcheronCore (Java)
├── tests/      # Suite de pruebas
└── docker-compose.yml
```

## Módulos

| Módulo | Descripción | Estado |
|---|---|---|
| **Sentinel** | API REST de escaneo (Nmap/Nikto/OpenVAS), resultados, informes PDF con IA y escaneos programados. | Operativo |
| **Iris** | Análisis de cabeceras de correo para detección de phishing mediante reglas puntuables. | Operativo |
| **Acheron** | Vault de secretos cifrados (`Account`, `CreditCard`) con sync granular y app Android. | Operativo |
| **Aegis** | Píldoras de concienciación + alertas de vulnerabilidades recientes, generadas por IA local. | Operativo |
| **SeQ Web** | SPA Vue 3 (Vite + Pinia + Vue Router) con dashboard Hub central. | Operativo |
| **AcheronMobile** | App Android/Kotlin + Jetpack Compose con motor de cifrado AcheronCore (Java). | Operativo |

## Quick start

> [!NOTE]
> Necesitas PostgreSQL, Redis, Docker y Python 3.10+ (o WSL). Para IA: **Ollama** con `llama3.2`. Para escaneos: Nmap, Nikto y OpenVAS/GVM.

```bash
# 1. Clonar
git clone https://github.com/gamustea/SeQ.git
cd SeQ

# 2. Levantar infraestructura (PostgreSQL 15432, Redis, Ollama, OpenVAS)
docker compose --profile dev up -d

# 3. Configurar API/.env (CREATE_DATABASE=True la primera vez) e instalar dependencias
cd API
pip install -r requirements.txt
python run.py          # → http://0.0.0.0:5000

# 4. (otro terminal) Lanzar un worker RQ para las tareas asíncronas
python -m src.modules.system.taskqueue.worker
```

> [!TIP]
> `_init_db()` (con `CREATE_DATABASE=True`) es **destructivo**: recrea la BD e inserta el usuario `root` y los Topics. Apágalo tras el primer arranque.

## Autenticación

OAuth 2.0 con `grant_type: password` y refresh tokens (JWT firmados con PyJWT). **Las claves JSON usan camelCase** (`grantType`, `refresh_token`).

```http
POST /oauth/token
Content-Type: application/json

{ "grantType": "password", "username": "root", "password": "admin" }
```

```json
{ "access_token": "<jwt>", "token_type": "Bearer", "expires_in": 1800, "refresh_token": "<token>" }
```

> [!WARNING]
> Todos los endpoints protegidos requieren `Authorization: Bearer <access_token>`. `POST /oauth/revoke-all` revoca todos los tokens del usuario.

## Referencia de la API

### Sentinel — escaneos

| Método | Endpoint | Descripción |
|---|---|---|
| `POST` | `/sentinel/nmap` | Escaneo de puertos (soporta rangos CIDR) |
| `POST` | `/sentinel/nikto` | Escaneo web de configuración/vulnerabilidades |
| `POST` | `/sentinel/openvas` | Escaneo NVT completo (un host por escaneo) |
| `GET` | `/sentinel/results` | Lista de escaneos (filtrable y paginado) |
| `GET` | `/sentinel/results/<id>` | Detalle de un escaneo |
| `GET` | `/sentinel/scan-status?id=` | Estado (`pending`/`running`/`done`/`cancelled`) |
| `POST` | `/sentinel/scans/<id>/cancel` | Cancela un escaneo en curso |
| `DELETE` | `/sentinel/<id>` | Elimina un escaneo |
| `POST` | `/sentinel/generate-pdf` | Genera PDF (`{ "id": <scanId>, "aiReport": true }`) |
| `GET` | `/sentinel/document/<id>/download` | Descarga del PDF |
| `POST` | `/sentinel/scheduled-scans` | Crea escaneo programado (cron/intervalo) |
| `GET/DELETE` | `/sentinel/folders[/<id>]` | Organiza escaneos en carpetas |

**Ejemplo — escaneo Nmap:**

```http
POST /sentinel/nmap
Authorization: Bearer <token>
Content-Type: application/json

{ "target": "192.168.1.0/24", "ports": "80,443,22,8080" }
```

```json
{
  "message": "Escaneo(s) Nmap iniciado(s) correctamente",
  "scanIds": [1, 2, 3],
  "totalScans": 3
}
```

### Iris — anti-phishing

| Método | Endpoint | Permiso | Descripción |
|---|---|---|---|
| `POST` | `/iris/analyze` | `IRIS_CREATE` | Envía cabeceras (opcional: `title`) |
| `GET` | `/iris/status?id=` | `IRIS_READ` | Estado y progreso del análisis |
| `GET` | `/iris/results/<id>` | `IRIS_READ` | Informe con reglas, scores y veredicto |
| `POST` | `/iris/analyze/<id>/cancel` | `IRIS_UPDATE` | Cancela un análisis en curso |
| `DELETE` | `/iris/results/<id>` | `IRIS_DELETE` | Elimina un análisis |

Iris aplica **8 reglas atómicas** (SPF, DKIM, DMARC, Reply-To, Return-Path, Message-ID, Content-Type, From) y devuelve un veredicto: `Legitimate` / `Suspicious` / `Phishing`. Umbrales en `SecOpsConfig.json` (`iris.legitimate_threshold`, `iris.suspicious_threshold`, `iris.min_headers`).

### Aegis — concienciación y alertas

| Método | Endpoint | Descripción |
|---|---|---|
| `POST` | `/aegis/generate` | Genera una píldora ({ `topicId`, `tweaks`: {…} }) |
| `GET` | `/aegis/status?id=` | Estado de la píldora |
| `GET` | `/aegis/download_as_md?id=` | Exporta la píldora + alertas como Markdown |
| `GET` | `/aegis/download_as_html?id=` | Exporta como HTML |
| `GET` | `/aegis/download_as_pdf?id=` | Exporta como PDF |
| `GET` | `/aegis/topics` | Lista de topics disponibles |
| `GET/DELETE` | `/aegis/documents[/<id>]` | Lista / detalle / borrado |

Aegis combina la píldora generada por Ollama con un resumen de vulnerabilidades recientes (INCIBE-CERT + API pública CIRCL/NVD), todo guardado como `AegisDocument` propio del usuario.

### Acheron — vault de secretos

| Método | Endpoint | Descripción |
|---|---|---|
| `GET` | `/acheron/vault` | Obtiene el vault (blob cifrado) |
| `POST` | `/acheron/vault` | Crea o reemplaza el vault completo |
| `POST` | `/acheron/storables` | Añade un `Account` o `CreditCard` |
| `PATCH` | `/acheron/storables` | Actualiza solo campos modificados (bulk) |
| `DELETE` | `/acheron/storables` | Elimina un Storable por `internalId` |

> [!NOTE]
> El cifrado ocurre **en el cliente** (AcheronCore, Java). El servidor solo almacena ciphertext. Cada Storable recibe un `internalId` = **SHA-256 truncado a 16 hex** del contenido cifrado, determinista y libre de colisiones entre dispositivos offline.

**Ejemplo — añadir una cuenta:**

```http
POST /acheron/storables
Authorization: Bearer <token>
Content-Type: application/json

{ "kind": "account", "title": "GitHub", "username": "usuario", "domain": "github.com", "password": "secreto" }
```

### Usuarios y sistema

| Método | Endpoint | Descripción |
|---|---|---|
| `POST` | `/users/sign-up` | Registro (username, password, email, alias) |
| `PUT` | `/users/change-password` | Cambio de contraseña (invalida todos los tokens) |
| `GET` | `/system/tasks` | (admin) Lista de tareas de la cola RQ |
| `POST` | `/system/tasks/<id>/cancel` | (admin) Cancela una tarea en cola |

## TaskQueue (RQ + Redis)

Sustituye al SeQueue legacy. Los trabajos persisten en Redis y **sobreviven a reinicios de la API**. Los workers son **procesos OS independientes** (no hilos), aislados de la API.

- `TaskQueue.get_instance().submit(func, name=, category=, external_id=, args=, timeout=)`.
- Categorías: `sentinel.scan`, `sentinel.report`, `aegis.generate`, `iris.analyze`.
- External IDs: `scan:<id>`, `sentinel-doc:<id>`, `aegis-doc:<id>`, `iris-analysis:<id>`.
- Cancelación: clave Redis `taskqueue:cancel:<job_id>` verificada cooperativamente por el worker vía `_Task.wait(cancel_check=…)`.
- Cada módulo expone funciones standalone en `services/rq_tasks.py` (reconstruyen manager/tarea dentro del worker y reportan progreso en `job.meta["progress"]`).

> [!WARNING]
> Los workers RQ deben estar corriendo para que las tareas asíncronas se ejecuten: `python -m src.modules.system.taskqueue.worker`. Escuchan en colas específicas por categoría + `default`.

## Docker

Dos perfiles en `docker-compose.yml`:

| Perfil | Contenido | Uso |
|---|---|---|
| `dev` | PostgreSQL, Redis, Ollama, OpenVAS | Desarrollo local con la API en Python |
| `container` | Infraestructura + API + worker + web | Despliegue completo |

```bash
docker compose --profile dev up -d        # solo infraestructura
docker compose --profile container up -d  # despliegue completo
```

GPU: añade `-f docker-compose.gpu-nvidia.yml` (o `.gpu-intel.yml` / `.gpu-amd.yml`).

### IA configurable (módulo `scribe`)

La generación con IA usa una **estrategia inyectable** elegida en `API/SecOpsConfig.json`:

```json
"ai": {
  "defaultStrategy": "ollama",
  "strategies": { "ollama": {}, "openai": {} },
  "modules": { "sentinel": "ollama", "aegis": "openai" }
}
```

- **`ollama`** — modelo local (`llama3.2` por defecto), ideal para máquinas con GPU.
- **`openai`** — API de OpenAI (`gpt-4o-mini`), pensada para VPS sin GPU.

```bash
ollama pull llama3.2   # o, en el contenedor: docker exec -it OllamaSeQ ollama pull llama3.2
```

Variables de entorno (en `API/.env`):

```
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=llama3.2
OPENAI_API_KEY=sk-...        # solo si algún módulo usa "openai"
OPENAI_MODEL=gpt-4o-mini
```

## Puertos

| Servicio | Puerto | Nota |
|---|---|---|
| API | 5000 | `0.0.0.0:5000` |
| PostgreSQL | 15432 | Contenedor mapea 5432→15432 |
| Redis | 6379 | Requerido por la TaskQueue |
| OpenVAS | 9390/9392 | ~15 min primer arranque (feed NVT) |
| Ollama | 11434 | |

## Stack tecnológico

| Capa | Tecnología |
|---|---|
| Backend | Python 3, Flask 3.0, SQLAlchemy 2.0, Flask-Smorest |
| Base de datos | PostgreSQL (psycopg2) |
| Cola de tareas | RQ + Redis |
| Autenticación | OAuth 2.0 + JWT (PyJWT con claim `jti`) |
| Hash de contraseñas | Argon2id (argon2-cffi) |
| Escaneo | Nmap + python-nmap, Nikto, OpenVAS/GVM (vía python-gvm) |
| Informes PDF | ReportLab + Pillow |
| IA | Ollama (local) / OpenAI (estrategia `scribe`) |
| Vulnerabilidades recientes | INCIBE-CERT + CIRCL/NVD |
| Frontend web | Vue 3 (Vite + Pinia + Vue Router) |
| Móvil | Android / Kotlin + Jetpack Compose, Retrofit + OkHttp |
| Vault | AcheronCore (Java): AES + Argon2id (fallback PBKDF2), IDs SHA-256 |
| Sesión móvil | `EncryptedSharedPreferences` (Android Keystore, AES-256-GCM/SIV) |
| Infraestructura | Docker + Docker Compose, APScheduler |

## Configuración

El sistema de configuración (`API/src/modules/system/config_reading.py`, importado como `CR`) carga en orden:

1. `API/SecOpsConfig.json` — JSON (DB fallback, prompts de IA, directorios, taskqueue, `appVersion`).
2. `API/.env` — variables que **sobreescriben** el JSON. Obligatorias para OAuth (JWT_SECRET_KEY, JWT_ALGORITHM…) y la BD.
3. `.env` raíz — solo para docker-compose (Postgres, Redis, OpenVAS). No para la API.

Todas las claves se cargan perezosamente vía `@_lazy_load`. Los cambios en `SecOpsConfig.json` requieren reinicio salvo que se apliquen vía `PUT /system`.

## Notas importantes

- `.env` contiene credenciales — **no commitear**. `API/.env` está en `.gitignore`.
- `API/src/data/` y `docs/` están en `.gitignore` (outputs de escaneos y docs generados).
- `_init_db()` con `CREATE_DATABASE=True` es **destructivo**: recrea la BD e inserta `root` y los Topics.
- OpenVAS solo acepta **un host** por escaneo (no rangos CIDR) y tarda ~15 min la primera vez.
- PostgreSQL usa el puerto **15432** en desarrollo local (no el estándar 5432).
- `sentinel/services/tasks.py` define su propio `TaskStatus`, **distinto** de `taskqueue.TaskStatus`.
- Los tokens JWT incluyen el claim `jti` — obligatorio en nueva emisión.
- La versión de la API (**3.2**) se declara como `appVersion` en `SecOpsConfig.json` (leída por `CR.get_app_version()`).