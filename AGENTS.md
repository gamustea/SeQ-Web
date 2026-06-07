# SeQ — Agent Guide

## Architecture

Monorepo:
- **API** (`API/`) — Python/Flask REST backend (primary work area)
- **web** (`web/app/`) — Vue 3 SPA (Vite + Pinia + Vue Router)
- **mobile** (`mobile/AcheronMobile/`) — Android/Kotlin + AcheronCore Java

## Entry Point

`API/run.py` → `create_app()` factory. Does this in order:
1. Register CORS, rate limiter, FlaskSmorest API
2. Register blueprints (system, oauth, users, sentinel, acheron, aegis, pages)
3. Init DB engine + create tables
4. **Start APScheduler** (`Scheduler.start()`)
5. **Start SeQueue** (`SeQueue.get_instance().start()`)
6. Signal handlers (SIGTERM/SIGINT) → cancel SeQueue → stop Scheduler → close DB

```bash
docker compose --profile dev up -d   # postgres(15432), ollama, openvas
cd API && python run.py               # 0.0.0.0:5000
```

## SeQueue — Background Task Queue

Central async task system at `API/src/modules/system/sequeue/`.

Key files: **`task.py`** (SeQueueTask dataclass + SeQueueTaskStatus enum), **`queue.py`** (SeQueue singleton with thread pool).

Facts:
- Thread-safe singleton: `SeQueue.get_instance()`
- Config: `general.sequeue` in `SecOpsConfig.json` (`max_workers`, `history_max_items`, `history_ttl_seconds`). Override `max_workers` via env `SEQUEUE_MAX_WORKERS`.
- Submit: `SeQueue.get_instance().submit(func, name=, category=, external_id=, args=, on_cancel=, on_complete=, on_error=)`
- Categories in use: `"sentinel.scan"`, `"sentinel.report"`, `"aegis.generate"`
- external_id patterns: `f"scan:{scan_id}"`, `f"sentinel-doc:{doc_id}"`, `f"aegis-doc:{document_id}"`
- CamelCase in `to_dict()`: `externalId`, `createdAt`, `startedAt`, `finishedAt`
- REST API (admin-only, `/system/sequeue/*`): status, list tasks, detail, cancel, resize workers
- Separate `TaskStatus` enum exists in `sentinel/services/tasks.py` — not the same as `SeQueueTaskStatus`

## Config System

`API/src/modules/system/config_reading.py` (imported as `CR`):
1. `API/SecOpsConfig.json` — JSON config (DB fallback, prompts, directories, sequeue)
2. `API/.env` — env vars override JSON. Required for OAuth (JWT_SECRET_KEY, JWT_ALGORITHM, etc.) and DB.
3. Root `.env` — for docker-compose only (Postgres + OpenVAS creds). Not for the API.

All config keys lazily loaded via `@_lazy_load` decorator.

## Auth

OAuth 2.0 + JWT. **JSON keys use camelCase** (`grantType`, `refresh_token`).

```
POST /oauth/token  {"grantType": "password", "username": "root", "password": "admin"}
```

Protected endpoints require `Authorization: Bearer <access_token>`. Roles checked via `require_role()`.

## Database

- PostgreSQL port **15432** (container maps 15432→5432)
- Init: set `CREATE_DATABASE=True` in `API/.env`, then run the app. `_init_db()` in `run.py` is destructive (drops + recreates DB + inserts root user and Topic rows).
- Models: SQLAlchemy, each module has `model.py`, base from `src.modules.shared`.
- All DB ops use `UnitOfWork` + repository pattern. No direct session management outside repos.

## Scan System (sentinel)

- `sentinel/services/tasks.py`: `_Task` base class → `NmapScanTask`, `NiktoScanTask`, `OpenVASTask`
- Each scan manager (NmapScanManager, NiktoScanManager, OpenVASScanManager) submits to SeQueue with `category="sentinel.scan"` and `external_id=f"scan:{scan_id}"`
- `on_cancel=task.cancel` — cancels the subprocess / GMP task
- OpenVAS: GMP API (not CLI). Uses `python-gvm`. Targets, port lists, scan configs auto-managed.
- Scheduled scans via APScheduler (`sentinel/services/scheduling.py`). `Scheduler` class with interval/cron triggers. Synced from DB.

## Aegis

- `aegis/managers.py`: `AegisManager` submits to SeQueue with `category="aegis.generate"`, `external_id=f"aegis-doc:{doc_id}"`
- Uses Ollama (`llama3.2` default, override via `OLLAMA_MODEL` env var)

## Ports

| Service | Port | Note |
|---|---|---|
| API | 5000 | `0.0.0.0:5000` |
| PostgreSQL | 15432 | Container maps 5432→15432 |
| OpenVAS | 9390/9392 | ~15min first start (NVT feed) |
| Ollama | 11434 | |

## Docker

Two profiles:
- `dev` — infrastructure only (postgres, ollama, openvas)
- `container` — everything including API and web containers

GPU: `-f docker-compose.gpu-nvidia.yml / .gpu-intel.yml / .gpu-amd.yml`

## Things That Bite

- `.env` files contain credentials — never commit. `API/.env` is gitignored.
- `API/src/data/` and `docs/` are gitignored.
- `_init_db()` is destructive — drops and recreates everything.
- OpenVAS only accepts a single host per scan (not CIDR ranges).
- `SecOpsConfig.json` values are lazily cached — changes require app restart unless written via `PUT /system` endpoint.
- `sentinel/services/tasks.py` has its own `TaskStatus` enum separate from `SeQueueTaskStatus`.
- API version is **3.2** (not from config, hardcoded in `create_app()`).
