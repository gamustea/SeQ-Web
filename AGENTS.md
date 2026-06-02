# SeQ — Agent Guide

## Architecture

Monorepo with three components:
- **API** (`API/`) — Python/Flask REST backend (the core)
- **web** (`web/`) — Vue 3 SPA in `web/app/` (Vite + Pinia + Vue Router), built to static files and served by Nginx in production or the Vite dev server in development
- **mobile** (`mobile/AcheronMobile/`) — Android/Kotlin app with AcheronCore Java module

The `API/` directory is the primary work area. The web and mobile dirs are separate projects with their own builds.

## Entry Point

`API/run.py` → `create_app()` factory. Registers blueprints then adds a catch-all UI route.

```bash
docker compose --profile dev up -d   # postgres (15432), ollama, openvas
cd API && python run.py               # starts on 0.0.0.0:5000
```

Development — Vue frontend (separate terminal):
```bash
cd web/app && pnpm dev               # Vite dev server on :5173, proxies API to :5000
```

Docker compose has two profiles:
- `dev` — infrastructure only (postgres, ollama, openvas). Use for local Python development.
- `container` — everything including the API container and web. Use for full deployment.

Ollama corre en CPU por defecto. Para aceleración GPU, añade el archivo correspondiente con `-f`:

| GPU | Comando |
|---|---|
| NVIDIA (dedicada) | `docker compose -f docker-compose.yml -f docker-compose.gpu-nvidia.yml --profile dev up -d` |
| Intel integrada (iGPU) | `docker compose -f docker-compose.yml -f docker-compose.gpu-intel.yml --profile dev up -d` |
| AMD (dedicada o APU) | `docker compose -f docker-compose.yml -f docker-compose.gpu-amd.yml --profile dev up -d` |

Cada archivo cambia la imagen al tag específico del backend (`intel-gpu`, `rocm`) o añade los device mappings necesarios.

The `.env` at the repo root is for docker-compose (PostgreSQL and OpenVAS credentials). The `API/.env` is for local development only; the containerised API does **not** load it.

## Database

- PostgreSQL on port **15432** (not 5432). Container maps 15432→5432.
- DB init: set `CREATE_DATABASE=True` in `API/.env`, then run the app. The `_init_db()` function in `run.py` drops and recreates everything. The `init_db.py` script referenced in README no longer exists.
- SQLAlchemy models are in each module's `model.py`. Base class comes from `src.modules.shared`.

## Config System

Two sources, merged via lazy loading in `API/src/modules/system/config_reading.py` (imported as `CR`):
1. `API/SecOpsConfig.json` — JSON config: DB credentials (fallback), prompts, color palettes, directory paths, module-specific settings.
2. `API/.env` — environment variables override JSON config. Required for OAuth (JWT_SECRET_KEY, JWT_ALGORITHM, ACCESS_TOKEN_EXPIRY_MINUTES, REFRESH_TOKEN_EXPIRY_DAYS) and database connection (POSTGRES_USER, POSTGRES_PASSWORD, POSTGRES_DB, etc.).

The root `.env` (at repo top level) is for docker-compose (PostgreSQL and OpenVAS credentials). The `API/.env` is read by python-dotenv **only when running locally** (`python run.py`). Inside the container, environment variables come directly from the `docker-compose.yml` `environment` section.

## Modules

All under `API/src/modules/`:
- **shared/** — Base classes: `BaseManager`, `Base` (SQLAlchemy), `AIWriter`, `Document`, `ExceptionHandler`, rate limiter, decorators (`require_json`, `require_arg`, `normalize_target`)
- **system/** — `config_reading` (`CR`), logging (`SecOpsLogger`), health endpoints
- **users/** — ORM, auth (OAuth 2.0 + JWT), user management
- **sentinel/** — Port scanning (Nmap), web scanning (Nikto), vulnerability scanning (OpenVAS), PDF/IA report generation. Sub-modules in `services/`
- **aegis/** — AI-powered cybersecurity awareness content via Ollama
- **acheron/** — Encrypted secret vault (Accounts, CreditCards)
- **pages/** — Static HTML page serving
- **infrastructure/** — Internal utilities

## Auth

OAuth 2.0 with JWT. **JSON keys use camelCase** (`grantType`, `refresh_token`), not snake_case.

```
POST /oauth/token  {"grantType": "password", "username": "root", "password": "admin"}
```

All protected endpoints require `Authorization: Bearer <access_token>`.

## Dev Commands

No test files exist yet (`pytest`, `flake8`, `mypy`, `black` are listed as dependencies but no tests are written).

```bash
cd API && python run.py           # Run the app
cd API && pip install -r requirements.txt   # Install deps (NOT REQUIREMENTS.txt)
```

Linting/formatting (when tests exist):
```bash
cd API && flake8 .
cd API && mypy .
cd API && black --check .
```

## Ollama

Default model is **llama3.2** (set in `config_reading.py`), not llama3.1 (README is outdated). Override with `OLLAMA_MODEL` env var.

## Ports

| Service | Port | Note |
|---|---|---|
| API | 5000 | `0.0.0.0:5000` |
| PostgreSQL | 15432 | Mapped from container's 5432 |
| OpenVAS | 9390/9392 | ~15min first start (NVT feed download) |
| Ollama | 11434 | |

## Things That Bite

- `.env` contains credentials — never commit. `API/.env` is gitignored.
- `API/src/data/` is gitignored (scan outputs, generated content).
- `docs/` is gitignored (auto-generated by CI on push to main).
- The `Interface/` directory referenced in README no longer exists — web files are in `web/` at repo root.
- Docker files are colocated with their components: `API/Dockerfile` and `web/Dockerfile`. The old `API/docker/` directory has been removed.
- OpenVAS only accepts a single host per scan (not CIDR ranges).
- `_init_db()` is destructive — it drops and recreates the entire database.

## CI

- Push to `main` → `sync-docs.yml` generates Python docs via `pdoc` → pushes to `docs` branch
- Push to `docs` branch → `static.yml` deploys to GitHub Pages