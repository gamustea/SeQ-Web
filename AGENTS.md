# SeQ — Developer Guide

## Quick Start

```bash
# 1. Levantar servicios Docker (infraestructura)
docker compose --profile dev up -d

# 2. Inicializar y arrancar API (desarrollo local)
cd API
python init_db.py   # Initialize PostgreSQL database (port 15432)
python run.py       # Start API at http://0.0.0.0:5000
```

## Architecture

Three modules under `/API/src/`:
- **Sentinel** — Vulnerability scanning (Nmap, Nikto, OpenVAS + AI reports via Ollama)
- **Aegis** — Security awareness content generation (Ollama-powered pills)
- **Acheron** — Encrypted secrets vault

Entry point: `API/run.py`
Blueprints: `API/src/endpoints/`
Models: `API/src/core/model/`

## Docker Setup

Uses profiles to switch between development and container modes:

```bash
# Modo desarrollo: levanta BD + Ollama + OpenVAS en Docker; API corre en local
docker compose --profile dev up -d
python API/run.py

# Modo contenedor: todo dentro de Docker (API + Web incluidas)
docker compose --profile container up -d

# Limpiar
docker compose down
```

Los servicios de infra (postgres, ollama, openvas) están siempre en el perfil `dev`, por lo que puedes cambiar de un modo a otro sin tocar nada.

## Commands

| Action | Command |
|--------|---------|
| Run API (desarrollo) | `python API/run.py` |
| Docker infra | `docker compose --profile dev up -d` |
| Docker todo | `docker compose --profile container up -d` |
| Test user | username: `root`, password: default (admin) |

## Key Config Files

- `API/SecOpsConfig.json` — AI prompts
- `API/.env` — Credenciales, conecta a `localhost:15432` (desarrollo local)
- `API/.env.docker` — Overrides para cuando la API corre dentro del contenedor (`POSTGRES_HOST=postgres`, etc.)
- `API/entrypoint.sh` — Carga `.env.docker` antes de arrancar la API dentro del contenedor
- `API/requirements.txt` — Python dependencies

## API Patterns

- **All endpoints except register/login require OAuth token:**
  ```
  Authorization: Bearer <access_token>
  ```
- Token via `POST /oauth/token` with `grant_type: password`
- Refresh via `POST /oauth/token` with `grant_type: refresh_token`

## Web UI

Static files served from `Interface/web/` at root. API routes (`/sentinel/*`, `/aegis/*`, etc.) are excluded from UI fallback.

## Testing

Uses `pytest`. Run with:
```bash
cd API
pip install -r requirements.txt
pytest
```

## Important Constraints

- PostgreSQL runs on **port 15432** (check `.env` if connection fails)
- OpenVAS first run takes several minutes (NVT feed download)
- `.env` contains credentials — never commit changes
- `.gitignore` excludes `API/data/*` (scan outputs)