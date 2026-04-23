# SeQ — Developer Guide

## Quick Start

```bash
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

## Required Setup

- Python 3.10+
- PostgreSQL (default: port **15432**, not 5432)
- Docker services (via `cd API && docker-compose up -d`):
  - PostgreSQL
  - Ollama (`OLLAMA_MODEL=qwen2.5:14b` in .env)
  - OpenVAS/GVM

## Commands

| Action | Command |
|--------|---------|
| Run API | `python API/run.py` |
| Docker stack | `docker-compose -f API/docker-compose.yml up -d` |
| Test user | username: `root`, password: default (admin) |

## Key Config Files

- `API/SecOpsConfig.json` — AI prompts (system/user templates for Nmap, Nikto, OpenVAS, Aegis)
- `API/.env` — DB port (15432), JWT secrets, Ollama host/model
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