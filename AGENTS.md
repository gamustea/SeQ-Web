# SeQ — Agent Guide

## Quick Start

```bash
# Levantar infra (BD, Ollama, OpenVAS)
docker compose --profile dev up -d

# Arrancar API
cd API && python run.py    # → http://0.0.0.0:5000
```

## Ports (de docker-compose.yml)

| Servicio | Puerto host | Nota |
|---|---|---|
| PostgreSQL | **15432** | No 5432 (verificar `.env`) |
| OpenVAS | 9390 | tarda ~15min primera vez |
| Ollama | 11434 | |
| API | 5000 | |

## Modules

- `API/src/modules/sentinel/` — Nmap, Nikto, OpenVAS + informes PDF/IA
- `API/src/modules/aegis/` — Píldoras de concienciación (Ollama)
- `API/src/modules/acheron/` — Vault de secretos cifrados

Entry point: `API/run.py`

## API Auth

Todos los endpoints requieren:
```
Authorization: Bearer <access_token>
```

Obtener token: `POST /oauth/token` con `grantType: password`
Renovar: `grantType: refresh_token`

Test user: `root` / `admin`

## Testing

```bash
cd API && pip install -r requirements.txt && pytest
```

## Documentation Workflow

Push a `main` → genera docs Python en `docs/py/` → push a rama `docs` → GitHub Pages.

## Config Clave

- `API/.env` — conecta a `localhost:15432`
- `API/SecOpsConfig.json` — prompts IA
- `API/requirements.txt` — dependencias (incluye pytest, mypy, black, flake8)

## Importante

- `.env` contiene credenciales — no hacer commit
- OpenVAS tarda ~15min en iniciar (descarga NVT feed)
- `API/src/data/` está en `.gitignore` (outputs de escaneos)