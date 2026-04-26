#!/bin/sh
# entrypoint.sh — carga .env.docker antes de arrancar la API
# Esto permite que las variables de entorno del contenedor (postgres, ollama, openvas)
# se usen sin modificar .env (que apunta a localhost para desarrollo local).

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ENV_FILE="$SCRIPT_DIR/.env.docker"

if [ -f "$ENV_FILE" ]; then
    set -a
    . "$ENV_FILE"
    set +a
fi

exec python run.py "$@"