#!/usr/bin/env bash
set -euo pipefail

MODEL="${OLLAMA_MODEL:-mistral}"
MAX_RETRIES=15
SLEEP_TIME=2

echo "🛡️  Aegis — Ollama container starting..."

# Arrancar Ollama en background para poder hacer el pull
/bin/ollama serve &
SERVE_PID=$!

# Esperar a que el servidor esté listo
echo "⏳ Esperando al servidor Ollama..."
for ((i=1; i<=MAX_RETRIES; i++)); do
    if curl -sf http://localhost:11434 &>/dev/null; then
        echo "✅ Servidor listo"
        break
    fi
    if [[ $i -eq $MAX_RETRIES ]]; then
        echo "❌ Timeout esperando a Ollama"
        kill "$SERVE_PID"
        exit 1
    fi
    echo "   Intento $i/$MAX_RETRIES..."
    sleep "$SLEEP_TIME"
done

# Descargar modelo solo si no está cacheado en el volumen
if ollama list | grep -q "^${MODEL}"; then
    echo "✅ Modelo '$MODEL' ya en caché"
else
    echo "⬇️  Descargando '$MODEL'..."
    ollama pull "$MODEL"
    echo "✅ Modelo listo"
fi

# Matar el proceso background y relanzar en foreground
# (para que Docker gestione el ciclo de vida correctamente)
kill "$SERVE_PID"
wait "$SERVE_PID" 2>/dev/null || true

echo "🚀 Arrancando Ollama en foreground..."
exec /bin/ollama serve
