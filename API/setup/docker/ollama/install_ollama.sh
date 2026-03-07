#!/usr/bin/env bash
set -euo pipefail

# ─────────────────────────────────────────────
# Aegis — Installer de Ollama
# Uso: ./install_ollama.sh [modelo]
# Ejemplo: ./install_ollama.sh mistral
# ─────────────────────────────────────────────

MODEL="${1:-mistral}"
OLLAMA_URL="http://localhost:11434"

echo "🛡️  Aegis — Setup de Ollama"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# ── 1. Instalar Ollama si no está presente ──
if command -v ollama &>/dev/null; then
    echo "✅ Ollama ya está instalado ($(ollama --version))"
else
    echo "⬇️  Instalando Ollama..."
    curl -fsSL https://ollama.com/install.sh | sh
    echo "✅ Ollama instalado correctamente"
fi

# ── 2. Levantar el servicio ──
if systemctl is-active --quiet ollama 2>/dev/null; then
    echo "✅ Servicio Ollama ya está corriendo (systemd)"
elif pgrep -x "ollama" &>/dev/null; then
    echo "✅ Ollama ya está corriendo como proceso"
else
    echo "🚀 Arrancando Ollama..."
    if systemctl list-unit-files | grep -q "^ollama.service"; then
        sudo systemctl enable --now ollama
    else
        nohup ollama serve > /tmp/ollama.log 2>&1 &
        echo "   Ollama corriendo en background (log: /tmp/ollama.log)"
    fi
fi

# ── 3. Esperar a que el servidor esté listo ──
echo "⏳ Esperando a que Ollama esté disponible..."
RETRIES=15
for ((i=1; i<=RETRIES; i++)); do
    if curl -sf "$OLLAMA_URL" &>/dev/null; then
        echo "✅ Ollama responde en $OLLAMA_URL"
        break
    fi
    if [[ $i -eq $RETRIES ]]; then
        echo "❌ Ollama no respondió tras $RETRIES intentos. Revisa /tmp/ollama.log"
        exit 1
    fi
    echo "   Intento $i/$RETRIES — reintentando en 2s..."
    sleep 2
done

# ── 4. Descargar el modelo si no está ──
if ollama list | grep -q "^${MODEL}"; then
    echo "✅ Modelo '$MODEL' ya está descargado"
else
    echo "⬇️  Descargando modelo '$MODEL' (puede tardar varios minutos)..."
    ollama pull "$MODEL"
    echo "✅ Modelo '$MODEL' listo"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🎉 Setup completado. Aegis puede usar Ollama."
echo "   Modelo activo : $MODEL"
echo "   Endpoint      : $OLLAMA_URL"
