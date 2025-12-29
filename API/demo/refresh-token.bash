#!/bin/bash

# oauth_refresh.sh
# Refresca el access token usando el refresh token

# Variables por defecto
API_URL="http://localhost:5000/oauth/token"
REFRESH_TOKEN_FILE=""

# Procesar argumentos
while getopts "f:h" opt; do
  case $opt in
    f)
      REFRESH_TOKEN_FILE="$OPTARG"
      ;;
    h)
      echo "Uso: $0 -f <archivo_refresh_token>"
      echo ""
      echo "Opciones:"
      echo "  -f    Archivo que contiene el refresh token"
      echo "  -h    Mostrar esta ayuda"
      exit 0
      ;;
    \?)
      echo "Opción inválida: -$OPTARG" >&2
      exit 1
      ;;
    :)
      echo "La opción -$OPTARG requiere un argumento" >&2
      exit 1
      ;;
  esac
done

# Validar que se proporcionó el archivo
if [ -z "$REFRESH_TOKEN_FILE" ]; then
  echo "Error: Se requiere especificar el archivo con el refresh token" >&2
  echo "Uso: $0 -f <archivo_refresh_token>" >&2
  exit 1
fi

# Verificar que el archivo existe
if [ ! -f "$REFRESH_TOKEN_FILE" ]; then
  echo "Error: El archivo '$REFRESH_TOKEN_FILE' no existe" >&2
  exit 1
fi

# Leer el refresh token del archivo
REFRESH_TOKEN=$(cat "$REFRESH_TOKEN_FILE" | tr -d '\n\r')

if [ -z "$REFRESH_TOKEN" ]; then
  echo "Error: El archivo está vacío o no contiene un token válido" >&2
  exit 1
fi

# Realizar la petición a la API
echo "Refrescando access token..."

RESPONSE=$(curl -s -X POST "$API_URL" \
  -H "Content-Type: application/json" \
  -d "{\"X-Grant-Type\":\"refresh_token\",\"X-Refresh-Token\":\"$REFRESH_TOKEN\"}")

# Verificar si la petición fue exitosa
if [ $? -ne 0 ]; then
  echo "Error: No se pudo conectar con la API" >&2
  exit 1
fi

# Extraer el nuevo access token
NEW_ACCESS_TOKEN=$(echo "$RESPONSE" | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)
EXPIRES_IN=$(echo "$RESPONSE" | grep -o '"expires_in":[0-9]*' | cut -d':' -f2)

# Verificar si se obtuvo el nuevo token
if [ -z "$NEW_ACCESS_TOKEN" ]; then
  echo "Error: No se pudo refrescar el access token" >&2
  echo "Respuesta del servidor:" >&2
  echo "$RESPONSE" >&2
  exit 1
fi

# Guardar el nuevo access token
echo "$NEW_ACCESS_TOKEN" > access_token.txt
chmod 600 access_token.txt

echo "✓ Access token refrescado exitosamente"
echo "  - Nuevo access token guardado en: access_token.txt"
echo "  - El token expira en: $EXPIRES_IN segundos"
