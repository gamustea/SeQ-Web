#!/bin/bash

# oauth_generate.sh
# Genera tokens OAuth 2.0 y los guarda en archivos separados

# Variables por defecto
API_URL="http://localhost:5000/oauth/token"
USERNAME=""
PASSWORD=""

# Procesar argumentos
while getopts "u:p:h" opt; do
  case $opt in
    u)
      USERNAME="$OPTARG"
      ;;
    p)
      PASSWORD="$OPTARG"
      ;;
    h)
      echo "Uso: $0 -u <usuario> -p <contraseña>"
      echo ""
      echo "Opciones:"
      echo "  -u    Nombre de usuario"
      echo "  -p    Contraseña"
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

# Validar que se proporcionaron usuario y contraseña
if [ -z "$USERNAME" ] || [ -z "$PASSWORD" ]; then
  echo "Error: Se requieren usuario y contraseña" >&2
  echo "Uso: $0 -u <usuario> -p <contraseña>" >&2
  exit 1
fi

# Realizar la petición a la API
echo "Solicitando tokens OAuth para el usuario: $USERNAME"

RESPONSE=$(curl -s -X POST "$API_URL" \
  -H "Content-Type: application/json" \
  -d "{\"X-Grant-Type\":\"password\",\"X-Username\":\"$USERNAME\",\"X-Password\":\"$PASSWORD\"}")

# Verificar si la petición fue exitosa
if [ $? -ne 0 ]; then
  echo "Error: No se pudo conectar con la API" >&2
  exit 1
fi

# Extraer tokens de la respuesta JSON
ACCESS_TOKEN=$(echo "$RESPONSE" | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)
REFRESH_TOKEN=$(echo "$RESPONSE" | grep -o '"refresh_token":"[^"]*"' | cut -d'"' -f4)
EXPIRES_IN=$(echo "$RESPONSE" | grep -o '"expires_in":[0-9]*' | cut -d':' -f2)

# Verificar si se obtuvieron los tokens
if [ -z "$ACCESS_TOKEN" ] || [ -z "$REFRESH_TOKEN" ]; then
  echo "Error: No se pudieron obtener los tokens" >&2
  echo "Respuesta del servidor:" >&2
  echo "$RESPONSE" >&2
  exit 1
fi

# Guardar tokens en archivos separados
echo "$ACCESS_TOKEN" > access_token.txt
echo "$REFRESH_TOKEN" > refresh_token.txt

# Establecer permisos restrictivos
chmod 600 access_token.txt
chmod 600 refresh_token.txt

echo "✓ Tokens generados exitosamente"
echo "  - Access token guardado en: access_token.txt"
echo "  - Refresh token guardado en: refresh_token.txt"
echo "  - El access
