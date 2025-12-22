#!/bin/bash
# Script para generar token de acceso a la SecOps API
# Estrategia: credenciales root/root si no existe refresh_token.txt, sino usa refresh token

BASE_URL="http://localhost:5000"
TOKEN_FILE="refresh_token.txt"

# Función para leer refresh token
read_refresh_token() {
    if [[ -f "$TOKEN_FILE" ]]; then
        cat "$TOKEN_FILE" | tr -d '\n\r'
    fi
}

# Función para login con credenciales
login_with_credentials() {
    echo "🔐 Login con credenciales root/root..."
    
    response=$(curl -s -w "\n%{http_code}" -X POST \
        "$BASE_URL/oauth/token" \
        -H "Content-Type: application/json" \
        -d '{
            "grant_type": "password",
            "username": "ana.garcia",
            "password": "ana123"
        }')
    
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | sed '$d')
    
    if [[ "$http_code" != "200" ]]; then
        echo "❌ Error login: $http_code"
        echo "$body" | jq .
        exit 1
    fi
    
    access_token=$(echo "$body" | jq -r .access_token)
    refresh_token=$(echo "$body" | jq -r .refresh_token)
    
    # Guardar refresh token
    echo "$refresh_token" > "$TOKEN_FILE"
    
    echo "✅ Tokens generados y $TOKEN_FILE guardado."
    echo "$access_token"
}

# Función para renovar token
refresh_token() {
    local current_refresh="$1"
    echo "🔄 Renovando token con refresh token..."
    
    response=$(curl -s -w "\n%{http_code}" -X POST \
        "$BASE_URL/oauth/token" \
        -H "Content-Type: application/json" \
        -d "{
            \"grant_type\": \"refresh_token\", 
            \"refresh_token\": \"$current_refresh\"
        }")
    
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | sed '$d')
    
    if [[ "$http_code" != "200" ]]; then
        echo "❌ Error refresh: $http_code"
        echo "🗑️ Eliminando $TOKEN_FILE inválido..."
        rm -f "$TOKEN_FILE"
        return 1
    fi
    
    echo "$body" | jq -r .access_token
}

# Main
echo "🚀 Generador de token SecOps API"
echo "================================="

# Intentar refresh token primero
refresh_token_str=$(read_refresh_token)
access_token=""

if [[ -n "$refresh_token_str" ]]; then
    access_token=$(refresh_token "$refresh_token_str")
fi

# Si no hay refresh o falló, hacer login
if [[ -z "$access_token" ]]; then
    access_token=$(login_with_credentials)
fi

echo ""
echo "🎉 TOKEN DE ACCESO:"
echo "Bearer $access_token"
echo ""
echo "📄 Refresh token guardado en: $TOKEN_FILE"
echo ""
echo "💡 Uso:"
echo "  curl -H \"Authorization: Bearer $access_token\" $BASE_URL/sentinel/results"
