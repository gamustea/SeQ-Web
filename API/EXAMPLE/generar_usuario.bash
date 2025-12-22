#!/bin/bash
# Script para crear Persona + Usuario Ana García + Token (SIN root)
# Flujo completo: Persona → Usuario → Token Ana

set -e  # Salir en error

BASE_URL="http://localhost:5000"
TOKEN_FILE="refresh_token_ana.txt"

red='\033[0;31m'
green='\033[0;32m'
yellow='\033[1;33m'
nc='\033[0m'

echo -e "${yellow}🚀 Creación completa Ana García${nc}"
echo "=============================================="

# 1. Crear PERSONA "Ana García" (NO requiere auth)
echo -e "\n${yellow}👤 1. Creando PERSONA Ana García...${nc}"
response=$(curl -s -w "\n%{http_code}" -X POST \
    "$BASE_URL/users/sign-up-person" \
    -H "X-First-Name: Ana" \
    -H "X-Last-Name: García" \
    -H "X-Email: ana.garcia@secops.com")

http_code=$(echo "$response" | tail -n1)
body=$(echo "$response" | sed '$d')

if [[ "$http_code" == "201" ]]; then
    person_id=$(echo "$body" | jq -r .personId)
    echo -e "${green}✅ Persona creada - ID: $person_id${nc}"
elif [[ "$http_code" == "409" ]]; then
    echo -e "${yellow}⚠️  Persona ya existe${nc}"
else
    echo -e "${red}❌ Error persona: $http_code${nc}"
    echo "$body" | jq .
    exit 1
fi

# 2. Crear USUARIO "ana.garcia" (NO requiere auth)
echo -e "\n${yellow}👤 2. Creando USUARIO ana.garcia...${nc}"
response=$(curl -s -w "\n%{http_code}" -X POST \
    "$BASE_URL/users/sign-up" \
    -H "X-Username: ana.garcia" \
    -H "X-Password: ana123" \
    -H "X-Email: ana.garcia@secops.com")

http_code=$(echo "$response" | tail -n1)
body=$(echo "$response" | sed '$d')

if [[ "$http_code" == "201" ]]; then
    user_id=$(echo "$body" | jq -r .userId)
    echo -e "${green}✅ Usuario creado - ID: $user_id${nc}"
elif [[ "$http_code" == "409" ]]; then
    echo -e "${yellow}⚠️  Usuario ya existe${nc}"
else
    echo -e "${red}❌ Error usuario: $http_code${nc}"
    echo "$body" | jq .
    exit 1
fi

# 3. Obtener TOKEN de Ana
echo -e "\n${yellow}🎫 3. Generando token ana.garcia...${nc}"
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

if [[ "$http_code" == "200" ]]; then
    access_token=$(echo "$body" | jq -r .access_token)
    refresh_token=$(echo "$body" | jq -r .refresh_token)
    
    # Guardar refresh token
    echo "$refresh_token" > "$TOKEN_FILE"
    
    echo -e "${green}✅ Token generado y guardado${nc}"
else
    echo -e "${red}❌ Error token: $http_code${nc}"
    echo "$body" | jq .
    exit 1
fi

echo -e "\n${green}🎊 ¡Ana García creada COMPLETAMENTE!${nc}"
echo -e "\n${yellow}📋 Credenciales:${nc}"
echo "   👤 Usuario: ana.garcia"
echo "   🔑 Password: ana123"
echo "   📧 Email: ana.garcia@secops.com"
echo "   💾 Refresh: $TOKEN_FILE"
echo ""
echo -e "${yellow}💡 Prueba:${nc}"
echo "   curl -H \"Authorization: Bearer $access_token\" $BASE_URL/sentinel/results"
